package main

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/keywords"
	"github.com/inkdust2021/vibeguard/internal/pii_next/ner"
	"github.com/inkdust2021/vibeguard/internal/pii_next/pipeline"
	piirec "github.com/inkdust2021/vibeguard/internal/pii_next/recognizer"
	"github.com/inkdust2021/vibeguard/internal/pii_next/rulelist"
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/rulelists"
	"github.com/inkdust2021/vibeguard/internal/secretsources"
	"github.com/inkdust2021/vibeguard/internal/session"
)

// testDryRunMaxMatches caps how many hits are printed per run.
const testDryRunMaxMatches = 50

// runTestDryRun runs the real detection pipeline (same recognizer assembly as the
// proxy) against the given text without starting the proxy. It only reads config and
// uses a throwaway session whose WAL lives in a temp dir (removed on return) — it
// never writes session data to ~/.vibeguard and never modifies the config.
func runTestDryRun(cmd *cobra.Command, lang, text string) error {
	w := cmd.OutOrStdout()
	errW := cmd.ErrOrStderr()

	// Load the effective config (global ~/.vibeguard/config.yaml + project
	// .vibeguard.yaml override) with keyword decryption, mirroring the daemon.
	cfg, err := loadRulesConfig(lang)
	if err != nil {
		return err
	}
	defer func() { _ = cfg.Close() }()
	c := cfg.Get()

	// Throwaway session: WAL in a temp dir, wiped afterwards. Never the real
	// ~/.vibeguard session data.
	tmpDir, err := os.MkdirTemp("", "vibeguard-test-*")
	if err != nil {
		return fmt.Errorf(uiText(lang, "创建临时目录失败：%v", "failed to create temp dir: %v"), err)
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	sessTTL, perr := time.ParseDuration(strings.TrimSpace(c.Session.TTL))
	if perr != nil || sessTTL <= 0 {
		sessTTL = time.Hour
	}
	maxMappings := c.Session.MaxMappings
	if maxMappings <= 0 {
		maxMappings = 100000
	}
	sess := session.NewManager(sessTTL, maxMappings)
	defer sess.Close()

	walKey := make([]byte, 32)
	if _, err := rand.Read(walKey); err != nil {
		return fmt.Errorf(uiText(lang, "生成临时 WAL 密钥失败：%v", "failed to generate temp WAL key: %v"), err)
	}
	if wal, werr := session.NewWAL(filepath.Join(tmpDir, "session.wal"), walKey); werr == nil {
		sess.AttachWAL(wal)
	}

	redactor, summary, notes, nerFailureCounter := buildTestRedactor(lang, c, sess)

	fmt.Fprintf(w, uiText(lang, "已加载检测配置：%s\n", "Loaded detection config: %s\n"), summary)
	for _, note := range notes {
		fmt.Fprintln(errW, note)
	}

	out, matches := redactor.RedactWithMatches([]byte(text))
	if n := *nerFailureCounter; n > 0 {
		fmt.Fprintln(errW, "Warning: "+fmt.Sprintf(uiText(lang,
			"NER 分析请求失败 %d 次（对应片段未由 NER 脱敏）。",
			"NER analysis failed %d time(s) (those fragments were not redacted by NER)."), n))
	}

	if len(matches) == 0 {
		fmt.Fprintln(w, uiText(lang, "未命中任何规则。", "No rules matched."))
		return nil
	}

	fmt.Fprintf(w, uiText(lang, "命中 %d 处，脱敏结果：\n%s\n", "Found %d match(es); redacted output:\n%s\n"), len(matches), string(out))

	limit := len(matches)
	truncated := false
	if limit > testDryRunMaxMatches {
		limit = testDryRunMaxMatches
		truncated = true
	}
	fmt.Fprintln(w, uiText(lang, "命中明细（最多显示 50 条）：", "Match details (first 50 shown):"))
	for i := 0; i < limit; i++ {
		m := matches[i]
		src := strings.TrimSpace(m.Source)
		if src == "" {
			src = "-"
		}
		fmt.Fprintf(w, "  [%d] category=%s source=%s preview=%s placeholder=%s\n",
			i+1, m.Category, src, previewMatchValue(m.Original), m.Placeholder)
	}
	if truncated {
		fmt.Fprintf(w, uiText(lang, "  …共 %d 条，仅显示前 %d 条（已截断）。\n", "  …%d matches in total, showing the first %d (truncated).\n"), len(matches), testDryRunMaxMatches)
	}
	return nil
}

// buildTestRedactor mirrors the recognizer assembly in proxy.applyConfig
// (internal/proxy/proxy.go): config keywords -> pii_next/keywords, inline
// patterns.regex/builtin rules, local rule-list files -> pii_next/rulelist, and an
// optional NER recognizer; everything merged into a pii_next pipeline. When no rule
// lists/NER are configured it falls back to the legacy redact.Engine, exactly like
// the proxy. Parse failures are reported in the returned notes and skipped, never fatal.
func buildTestRedactor(lang string, c config.Config, sess *session.Manager) (redact.Redactor, string, []string, *int) {
	var notes []string
	warnf := func(format string, args ...any) {
		notes = append(notes, "Warning: "+fmt.Sprintf(format, args...))
	}

	prefix := strings.TrimSpace(c.Proxy.PlaceholderPrefix)
	if prefix == "" {
		prefix = "__VG_"
	}

	var (
		kws     []keywords.Keyword
		exclude []string
	)
	for _, kw := range c.Patterns.Keywords {
		val := config.SanitizePatternValue(kw.Value)
		if val == "" {
			continue
		}
		cat := config.SanitizeCategory(kw.Category)
		if cat == "" {
			cat = "TEXT"
		}
		kws = append(kws, keywords.Keyword{Text: val, Category: cat})
	}
	for _, ex := range c.Patterns.Exclude {
		ex = config.SanitizePatternValue(ex)
		if ex == "" {
			continue
		}
		exclude = append(exclude, ex)
	}

	secretCount := 0
	if len(c.Patterns.SecretFiles) > 0 {
		extra, warns := secretsources.LoadKeywords(c.Patterns.SecretFiles)
		for _, we := range warns {
			warnf(uiText(lang, "secret_files 加载问题：%v", "secret_files issue: %v"), we)
		}
		if len(extra) > 0 {
			seen := make(map[string]struct{}, len(kws)+len(extra))
			for _, kw := range kws {
				if kw.Text == "" {
					continue
				}
				seen[kw.Text] = struct{}{}
			}
			for _, kw := range extra {
				if kw.Text == "" {
					continue
				}
				if _, ok := seen[kw.Text]; ok {
					continue
				}
				seen[kw.Text] = struct{}{}
				kws = append(kws, kw)
				secretCount++
			}
		}
	}

	ruleRecs, inlineErrs := buildTestInlineRecognizers(c.Patterns)
	for _, ie := range inlineErrs {
		warnf(uiText(lang, "内置规则配置无效（已跳过该条）：%v", "invalid inline rule (skipped): %v"), ie)
	}

	skippedURL := 0
	for _, rl := range c.Patterns.RuleLists {
		if !rl.Enabled {
			continue
		}
		// Mirror the proxy: URL subscriptions are read from their local cache file
		// (the running proxy keeps it up to date); a missing cache just skips the list.
		path := ""
		if strings.TrimSpace(rl.URL) != "" {
			if p, ok := rulelists.SubscriptionRulesPath(rl); ok {
				path = p
			}
		} else {
			path = resolveTestRuleListPath(rl.Path)
		}
		if strings.TrimSpace(path) == "" {
			continue
		}
		name := strings.TrimSpace(rl.Name)
		if name == "" {
			name = strings.TrimSpace(rl.ID)
		}
		if name == "" {
			name = filepath.Base(path)
		}
		if _, err := os.Stat(path); err != nil {
			if strings.TrimSpace(rl.URL) != "" {
				skippedURL++
				continue
			}
			warnf(uiText(lang, "规则列表文件不存在（已跳过）：%s", "rule list file not found (skipped): %s"), rl.Path)
			continue
		}
		rec, err := rulelist.ParseFile(path, rulelist.ParseOptions{
			Name:     name,
			Priority: rl.Priority,
		})
		if err != nil {
			if strings.TrimSpace(rl.URL) != "" {
				warnf(uiText(lang, "解析订阅规则列表失败（已跳过）%s：%v", "failed to parse subscribed rule list (skipped) %s: %v"), rl.URL, err)
			} else {
				warnf(uiText(lang, "解析规则列表失败（已跳过）%s：%v", "failed to parse rule list (skipped) %s: %v"), path, err)
			}
			continue
		}
		ruleRecs = append(ruleRecs, rec)
	}
	if skippedURL > 0 {
		warnf(uiText(lang,
			"%d 个 URL 订阅规则列表暂无本地缓存，已跳过（干跑不会联网拉取；可先运行 'vibeguard start' 让代理拉取）。",
			"%d URL-subscribed rule list(s) have no local cache and were skipped (the dry-run never fetches; run 'vibeguard start' first to let the proxy fetch them)."), skippedURL)
	}

	nerFailures := 0
	nerFailureCounter := &nerFailures
	var redactor redact.Redactor
	if len(ruleRecs) > 0 || c.Patterns.NER.Enabled {
		var merged []piirec.Recognizer
		if len(kws) > 0 {
			merged = append(merged, keywords.New(kws))
		}
		merged = append(merged, ruleRecs...)

		if c.Patterns.NER.Enabled {
			rec, err := ner.New(ner.Options{
				PresidioURL: c.Patterns.NER.PresidioURL,
				Language:    c.Patterns.NER.Language,
				Entities:    c.Patterns.NER.Entities,
				MinScore:    c.Patterns.NER.MinScore,
				OnFailure: func(kind string) {
					nerFailures++
				},
			})
			if err != nil {
				warnf(uiText(lang,
					"NER 初始化失败，已跳过（不影响其他规则）：%v",
					"failed to init NER recognizer; skipped (other rules still apply): %v"), err)
			} else if rec != nil {
				merged = append(merged, rec)
			}
		}

		p := pipeline.New(sess, prefix, merged...)
		p.SetExclude(exclude)
		redactor = p
	} else {
		eng := redact.NewEngine(sess, prefix)
		for _, kw := range kws {
			eng.AddKeyword(kw.Text, kw.Category)
		}
		for _, ex := range exclude {
			eng.AddExclude(ex)
		}
		redactor = eng
	}

	return redactor, testRedactorSummary(lang, c, len(kws), secretCount, len(ruleRecs), len(exclude)), notes, nerFailureCounter
}

// testRedactorSummary builds a compact one-line summary of what was loaded.
func testRedactorSummary(lang string, c config.Config, kwCount, secretCount, ruleListCount, excludeCount int) string {
	parts := []string{
		fmt.Sprintf(uiText(lang, "%d 个关键词", "%d keyword(s)"), kwCount),
		fmt.Sprintf(uiText(lang, "%d 个规则列表/内置规则", "%d rule list(s)/inline rule(s)"), ruleListCount),
		fmt.Sprintf(uiText(lang, "%d 条排除项", "%d exclude(s)"), excludeCount),
	}
	if secretCount > 0 {
		parts = append(parts, fmt.Sprintf(uiText(lang, "%d 个 secret_files 导入值", "%d secret_files import(s)"), secretCount))
	}
	if c.Patterns.NER.Enabled {
		parts = append(parts, uiText(lang, "NER 已启用", "NER enabled"))
	}
	return strings.Join(parts, uiText(lang, "，", ", "))
}

// testInlineRulePriority ranks patterns.regex/builtin above the default rule list (50),
// mirroring proxy.inline_rules.go so explicit config wins on overlaps.
const testInlineRulePriority = 60

// buildTestInlineRecognizers wires patterns.regex / patterns.builtin into the
// pipeline as inline rule lists (mirrors proxy.buildInlineRuleRecognizers). Invalid
// entries produce errors in the returned slice without discarding valid rules.
func buildTestInlineRecognizers(p config.PatternsConfig) (recs []piirec.Recognizer, errs []error) {
	add := func(cat, pattern, origin string) {
		rec, err := rulelist.Parse(strings.NewReader("regex "+cat+" "+pattern), rulelist.ParseOptions{
			Name:     origin,
			Priority: testInlineRulePriority,
		})
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", origin, err))
			return
		}
		recs = append(recs, rec)
	}

	for _, rp := range p.Regex {
		pat := strings.TrimSpace(rp.Pattern)
		if pat == "" {
			continue
		}
		cat := config.SanitizeCategory(rp.Category)
		if cat == "" {
			cat = "REGEX"
		}
		add(cat, pat, "patterns.regex")
	}

	for _, name := range p.Builtin {
		n := strings.ToLower(strings.TrimSpace(name))
		if n == "" {
			continue
		}
		pat, cat, ok := redact.BuiltinRule(n)
		if !ok {
			errs = append(errs, fmt.Errorf("patterns.builtin: unknown builtin rule %q", name))
			continue
		}
		add(cat, pat, "patterns.builtin:"+n)
	}

	return recs, errs
}

// resolveTestRuleListPath is the cmd-side equivalent of proxy.resolveRuleListPath:
// it expands a leading ~ (or ~/) to the user's home directory.
func resolveTestRuleListPath(path string) string {
	p := strings.TrimSpace(path)
	if p == "" {
		return p
	}
	if p == "~" {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return home
		}
		return p
	}
	if strings.HasPrefix(p, "~/") || strings.HasPrefix(p, "~"+string(os.PathSeparator)) {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			return filepath.Join(home, p[2:])
		}
	}
	return p
}

// previewMatchValue masks a matched value for display (first2…last2), mirroring
// previewValue in internal/proxy. It never prints the full sensitive content.
func previewMatchValue(s string) string {
	r := []rune(s)
	n := len(r)
	if n == 0 {
		return ""
	}
	if n <= 4 {
		return strings.Repeat("*", n)
	}
	return string(r[:2]) + "…" + string(r[n-2:])
}
