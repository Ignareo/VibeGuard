package rulelists

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/pii_next/rulelist"
)

const (
	defaultSubscriptionUpdateInterval = 24 * time.Hour
	defaultSubscriptionTimeout        = 20 * time.Second
	maxSubscriptionRuleListBytes      = 10 * 1024 * 1024 // 10MB
)

// SubscriptionMeta tracks the subscription cache state (for conditional requests and admin UI display).
type SubscriptionMeta struct {
	URL          string `json:"url"`
	ETag         string `json:"etag,omitempty"`
	LastModified string `json:"last_modified,omitempty"`

	CheckedAt int64 `json:"checked_at,omitempty"`
	UpdatedAt int64 `json:"updated_at,omitempty"`

	// ContentSHA256 is the sha256 (hex) of the accepted subscription content (after parsing):
	// - used to detect content changes
	// - shown in the admin UI as a cache fingerprint
	ContentSHA256 string `json:"content_sha256,omitempty"`
	// VerifiedSHA256 is a legacy field name (easy to confuse with "verified"); kept for backward compatibility with older meta files.
	// New code should prefer ContentSHA256.
	VerifiedSHA256 string `json:"verified_sha256,omitempty"`
	// PinnedSHA256 is the trust-on-first-use pin, recorded on the first accepted fetch
	// when sha256_pin is empty (the default) or "tofu". Once set, subscription updates
	// whose content hash differs are rejected. An explicit fixed sha256_pin takes
	// precedence and does not use this field.
	PinnedSHA256 string `json:"pinned_sha256,omitempty"`

	Bytes     int    `json:"bytes,omitempty"`
	LastError string `json:"last_error,omitempty"`
	// ConsecutiveFailures counts consecutive failed sync attempts (fetch/validate/apply);
	// reset to 0 on the first successful sync. Surfaced to the admin UI for alerting.
	ConsecutiveFailures int `json:"consecutive_failures,omitempty"`
}

func SubscriptionsDir() string {
	// Subscription cache lives under ~/.vibeguard/rules/subscriptions/ for easy user inspection.
	return filepath.Join(config.GetRulesDir(), "subscriptions")
}

func IsSubscription(rl config.RuleListConfig) bool {
	return strings.TrimSpace(rl.URL) != ""
}

func SubscriptionKey(rl config.RuleListConfig) (string, bool) {
	if id := safeCacheKey(rl.ID); id != "" {
		return id, true
	}
	u := strings.TrimSpace(rl.URL)
	if u == "" {
		return "", false
	}
	sum := sha256.Sum256([]byte(u))
	return "url_" + hex.EncodeToString(sum[:]), true
}

func safeCacheKey(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s))
	lastUnderscore := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
			b.WriteByte(c)
			lastUnderscore = false
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c - 'A' + 'a')
			lastUnderscore = false
		case c >= '0' && c <= '9':
			b.WriteByte(c)
			lastUnderscore = false
		case c == '_' || c == '-':
			b.WriteByte(c)
			lastUnderscore = false
		default:
			if !lastUnderscore {
				b.WriteByte('_')
				lastUnderscore = true
			}
		}
	}
	out := strings.Trim(b.String(), "_-")
	if out == "" {
		return ""
	}
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func SubscriptionRulesPath(rl config.RuleListConfig) (string, bool) {
	key, ok := SubscriptionKey(rl)
	if !ok {
		return "", false
	}
	return filepath.Join(SubscriptionsDir(), key+".vgrules"), true
}

func SubscriptionMetaPath(rl config.RuleListConfig) (string, bool) {
	key, ok := SubscriptionKey(rl)
	if !ok {
		return "", false
	}
	return filepath.Join(SubscriptionsDir(), key+".json"), true
}

func LoadSubscriptionMeta(metaPath string) (SubscriptionMeta, bool, error) {
	p := strings.TrimSpace(metaPath)
	if p == "" {
		return SubscriptionMeta{}, false, nil
	}
	b, err := os.ReadFile(p)
	if err != nil {
		if os.IsNotExist(err) {
			return SubscriptionMeta{}, false, nil
		}
		return SubscriptionMeta{}, false, err
	}
	var m SubscriptionMeta
	if err := json.Unmarshal(b, &m); err != nil {
		return SubscriptionMeta{}, false, err
	}
	// Backward-compat: older versions only wrote verified_sha256.
	if strings.TrimSpace(m.ContentSHA256) == "" && strings.TrimSpace(m.VerifiedSHA256) != "" {
		m.ContentSHA256 = strings.TrimSpace(m.VerifiedSHA256)
	}
	return m, true, nil
}

func SaveSubscriptionMeta(metaPath string, meta SubscriptionMeta) error {
	p := strings.TrimSpace(metaPath)
	if p == "" {
		return fmt.Errorf("empty meta path")
	}
	// Backward-compat: write the legacy field as well so older tools can still read the fingerprint.
	if strings.TrimSpace(meta.ContentSHA256) != "" {
		meta.VerifiedSHA256 = strings.TrimSpace(meta.ContentSHA256)
	}
	dir := filepath.Dir(p)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(meta, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	_ = os.Chmod(tmp, 0o600)
	if err := renameReplace(tmp, p); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(p, 0o600)
	return nil
}

func SubscriptionUpdateInterval(rl config.RuleListConfig) time.Duration {
	if !IsSubscription(rl) {
		return 0
	}
	s := strings.TrimSpace(rl.UpdateInterval)
	if s == "" {
		return defaultSubscriptionUpdateInterval
	}
	d, err := time.ParseDuration(s)
	if err != nil || d <= 0 {
		return defaultSubscriptionUpdateInterval
	}
	// Prevent accidental overly-frequent pulls (wastes bandwidth and increases the chance of upstream rate limits).
	if d < 10*time.Minute {
		return 10 * time.Minute
	}
	return d
}

type SyncSubscriptionOptions struct {
	Client   *http.Client
	Force    bool
	Now      time.Time
	MaxBytes int
}

// SyncSubscriptionIfDue pulls the subscription when "due" (or forced) and writes it to disk.
// updated indicates cache content changed (or first write); err only means this sync attempt failed and should not make the proxy unusable.
func SyncSubscriptionIfDue(ctx context.Context, rl config.RuleListConfig, opts SyncSubscriptionOptions) (updated bool, meta SubscriptionMeta, err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if !rl.Enabled {
		return false, SubscriptionMeta{}, nil
	}
	if strings.TrimSpace(rl.URL) == "" {
		return false, SubscriptionMeta{}, nil
	}

	now := opts.Now
	if now.IsZero() {
		now = time.Now()
	}

	rulesPath, ok := SubscriptionRulesPath(rl)
	if !ok {
		return false, SubscriptionMeta{}, fmt.Errorf("无法生成订阅缓存路径")
	}
	metaPath, ok := SubscriptionMetaPath(rl)
	if !ok {
		return false, SubscriptionMeta{}, fmt.Errorf("无法生成订阅元数据路径")
	}

	prev, prevOK, prevErr := LoadSubscriptionMeta(metaPath)
	if prevErr != nil {
		prev = SubscriptionMeta{}
		prevOK = false
	}

	meta = prev
	meta.URL = normalizeSubscriptionURL(strings.TrimSpace(rl.URL))
	// If the subscription URL changes, do not reuse conditional caching headers (ETag/Last-Modified) to avoid incorrect 304s.
	if prevOK && strings.TrimSpace(prev.URL) != "" && strings.TrimSpace(prev.URL) != strings.TrimSpace(meta.URL) {
		prev.ETag = ""
		prev.LastModified = ""
		// Also clear meta fields to avoid carrying old subscription cache state onto the new subscription.
		meta.ETag = ""
		meta.LastModified = ""
		meta.ContentSHA256 = ""
		meta.VerifiedSHA256 = ""
		meta.PinnedSHA256 = ""
		meta.Bytes = 0
	}

	interval := SubscriptionUpdateInterval(rl)
	if !opts.Force && prevOK && prev.CheckedAt > 0 && interval > 0 {
		last := time.Unix(prev.CheckedAt, 0)
		if now.Sub(last) < interval {
			return false, meta, nil
		}
	}

	// A sync is attempted from here on: persist the meta exactly once per attempt.
	// The deferred save keeps ConsecutiveFailures and LastError consistent on every
	// outcome; sync failures never fail closed (the proxy stays usable).
	defer func() {
		if err != nil {
			meta.ConsecutiveFailures++
		} else {
			meta.ConsecutiveFailures = 0
		}
		if saveErr := SaveSubscriptionMeta(metaPath, meta); saveErr != nil {
			slog.Warn("订阅元数据写入失败", "path", metaPath, "error", saveErr)
		}
	}()

	client := opts.Client
	if client == nil {
		client = &http.Client{Timeout: defaultSubscriptionTimeout}
	}
	{
		// Wrap the client so redirects cannot bypass the scheme validation below:
		// an https URL must not be followed to http (allow_http bypass) or to a
		// different host under an existing TOFU pin without revalidation.
		clientCopy := *client
		clientCopy.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return fmt.Errorf("重定向次数过多（>10）")
			}
			if err := validateRemoteURL(req.URL.String(), rl.AllowHTTP); err != nil {
				return fmt.Errorf("拒绝重定向：%w", err)
			}
			return nil
		}
		client = &clientCopy
	}
	maxBytes := opts.MaxBytes
	if maxBytes <= 0 {
		maxBytes = maxSubscriptionRuleListBytes
	}

	// Validate URL (default: https only; allow http only when allow_http is explicitly set).
	if err := validateRemoteURL(meta.URL, rl.AllowHTTP); err != nil {
		meta.CheckedAt = now.Unix()
		meta.LastError = err.Error()
		return false, meta, err
	}

	// Only send conditional requests when local cache exists and last sync had no error,
	// to avoid a 304 "washing away" an error state.
	useConditional := false
	if prevOK && strings.TrimSpace(prev.LastError) == "" && (strings.TrimSpace(prev.ETag) != "" || strings.TrimSpace(prev.LastModified) != "") {
		if _, statErr := os.Stat(rulesPath); statErr == nil {
			useConditional = true
		}
	}

	makeReq := func(withCond bool) (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, meta.URL, nil)
		if err != nil {
			return nil, err
		}
		if withCond {
			if strings.TrimSpace(prev.ETag) != "" {
				req.Header.Set("If-None-Match", prev.ETag)
			}
			if strings.TrimSpace(prev.LastModified) != "" {
				req.Header.Set("If-Modified-Since", prev.LastModified)
			}
		}
		return req, nil
	}

	req, err := makeReq(useConditional)
	if err != nil {
		meta.CheckedAt = now.Unix()
		meta.LastError = err.Error()
		return false, meta, err
	}

	resp, err := client.Do(req)
	if err != nil {
		meta.CheckedAt = now.Unix()
		meta.LastError = err.Error()
		return false, meta, err
	}
	meta.CheckedAt = now.Unix()

	// 304 has no body: ensure local cache is usable; otherwise retry once without conditional headers.
	if resp.StatusCode == http.StatusNotModified {
		_ = resp.Body.Close()
		if _, statErr := os.Stat(rulesPath); statErr != nil {
			req2, reqErr := makeReq(false)
			if reqErr != nil {
				meta.LastError = reqErr.Error()
				return false, meta, reqErr
			}
			resp2, err2 := client.Do(req2)
			if err2 != nil {
				meta.LastError = err2.Error()
				return false, meta, err2
			}
			resp = resp2
		} else {
			// Cache exists: a 304 means the content equals what we last accepted, but the
			// cached bytes must still be validated against the pin (fixed pin, or the TOFU
			// pin that pin-less subscriptions default to — recorded here on first use).
			cached, readErr := os.ReadFile(rulesPath)
			if readErr != nil {
				meta.LastError = readErr.Error()
				return false, meta, readErr
			}
			sum := sha256.Sum256(cached)
			if err := checkSubscriptionPin(rl.SHA256Pin, hex.EncodeToString(sum[:]), meta.PinnedSHA256, &meta); err != nil {
				slog.Warn("订阅缓存内容未通过钉扎校验（304）", "url", meta.URL, "error", err)
				meta.LastError = err.Error()
				return false, meta, err
			}
			// Cache exists: just update check time; keep existing fingerprint.
			meta.LastError = ""
			return false, meta, nil
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("订阅拉取失败：HTTP %d", resp.StatusCode)
		meta.LastError = err.Error()
		return false, meta, err
	}

	respETag := strings.TrimSpace(resp.Header.Get("ETag"))
	respLastModified := strings.TrimSpace(resp.Header.Get("Last-Modified"))

	body, err := readAllLimited(resp.Body, maxBytes)
	if err != nil {
		meta.LastError = err.Error()
		return false, meta, err
	}

	sum := sha256.Sum256(body)
	sumHex := hex.EncodeToString(sum[:])
	meta.Bytes = len(body)

	// Syntax validation: parse (including regex compilation) to avoid "updated successfully but not effective" confusion.
	if _, err := rulelist.Parse(bytes.NewReader(body), rulelist.ParseOptions{
		Name:     strings.TrimSpace(rl.Name),
		Priority: rl.Priority,
	}); err != nil {
		meta.LastError = err.Error()
		return false, meta, err
	}

	// Integrity pinning (anti-poisoning): reject tampered content before it can overwrite the cache.
	// Note: uses meta.PinnedSHA256 (not prev.PinnedSHA256) so a URL change that reset the pin
	// above starts a fresh TOFU cycle instead of validating against the old subscription's pin.
	if err := checkSubscriptionPin(rl.SHA256Pin, sumHex, meta.PinnedSHA256, &meta); err != nil {
		slog.Warn("订阅内容校验失败，已拒绝更新", "url", meta.URL, "error", err)
		meta.CheckedAt = now.Unix()
		meta.LastError = err.Error()
		return false, meta, err
	}

	// At this point the content is accepted: persist the fingerprint and conditional request headers.
	meta.ContentSHA256 = sumHex
	if respETag != "" {
		meta.ETag = respETag
	}
	if respLastModified != "" {
		meta.LastModified = respLastModified
	}

	// If content is unchanged, update metadata only.
	if prevOK && strings.TrimSpace(prev.ContentSHA256) != "" && strings.EqualFold(prev.ContentSHA256, sumHex) {
		meta.UpdatedAt = prev.UpdatedAt
		meta.LastError = ""
		return false, meta, nil
	}

	if err := writeFile0600(rulesPath, bytes.NewReader(body)); err != nil {
		meta.LastError = err.Error()
		return false, meta, err
	}

	meta.UpdatedAt = now.Unix()
	meta.LastError = ""
	return true, meta, nil
}

// checkSubscriptionPin enforces the sha256_pin integrity setting before new content
// may overwrite the local cache. pin comes from config; prevPinned is the TOFU pin
// recorded in the subscription meta. An empty pin defaults to trust-on-first-use so
// every subscription gets content-integrity protection out of the box (the pin is
// shared with explicit "tofu" so toggling the setting cannot downgrade protection);
// an explicit fixed pin takes precedence over TOFU. On TOFU first use,
// meta.PinnedSHA256 is set.
func checkSubscriptionPin(pin, sumHex, prevPinned string, meta *SubscriptionMeta) error {
	pin = strings.ToLower(strings.TrimSpace(pin))
	if pin == "" || pin == "tofu" {
		explicit := pin == "tofu"
		pinned := strings.ToLower(strings.TrimSpace(prevPinned))
		if pinned == "" {
			// Trust on first use: pin to the first accepted content. Older meta files
			// without a recorded pin take this path once and are protected from then on.
			meta.PinnedSHA256 = sumHex
			slog.Info("订阅已启用 TOFU 钉扎：已记录首次接受内容的 sha256，后续内容哈希变化将被拒绝；如确认上游合法变更，请将 sha256_pin 设置为该哈希或删除订阅缓存以重新钉扎",
				"url", strings.TrimSpace(meta.URL), "sha256", shortHash(sumHex), "explicit_tofu", explicit)
			return nil
		}
		if !hashEqualHexConstantTime(pinned, sumHex) {
			return fmt.Errorf("订阅内容 sha256 (%s) 与 TOFU 钉扎值 (%s) 不匹配，已拒绝更新；如确认上游变更合法，请将 sha256_pin 改为该哈希或删除订阅缓存后重试", shortHash(sumHex), shortHash(pinned))
		}
		return nil
	}
	if !isSHA256Hex(pin) {
		return fmt.Errorf("sha256_pin 格式非法（应为 64 位十六进制或 tofu）：%q", pin)
	}
	if !hashEqualHexConstantTime(pin, sumHex) {
		return fmt.Errorf("订阅内容 sha256 (%s) 与 sha256_pin (%s) 不匹配，已拒绝更新；疑似订阅被篡改", shortHash(sumHex), shortHash(pin))
	}
	return nil
}

// hashEqualHexConstantTime compares two hex-encoded hashes in constant time.
func hashEqualHexConstantTime(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}

func isSHA256Hex(s string) bool {
	if len(s) != 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

func shortHash(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 12 {
		return s[:12] + "…"
	}
	return s
}

func validateRemoteURL(raw string, allowHTTP bool) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return fmt.Errorf("无效 URL：%w", err)
	}
	if u == nil || strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return fmt.Errorf("无效 URL：缺少 scheme/host")
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	switch scheme {
	case "https":
		return nil
	case "http":
		if allowHTTP {
			return nil
		}
		return fmt.Errorf("不允许使用 http 订阅（可设置 allow_http: true 解除限制）")
	default:
		return fmt.Errorf("不支持的订阅 URL scheme：%s", scheme)
	}
}

func normalizeSubscriptionURL(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}
	u, err := url.Parse(s)
	if err != nil || u == nil {
		return s
	}

	// GitHub blob links return HTML rather than raw file content; convert to raw URLs automatically for usability.
	// Example: https://github.com/<owner>/<repo>/blob/<ref>/<path>
	if strings.EqualFold(u.Host, "github.com") {
		parts := strings.Split(strings.Trim(u.Path, "/"), "/")
		if len(parts) >= 5 && parts[2] == "blob" {
			owner := parts[0]
			repo := parts[1]
			ref := parts[3]
			filePath := strings.Join(parts[4:], "/")
			return (&url.URL{
				Scheme: "https",
				Host:   "raw.githubusercontent.com",
				Path:   "/" + owner + "/" + repo + "/" + ref + "/" + filePath,
			}).String()
		}
	}

	return s
}

func readAllLimited(r io.Reader, limit int) ([]byte, error) {
	limited := io.LimitReader(r, int64(limit)+1)
	out, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if len(out) > limit {
		return nil, fmt.Errorf("订阅内容过大（>%d bytes）", limit)
	}
	return out, nil
}

func writeFile0600(path string, r io.Reader) error {
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("empty path")
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp := path + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(f, r)
	closeErr := f.Close()
	if copyErr != nil {
		_ = os.Remove(tmp)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(tmp)
		return closeErr
	}
	if err := renameReplace(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	_ = os.Chmod(path, 0o600)
	return nil
}

func renameReplace(src, dst string) error {
	// On POSIX, os.Rename overwrites; on Windows it fails, so we do a compatibility fallback.
	if err := os.Rename(src, dst); err == nil {
		return nil
	} else if runtime.GOOS == "windows" {
		_ = os.Remove(dst)
		return os.Rename(src, dst)
	} else {
		// Some filesystems may not support overwrite either: try remove then rename (not fully atomic).
		if _, statErr := os.Stat(dst); statErr == nil {
			_ = os.Remove(dst)
			return os.Rename(src, dst)
		}
		return err
	}
}
