package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/inkdust2021/vibeguard/internal/cert"
	"github.com/inkdust2021/vibeguard/internal/config"
	"github.com/inkdust2021/vibeguard/internal/defaultrules"
	"github.com/inkdust2021/vibeguard/internal/log"
	"github.com/inkdust2021/vibeguard/internal/proxy"
	"github.com/inkdust2021/vibeguard/internal/redact"
	"github.com/inkdust2021/vibeguard/internal/rulelists"
	"github.com/inkdust2021/vibeguard/internal/session"
	"github.com/inkdust2021/vibeguard/internal/version"
)

var (
	cfgFile         string
	trustMode       string
	startForeground bool
	envShell        string
	rulesCategory   string
	testText        string
)

func uiLang() string {
	if v := strings.TrimSpace(os.Getenv("VIBEGUARD_LANG")); v != "" {
		if isLangZh(v) {
			return "zh"
		}
		if isLangEn(v) {
			return "en"
		}
		return "en"
	}

	loc := strings.TrimSpace(os.Getenv("LC_ALL"))
	if loc == "" {
		loc = strings.TrimSpace(os.Getenv("LANG"))
	}
	if isLangZh(loc) {
		return "zh"
	}
	return "en"
}

func isLangZh(v string) bool {
	v = strings.TrimSpace(v)
	switch v {
	case "中文", "cn":
		return true
	}
	vLower := strings.ToLower(v)
	return strings.HasPrefix(vLower, "zh") || strings.Contains(vLower, "zh")
}

func isLangEn(v string) bool {
	vLower := strings.ToLower(strings.TrimSpace(v))
	return strings.HasPrefix(vLower, "en") || strings.Contains(vLower, "en")
}

func uiText(lang, zh, en string) string {
	if lang == "zh" {
		return zh
	}
	return en
}

func uiIsYes(lang, s string) bool {
	s = strings.TrimSpace(s)
	sLower := strings.ToLower(s)
	if sLower == "y" || sLower == "yes" {
		return true
	}
	if lang == "zh" {
		switch s {
		case "是", "好", "确认", "继续", "覆盖":
			return true
		}
	}
	return false
}

func uiIsNo(lang, s string) bool {
	s = strings.TrimSpace(s)
	sLower := strings.ToLower(s)
	if sLower == "n" || sLower == "no" {
		return true
	}
	if lang == "zh" {
		switch s {
		case "否", "不", "不要", "跳过":
			return true
		}
	}
	return false
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

var rootCmd = &cobra.Command{
	Use:   "vibeguard",
	Short: "VibeGuard proxy helper (service + launchers)",
	Long: `VibeGuard is a MITM HTTPS proxy that protects your privacy when using
AI coding assistants like Claude Code, Cursor, or Copilot.

It intercepts HTTPS traffic, redacts sensitive data (IDs, names, etc.)
before sending to AI APIs, and restores the original data in responses.`,
	RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
}

var startCmd = &cobra.Command{
	Use:   "start",
	Short: "Start the proxy server (background by default)",
	RunE:  runStart,
}

var stopCmd = &cobra.Command{
	Use:   "stop",
	Short: "Stop the proxy service/process",
	RunE:  runStop,
}

var envCmd = &cobra.Command{
	Use:    "env",
	Short:  "Print proxy env exports for your shell",
	Args:   cobra.NoArgs,
	RunE:   runEnv,
	Hidden: true,
}

var runCmd = &cobra.Command{
	Use:                "run <command> [args...]",
	Short:              "Run a command through VibeGuard proxy (process-only)",
	Args:               cobra.MinimumNArgs(1),
	DisableFlagParsing: true,
	RunE:               runWithProxy,
}

var claudeCmd = newAssistantProxyCmd("claude", "Claude Code")
var codexCmd = newAssistantProxyCmd("codex", "Codex")
var geminiCmd = newAssistantProxyCmd("gemini", "Gemini")
var opencodeCmd = newAssistantProxyCmd("opencode", "OpenCode")
var qwenCmd = newAssistantProxyCmd("qwen", "Qwen")
var kimiCmd = newAssistantProxyCmd("kimi", "Kimi Code")

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Interactive first-time setup",
	Long:  `Run an interactive wizard to set up VibeGuard for the first time.`,
	RunE:  runInit,
}

var trustCmd = &cobra.Command{
	Use:   "trust",
	Short: "Install CA certificate to system trust store",
	Long: `Install the VibeGuard CA certificate to your system's trust store.
This is required for the proxy to intercept HTTPS traffic.

On macOS/Linux this may require sudo. On Windows this requires Administrator.`,
	RunE: runTrust,
}

var testCmd = &cobra.Command{
	Use:   "test [pattern] [text]",
	Short: "Test redaction (pattern mode, or --text for a full dry-run)",
	Long: `Test redaction against sample text.

With a pattern and text, tests the pattern as a keyword (exact substring match).
With --text, runs a full dry-run with the real config (keywords, rule lists,
inline regex/builtin rules, NER if enabled) and prints every match.`,
	Args: cobra.RangeArgs(0, 2),
	RunE: runTest,
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print version information",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("VibeGuard %s\n", version.Version)
		fmt.Printf("  Git commit: %s\n", version.GitCommit)
		fmt.Printf("  Build date: %s\n", version.BuildDate)
	},
}

var rulesCmd = &cobra.Command{
	Use:   "rules",
	Short: "Manage redaction keywords in the global config",
	Long: `Manage patterns.keywords in the global VibeGuard config (~/.vibeguard/config.yaml).

Keyword values are stored encrypted on disk (the key is derived from the CA
private key); this command shows plaintext. A running proxy hot-reloads
changes automatically, no restart needed.`,
	RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
}

var rulesListCmd = &cobra.Command{
	Use:          "list",
	Short:        "List configured redaction keywords (value + category)",
	Args:         cobra.NoArgs,
	SilenceUsage: true,
	RunE:         runRulesList,
}

var rulesAddCmd = &cobra.Command{
	Use:   "add <keyword>",
	Short: "Add a redaction keyword",
	Long: `Add a keyword to patterns.keywords in the global config.
Adding a keyword value that already exists is rejected.`,
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runRulesAdd,
}

var rulesRemoveCmd = &cobra.Command{
	Use:          "remove <keyword>",
	Short:        "Remove a redaction keyword by exact value",
	Args:         cobra.ExactArgs(1),
	SilenceUsage: true,
	RunE:         runRulesRemove,
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "config file (default is ~/.vibeguard/config.yaml)")

	rootCmd.AddCommand(startCmd)
	rootCmd.AddCommand(stopCmd)
	rootCmd.AddCommand(envCmd)
	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(claudeCmd)
	rootCmd.AddCommand(codexCmd)
	rootCmd.AddCommand(geminiCmd)
	rootCmd.AddCommand(opencodeCmd)
	rootCmd.AddCommand(qwenCmd)
	rootCmd.AddCommand(kimiCmd)
	rootCmd.AddCommand(initCmd)
	rootCmd.AddCommand(trustCmd)
	rootCmd.AddCommand(testCmd)
	rootCmd.AddCommand(versionCmd)
	rulesCmd.AddCommand(rulesListCmd)
	rulesCmd.AddCommand(rulesAddCmd)
	rulesCmd.AddCommand(rulesRemoveCmd)
	rootCmd.AddCommand(rulesCmd)

	trustCmd.Flags().StringVar(&trustMode, "mode", string(cert.TrustInstallModeSystem), "trust store mode: system|user|auto")
	startCmd.Flags().BoolVar(&startForeground, "foreground", false, "run in foreground (for service/debugging)")
	envCmd.Flags().StringVar(&envShell, "shell", "sh", "shell type: sh|bash|zsh|fish|powershell")
	rulesAddCmd.Flags().StringVar(&rulesCategory, "category", "", "category for the keyword (default TEXT)")
	testCmd.Flags().StringVar(&testText, "text", "", "dry-run the full detection pipeline from the real config against this text")
}

func newAssistantProxyCmd(exeName, displayName string) *cobra.Command {
	return &cobra.Command{
		Use:                exeName + " [args...]",
		Short:              fmt.Sprintf("Run %s through VibeGuard proxy (process-only)", displayName),
		Args:               cobra.ArbitraryArgs,
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			argv := append([]string{exeName}, args...)
			return runWithProxy(cmd, argv)
		},
	}
}

func runStart(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	// If explicitly requested to run in foreground, or a non-default config path is provided, run in foreground.
	if startForeground || strings.TrimSpace(cfgFile) != "" {
		if !startForeground && strings.TrimSpace(cfgFile) != "" {
			fmt.Println(uiText(lang, "检测到 --config：将以前台模式启动（不会走后台服务）。", "Detected --config: starting in foreground (no background service)."))
		}
		return runProxy(cmd, args)
	}

	started, err := tryStartBackgroundService()
	if err != nil {
		fmt.Fprintf(os.Stderr, uiText(lang, "启动后台服务失败：%v\n", "Failed to start background service: %v\n"), err)
	}
	if started && err == nil {
		fmt.Println(uiText(lang, "已启动后台服务。", "Background service started."))
		waitForProxyUp(lang, 2*time.Second)
		return nil
	}

	// If the service is unavailable, fall back to a self-managed background start:
	// spawn a foreground child process and detach it from the terminal.
	if derr := startDetachedProxyProcess(); derr == nil {
		fmt.Println(uiText(lang, "已在后台启动代理进程。", "Proxy process started in background."))
		fmt.Println(uiText(lang, "提示：如需开机自启后台运行，请运行 install.sh 并启用 --autostart。",
			"Tip: to enable autostart background service, run install.sh and enable --autostart."))
		fmt.Println(uiText(lang, "如需在前台调试，请使用：vibeguard start --foreground", "For foreground debugging, use: vibeguard start --foreground"))
		waitForProxyUp(lang, 2*time.Second)
		return nil
	} else {
		fmt.Fprintf(os.Stderr, uiText(lang, "后台启动失败（将改为前台启动）：%v\n", "Background start failed (falling back to foreground): %v\n"), derr)
	}

	fmt.Println(uiText(lang, "将以前台模式启动（Ctrl+C 停止）。", "Starting in foreground (Ctrl+C to stop)."))
	fmt.Println(uiText(lang, "如需开机自启后台运行，请运行 install.sh 并启用 --autostart。",
		"To enable autostart background service, run install.sh and enable --autostart."))
	return runProxy(cmd, args)
}

func runStop(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	stopped, err := tryStopBackgroundService()
	if err != nil {
		fmt.Fprintf(cmd.ErrOrStderr(), uiText(lang, "停止后台服务失败：%v\n", "Failed to stop background service: %v\n"), err)
	}
	if stopped && err == nil {
		fmt.Fprintln(cmd.OutOrStdout(), uiText(lang, "已停止后台服务。", "Background service stopped."))
		return nil
	}

	// Fall back to PID-based stop (for cases where no system service is installed and we run detached in the background).
	pid, perr := readProxyPid()
	if perr != nil {
		return fmt.Errorf(uiText(lang, "未检测到后台服务，且读取 PID 失败：%v", "No background service detected and failed to read PID: %v"), perr)
	}
	if pid <= 0 {
		return errors.New(uiText(lang, "未检测到正在运行的代理进程（PID 无效）。", "No running proxy process detected (invalid PID)."))
	}

	if err := stopProcessByPID(pid); err != nil {
		return fmt.Errorf(uiText(lang, "停止代理进程失败：%v", "Failed to stop proxy process: %v"), err)
	}

	// Wait for the port to close (try to provide deterministic feedback).
	hostport, _ := proxyListenHostportForClient()
	if hostport != "" {
		waitForProxyDown(hostport, 2*time.Second)
	}

	_ = removeProxyPidIfMatches(pid)
	fmt.Fprintln(cmd.OutOrStdout(), uiText(lang, "已停止代理进程。", "Proxy process stopped."))
	return nil
}

func waitForProxyUp(lang string, timeout time.Duration) {
	hostport, err := proxyListenHostportForClient()
	if err != nil || strings.TrimSpace(hostport) == "" {
		return
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostport, 200*time.Millisecond)
		if err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(150 * time.Millisecond)
	}

	fmt.Fprintln(os.Stderr, uiText(lang,
		"提示：代理可能尚未就绪或启动失败；可尝试访问 /manager/ 或查看日志文件。",
		"Tip: proxy may not be ready or failed to start; try /manager/ or check the log file.",
	))
}

func waitForProxyDown(hostport string, timeout time.Duration) {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return
	}

	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", hostport, 200*time.Millisecond)
		if err != nil {
			return
		}
		_ = c.Close()
		time.Sleep(150 * time.Millisecond)
	}
}

func runEnv(cmd *cobra.Command, args []string) error {
	hostport, err := proxyListenHostportForClient()
	if err != nil || strings.TrimSpace(hostport) == "" {
		// Provide a usable default even when config is missing (helps "connect to the proxy first, then run init").
		hostport = "127.0.0.1:28657"
	}

	if err := ensureProxyRunning(hostport, cmd.ErrOrStderr()); err != nil {
		return err
	}

	proxyURL := "http://" + hostport
	noProxy := "127.0.0.1,localhost"

	shell := strings.ToLower(strings.TrimSpace(envShell))
	if shell == "" {
		shell = "sh"
	}

	out, err := formatProxyEnv(shell, proxyURL, noProxy)
	if err != nil {
		return err
	}

	// The env output must be safe to eval/Invoke-Expression: write to stdout only, no extra hints/messages.
	_, _ = io.WriteString(cmd.OutOrStdout(), out)

	return nil
}

func ensureProxyRunning(hostport string, stderr io.Writer) error {
	lang := uiLang()

	if isTCPListening(hostport) {
		return nil
	}

	started, err := tryStartBackgroundService()
	if err != nil {
		fmt.Fprintf(stderr, uiText(lang, "启动后台服务失败（将尝试直接后台启动）：%v\n", "Failed to start background service (will try direct background start): %v\n"), err)
	}
	if started && err == nil {
		waitForProxyUp(lang, 3*time.Second)
		if isTCPListening(hostport) {
			return nil
		}
	}

	if derr := startDetachedProxyProcess(); derr != nil {
		return fmt.Errorf(uiText(lang, "启动后台代理失败：%v", "Failed to start proxy in background: %v"), derr)
	}
	waitForProxyUp(lang, 3*time.Second)
	if isTCPListening(hostport) {
		return nil
	}
	return errors.New(uiText(lang, "代理未就绪：请运行 vibeguard start --foreground 查看错误日志。", "Proxy is not ready: run vibeguard start --foreground to see errors."))
}

func isTCPListening(hostport string) bool {
	hostport = strings.TrimSpace(hostport)
	if hostport == "" {
		return false
	}

	c, err := net.DialTimeout("tcp", hostport, 200*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func formatProxyEnv(shell, proxyURL, noProxy string) (string, error) {
	switch shell {
	case "sh", "bash", "zsh":
		return fmt.Sprintf(
			"export HTTPS_PROXY=%q\nexport HTTP_PROXY=%q\nexport https_proxy=%q\nexport http_proxy=%q\nexport NO_PROXY=%q\nexport no_proxy=%q\n",
			proxyURL, proxyURL, proxyURL, proxyURL, noProxy, noProxy,
		), nil
	case "fish":
		return fmt.Sprintf(
			"set -gx HTTPS_PROXY %q;\nset -gx HTTP_PROXY %q;\nset -gx https_proxy %q;\nset -gx http_proxy %q;\nset -gx NO_PROXY %q;\nset -gx no_proxy %q;\n",
			proxyURL, proxyURL, proxyURL, proxyURL, noProxy, noProxy,
		), nil
	case "powershell", "pwsh", "ps":
		// PowerShell env vars are case-insensitive; set both cases to maximize compatibility.
		return fmt.Sprintf(
			"$env:HTTPS_PROXY=%q\n$env:HTTP_PROXY=%q\n$env:https_proxy=%q\n$env:http_proxy=%q\n$env:NO_PROXY=%q\n$env:no_proxy=%q\n",
			proxyURL, proxyURL, proxyURL, proxyURL, noProxy, noProxy,
		), nil
	default:
		return "", fmt.Errorf("unsupported shell: %s", shell)
	}
}

func runWithProxy(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	if len(args) < 1 || strings.TrimSpace(args[0]) == "" {
		return errors.New(uiText(lang, "缺少要运行的命令。", "Missing command to run."))
	}

	hostport, err := proxyListenHostportForClient()
	if err != nil || strings.TrimSpace(hostport) == "" {
		hostport = "127.0.0.1:28657"
	}
	if err := ensureProxyRunning(hostport, cmd.ErrOrStderr()); err != nil {
		return err
	}

	proxyURL := "http://" + hostport
	// Do not inject NO_PROXY for child processes:
	// - This allows proxying localhost/127.0.0.1 traffic when needed (e.g. local AI gateways that should be redacted).
	// - If the parent environment already sets NO_PROXY, it is preserved (user-controlled bypass list).
	childEnv := withProxyEnv(os.Environ(), proxyURL)
	childEnv = withExtraCAEnv(childEnv, filepath.Join(config.GetConfigDir(), "ca.crt"))

	target := args[0]
	targetArgs := []string{}
	if len(args) > 1 {
		targetArgs = args[1:]
	}

	path, err := exec.LookPath(target)
	if err != nil {
		return fmt.Errorf(uiText(lang, "未找到命令：%s（请确认已安装并在 PATH 中）", "Command not found: %s (ensure it's installed and on PATH)"), target)
	}

	if runtime.GOOS != "windows" {
		// Use direct exec: better for interactive TUIs (signals/TTY behave more naturally).
		return syscall.Exec(path, append([]string{target}, targetArgs...), childEnv)
	}

	c := exec.Command(path, targetArgs...)
	c.Env = childEnv
	c.Stdin = os.Stdin
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	if err := c.Run(); err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			os.Exit(ee.ExitCode())
		}
		return err
	}
	return nil
}

func withExtraCAEnv(base []string, caCertPath string) []string {
	caCertPath = strings.TrimSpace(caCertPath)
	if caCertPath == "" {
		return base
	}
	if _, err := os.Stat(caCertPath); err != nil {
		return base
	}
	if envHasKey(base, "NODE_EXTRA_CA_CERTS") {
		return base
	}
	// Claude Code (Bun) reads NODE_EXTRA_CA_CERTS; Node.js also supports it.
	return append(base, "NODE_EXTRA_CA_CERTS="+caCertPath)
}

func withProxyEnv(base []string, proxyURL string) []string {
	// Simple override: for duplicate keys, the last one wins.
	out := make([]string, 0, len(base)+4)
	for _, kv := range base {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		switch strings.ToUpper(k) {
		case "HTTPS_PROXY", "HTTP_PROXY", "https_proxy", "http_proxy":
			continue
		default:
			out = append(out, kv)
		}
	}
	out = append(out,
		"HTTPS_PROXY="+proxyURL,
		"HTTP_PROXY="+proxyURL,
		"https_proxy="+proxyURL,
		"http_proxy="+proxyURL,
	)
	return out
}

func envHasKey(env []string, key string) bool {
	key = strings.ToUpper(strings.TrimSpace(key))
	if key == "" {
		return false
	}
	for _, kv := range env {
		k := kv
		if i := strings.IndexByte(kv, '='); i >= 0 {
			k = kv[:i]
		}
		if strings.ToUpper(k) == key {
			return true
		}
	}
	return false
}

func isTerminal(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}

func proxyPidFilePath() string {
	return filepath.Join(config.GetConfigDir(), "vibeguard.pid")
}

func readProxyPid() (int, error) {
	b, err := os.ReadFile(proxyPidFilePath())
	if err != nil {
		return 0, err
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return 0, errors.New("empty pid file")
	}
	pid, err := strconv.Atoi(s)
	if err != nil {
		return 0, err
	}
	return pid, nil
}

func removeProxyPidIfMatches(pid int) error {
	b, err := os.ReadFile(proxyPidFilePath())
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(b)) != strconv.Itoa(pid) {
		return nil
	}
	return os.Remove(proxyPidFilePath())
}

func stopProcessByPID(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}

	if runtime.GOOS == "windows" {
		return p.Kill()
	}

	// Try to exit gracefully.
	if err := p.Signal(syscall.SIGTERM); err != nil {
		// The process may already have exited; treat as success.
		if !processAlive(pid) {
			return nil
		}
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if !processAlive(pid) {
			return nil
		}
		time.Sleep(120 * time.Millisecond)
	}

	// Still running after timeout: force kill.
	if err := p.Kill(); err != nil {
		if !processAlive(pid) {
			return nil
		}
		return err
	}
	return nil
}

func processAlive(pid int) bool {
	if pid <= 0 {
		return false
	}
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		// On Windows, signal 0 is not reliable; conservatively return true and let callers decide via other signals (e.g. port checks).
		return true
	}
	return p.Signal(syscall.Signal(0)) == nil
}

func proxyListenHostportForClient() (string, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return "", err
	}
	defer func() { _ = cfg.Close() }()

	listen := strings.TrimSpace(cfg.Get().Proxy.Listen)
	if listen == "" {
		listen = "127.0.0.1:28657"
	}
	if strings.HasPrefix(listen, ":") {
		return "127.0.0.1" + listen, nil
	}

	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		return listen, nil
	}

	host = strings.TrimSpace(host)
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") {
		return "[" + host + "]:" + port, nil
	}
	return host + ":" + port, nil
}

func tryStartBackgroundService() (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return false, fmt.Errorf("cannot determine home directory: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(home, "Library", "LaunchAgents", "com.vibeguard.proxy.plist")
		if _, err := os.Stat(plist); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if _, err := exec.LookPath("launchctl"); err != nil {
			return false, err
		}
		if err := startLaunchAgent(plist); err != nil {
			return false, err
		}
		return true, nil
	case "linux":
		unit := filepath.Join(home, ".config", "systemd", "user", "vibeguard.service")
		if _, err := os.Stat(unit); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			return false, err
		}
		if err := startSystemdUserService(); err != nil {
			return false, err
		}
		return true, nil
	case "windows":
		// Windows autostart is created by the installer (Scheduled Task name is fixed to "VibeGuard").
		if _, err := exec.LookPath("schtasks"); err != nil {
			return false, nil
		}
		if !windowsScheduledTaskExists("VibeGuard") {
			return false, nil
		}
		if err := startWindowsScheduledTask("VibeGuard"); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, nil
	}
}

func tryStopBackgroundService() (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return false, fmt.Errorf("cannot determine home directory: %w", err)
	}

	switch runtime.GOOS {
	case "darwin":
		plist := filepath.Join(home, "Library", "LaunchAgents", "com.vibeguard.proxy.plist")
		if _, err := os.Stat(plist); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if _, err := exec.LookPath("launchctl"); err != nil {
			return false, err
		}
		if err := stopLaunchAgent(plist); err != nil {
			return false, err
		}
		return true, nil
	case "linux":
		unit := filepath.Join(home, ".config", "systemd", "user", "vibeguard.service")
		if _, err := os.Stat(unit); err != nil {
			if os.IsNotExist(err) {
				return false, nil
			}
			return false, err
		}
		if _, err := exec.LookPath("systemctl"); err != nil {
			return false, err
		}
		if err := stopSystemdUserService(); err != nil {
			return false, err
		}
		return true, nil
	case "windows":
		if _, err := exec.LookPath("schtasks"); err != nil {
			return false, nil
		}
		if !windowsScheduledTaskExists("VibeGuard") {
			return false, nil
		}
		if err := stopWindowsScheduledTask("VibeGuard"); err != nil {
			return false, err
		}
		return true, nil
	default:
		return false, nil
	}
}

func startLaunchAgent(plistPath string) error {
	uid := os.Getuid()
	domain := fmt.Sprintf("gui/%d", uid)
	svc := domain + "/com.vibeguard.proxy"

	// Keep it idempotent: try removing existing registrations before bootstrap/kickstart.
	_ = exec.Command("launchctl", "bootout", domain, plistPath).Run()
	if out, err := exec.Command("launchctl", "bootstrap", domain, plistPath).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl bootstrap failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	_ = exec.Command("launchctl", "enable", svc).Run()
	if out, err := exec.Command("launchctl", "kickstart", "-k", svc).CombinedOutput(); err != nil {
		return fmt.Errorf("launchctl kickstart failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopLaunchAgent(plistPath string) error {
	uid := os.Getuid()
	domain := fmt.Sprintf("gui/%d", uid)

	out, err := exec.Command("launchctl", "bootout", domain, plistPath).CombinedOutput()
	if err != nil {
		s := strings.ToLower(strings.TrimSpace(string(out)))
		// Keep it idempotent: bootout may error if not loaded; treat as already stopped.
		if strings.Contains(s, "no such process") || strings.Contains(s, "not loaded") || strings.Contains(s, "could not find") {
			return nil
		}
		return fmt.Errorf("launchctl bootout failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func startSystemdUserService() error {
	if out, err := exec.Command("systemctl", "--user", "start", "vibeguard.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user start vibeguard.service failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopSystemdUserService() error {
	if out, err := exec.Command("systemctl", "--user", "stop", "vibeguard.service").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl --user stop vibeguard.service failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func windowsScheduledTaskExists(taskName string) bool {
	taskName = strings.TrimSpace(taskName)
	if taskName == "" {
		return false
	}
	// schtasks /Query /TN <name>
	c := exec.Command("schtasks", "/Query", "/TN", taskName)
	if err := c.Run(); err != nil {
		return false
	}
	return true
}

func startWindowsScheduledTask(taskName string) error {
	out, err := exec.Command("schtasks", "/Run", "/TN", taskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /Run failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func stopWindowsScheduledTask(taskName string) error {
	out, err := exec.Command("schtasks", "/End", "/TN", taskName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("schtasks /End failed: %w - %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func runProxy(cmd *cobra.Command, args []string) error {
	// Load config
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	defer func() { _ = cfg.Close() }()

	c := cfg.Get()

	// Pre-warm the local cache for the default rules subscription (so offline start works immediately);
	// later the subscription manager updates it.
	for _, rl := range c.Patterns.RuleLists {
		if strings.TrimSpace(rl.ID) != "vibeguard-default" {
			continue
		}
		if strings.TrimSpace(rl.URL) == "" {
			continue
		}
		if p, ok := rulelists.SubscriptionRulesPath(rl); ok && strings.TrimSpace(p) != "" {
			defaultrules.EnsureInstalled(p)
		}
		break
	}

	// Setup logging
	if err := log.Setup(c.Log.File, c.Log.Level); err != nil {
		return fmt.Errorf("failed to setup logging: %w", err)
	}

	// Record PID so `vibeguard stop` can locate and stop the background process.
	pid := os.Getpid()
	if err := os.MkdirAll(config.GetConfigDir(), 0o755); err == nil {
		_ = os.WriteFile(proxyPidFilePath(), []byte(strconv.Itoa(pid)+"\n"), 0o644)
	}
	defer func() { _ = removeProxyPidIfMatches(pid) }()

	slog.Info("Starting VibeGuard", "version", version.Version)

	// Get config dir for CA cert
	configDir := config.GetConfigDir()
	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")

	// Load or generate CA
	ca, err := cert.LoadOrGenerateCA(caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to load/generate CA: %w", err)
	}
	if !cert.IsCATrusted(caCertPath) {
		slog.Warn("CA 证书未被系统信任：启用 MITM 拦截时客户端可能报 TLS 错误；请先运行 vibeguard trust（或 vibeguard trust --mode system）", "cert_path", caCertPath)
	}

	// Derive a local "at-rest encryption" key from the CA private key:
	// used to encrypt keywords/excludes in config so plaintext is not written to disk.
	if key, err := ca.DeriveStorageKey(); err != nil {
		return fmt.Errorf("failed to derive storage key: %w", err)
	} else if err := cfg.SetPatternEncryptionKey(key); err != nil {
		return fmt.Errorf("failed to configure pattern encryption: %w", err)
	}
	// Reload config once to decrypt persisted ciphertext into plaintext in memory,
	// and ensure future saves write ciphertext back to disk.
	if err := cfg.Load(); err != nil {
		return fmt.Errorf("failed to reload config with pattern decryption: %w", err)
	}

	// Create proxy server
	srv, err := proxy.NewServer(cfg, ca, caCertPath, caKeyPath)
	if err != nil {
		return fmt.Errorf("failed to create proxy: %w", err)
	}
	// Enable config hot-reload: changes from the admin UI take effect without restart.
	if err := cfg.Watch(srv.ReloadFromConfig); err != nil {
		slog.Warn("Failed to enable config hot-reload; restart may be required after config changes", "error", err)
	}

	// Handle graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	errChan := make(chan error, 1)
	go func() {
		errChan <- srv.Start()
	}()

	select {
	case err := <-errChan:
		if isAddrInUseErr(err) {
			fmt.Fprintln(os.Stderr, uiText(uiLang(),
				"启动失败：监听地址已被占用。可先执行 'vibeguard stop' 停止已运行的实例，或修改配置中的 proxy.listen 端口后重试。",
				"Failed to start: the listen address is already in use. Run 'vibeguard stop' to stop the existing instance first, or change the proxy.listen port in the config and retry."))
		}
		return err
	case sig := <-sigChan:
		slog.Info("Received signal, shutting down", "signal", sig)
		srv.Stop()
	}

	return nil
}

// isAddrInUseErr reports whether err is an "address already in use" listen failure.
func isAddrInUseErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.EADDRINUSE) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "address already in use")
}

func runInit(cmd *cobra.Command, args []string) error {
	lang := uiLang()
	reader := bufio.NewReader(os.Stdin)

	// Get config directory
	configDir := config.GetConfigDir()
	configPath := filepath.Join(configDir, "config.yaml")

	// Check if config already exists
	if _, err := os.Stat(configPath); err == nil {
		fmt.Printf(uiText(lang, "配置文件已存在：%s\n", "Config file already exists at %s\n"), configPath)
		fmt.Print(uiText(lang, "是否覆盖？(y/N): ", "Overwrite? (y/N): "))
		answer, _ := reader.ReadString('\n')
		answer = strings.TrimSpace(answer)
		if !uiIsYes(lang, answer) {
			fmt.Println(uiText(lang, "已取消。", "Aborted."))
			return nil
		}
	}

	// Create config directory
	if err := os.MkdirAll(configDir, 0700); err != nil {
		if lang == "zh" {
			return fmt.Errorf("创建配置目录失败：%w", err)
		}
		return fmt.Errorf("failed to create config directory: %w", err)
	}

	fmt.Println(uiText(lang, "VibeGuard 初始化向导", "VibeGuard Setup Wizard"))
	fmt.Println("======================")
	fmt.Println()

	// Prompt for listen address
	fmt.Print(uiText(lang, "监听地址 [127.0.0.1:28657]: ", "Listen address [127.0.0.1:28657]: "))
	listen, _ := reader.ReadString('\n')
	listen = strings.TrimSpace(listen)
	if listen == "" {
		listen = "127.0.0.1:28657"
	}

	// Prompt for session TTL
	fmt.Print(uiText(lang, "会话 TTL（占位符映射保留时长） [1h]: ", "Session TTL (how long to remember redacted values) [1h]: "))
	ttl, _ := reader.ReadString('\n')
	ttl = strings.TrimSpace(ttl)
	if ttl == "" {
		ttl = "1h"
	}

	// Prompt for log file
	fmt.Print(uiText(lang, "日志文件路径 [~/.vibeguard/vibeguard.log]: ", "Log file path [~/.vibeguard/vibeguard.log]: "))
	logFile, _ := reader.ReadString('\n')
	logFile = strings.TrimSpace(logFile)
	if logFile == "" {
		logFile = filepath.Join(configDir, "vibeguard.log")
	}

	// Prompt for CA generation
	fmt.Print(uiText(lang, "生成 CA 证书？(Y/n): ", "Generate CA certificate? (Y/n): "))
	genCAAnswer, _ := reader.ReadString('\n')
	genCAAnswer = strings.TrimSpace(genCAAnswer)
	genCA := !uiIsNo(lang, genCAAnswer) // default: yes

	cfgTemplateZh := `# VibeGuard Configuration
	proxy:
	  listen: %s
	  placeholder_prefix: "__VG_"
	  # HTTPS intercept mode: global (default, intercept all) or targets (only intercept targets below)
	  intercept_mode: global
	  # Fallback policy when redaction would corrupt a JSON body: partial (default; drop only
	  # JSON-breaking matches and forward the rest redacted), block (reject the request),
	  # or allow (forward the original body unredacted)
	  invalid_json_policy: partial

session:
  ttl: %s
  max_mappings: 100000
  # WAL fsync batching interval ("0" = fsync every mapping, legacy behavior)
  # wal_sync_interval: 200ms
  # Rewrite the WAL with live mappings only when it exceeds this size (0 = never)
  # wal_compact_bytes: 4194304

log:
  file: %s
  level: info

# Optional: persist audit events to SQLite (full build only). Raw matched values are never
# persisted unless persist_raw_values is explicitly enabled.
# audit_db:
#   enabled: false
#   path: ~/.vibeguard/audit.db
#   retention: 7d
#   persist_raw_values: false

# Security-sensitive overrides from a project-level .vibeguard.yaml (audit_db, proxy.listen,
# proxy.intercept_mode, rule_lists URLs) are ignored unless explicitly allowed here.
# allow_project_sensitive_overrides: false

	# Target hosts to intercept (AI API endpoints)
	targets:
  - host: api.anthropic.com
    enabled: true
  - host: api.openai.com
    enabled: true
  - host: api2.cursor.sh
    enabled: true
  - host: generativelanguage.googleapis.com
    enabled: true
  - host: api.moonshot.cn
    enabled: true
  - host: api.moonshot.ai
    enabled: true
  - host: api.kimi.com
    enabled: true
  - host: opencode.ai
    enabled: true

	# Sensitive data matching rules
	patterns:
	  # Example (uncomment and remove the "keywords: []" line below, or use
	  # 'vibeguard rules add <word> --category <CATEGORY>'):
	  # keywords:
	  #   - value: "internal.example.com"
	  #     category: INTERNAL
	  keywords: []
	  exclude: []
	  # Optional: import secrets from local files (e.g. .env) and redact them automatically.
	  # secret_files:
	  #   - path: .env
	  #     format: dotenv
	  #     enabled: true
	  # Optional: remote rule-list subscriptions (.vgrules). sha256_pin pins the content
	  # hash against poisoning: leave empty or "tofu" for trust-on-first-use (the sha256 of
	  # the first successful fetch is recorded and later content changes are rejected), or
	  # pin a fixed 64-char hex sha256. Repeated sync failures are surfaced in the admin UI.
	  # rule_lists:
	  #   - name: my-rules
	  #     url: https://example.com/rules.vgrules
	  #     sha256_pin: tofu
	  #     enabled: true
	  #   # Local rule-list file example (mutually exclusive with url):
	  #   - path: ~/.vibeguard/rules/local/my.vgrules
	  #     enabled: true
	`

	cfgTemplateEn := `# VibeGuard Configuration
proxy:
  listen: %s
  placeholder_prefix: "__VG_"
  # HTTPS intercept mode: global (default, intercept all) or targets (only intercept targets below)
  intercept_mode: global
  # Fallback policy when redaction would corrupt a JSON body: partial (default; drop only
  # JSON-breaking matches and forward the rest redacted), block (reject the request),
  # or allow (forward the original body unredacted)
  invalid_json_policy: partial

session:
  ttl: %s
  max_mappings: 100000
  # WAL fsync batching interval ("0" = fsync every mapping, legacy behavior)
  # wal_sync_interval: 200ms
  # Rewrite the WAL with live mappings only when it exceeds this size (0 = never)
  # wal_compact_bytes: 4194304

log:
  file: %s
  level: info

# Optional: persist audit events to SQLite (full build only). Raw matched values are never
# persisted unless persist_raw_values is explicitly enabled.
# audit_db:
#   enabled: false
#   path: ~/.vibeguard/audit.db
#   retention: 7d
#   persist_raw_values: false

# Security-sensitive overrides from a project-level .vibeguard.yaml (audit_db, proxy.listen,
# proxy.intercept_mode, rule_lists URLs) are ignored unless explicitly allowed here.
# allow_project_sensitive_overrides: false

# Target hosts to intercept (AI API endpoints)
targets:
  - host: api.anthropic.com
    enabled: true
  - host: api.openai.com
    enabled: true
  - host: api2.cursor.sh
    enabled: true
  - host: generativelanguage.googleapis.com
    enabled: true
  - host: api.moonshot.cn
    enabled: true
  - host: api.moonshot.ai
    enabled: true
  - host: api.kimi.com
    enabled: true
  - host: opencode.ai
    enabled: true

# Sensitive data patterns
patterns:
  # Example (uncomment and remove the "keywords: []" line below, or use
  # 'vibeguard rules add <word> --category <CATEGORY>'):
  # keywords:
  #   - value: "internal.example.com"
  #     category: INTERNAL
  keywords: []
  exclude: []
  # Optional: import secrets from local files (e.g. .env) and redact them automatically.
  # secret_files:
  #   - path: .env
  #     format: dotenv
  #     enabled: true
  # Optional: remote rule-list subscriptions (.vgrules). sha256_pin pins the content
  # hash against poisoning: leave empty or "tofu" for trust-on-first-use (the sha256 of
  # the first successful fetch is recorded and later content changes are rejected), or
  # pin a fixed 64-char hex sha256. Repeated sync failures are surfaced in the admin UI.
  # rule_lists:
  #   - name: my-rules
  #     url: https://example.com/rules.vgrules
  #     sha256_pin: tofu
  #     enabled: true
  #   # Local rule-list file example (mutually exclusive with url):
  #   - path: ~/.vibeguard/rules/local/my.vgrules
  #     enabled: true
`

	// Write config
	var cfgContent string
	if lang == "zh" {
		cfgContent = fmt.Sprintf(cfgTemplateZh, listen, ttl, logFile)
	} else {
		cfgContent = fmt.Sprintf(cfgTemplateEn, listen, ttl, logFile)
	}

	if err := os.WriteFile(configPath, []byte(cfgContent), 0600); err != nil {
		if lang == "zh" {
			return fmt.Errorf("写入配置失败：%w", err)
		}
		return fmt.Errorf("failed to write config: %w", err)
	}

	fmt.Printf(uiText(lang, "\n配置已写入 %s\n", "\nConfig written to %s\n"), configPath)

	// Generate CA if requested
	if genCA {
		caCertPath := filepath.Join(configDir, "ca.crt")
		caKeyPath := filepath.Join(configDir, "ca.key")

		_, err := cert.LoadOrGenerateCA(caCertPath, caKeyPath)
		if err != nil {
			if lang == "zh" {
				return fmt.Errorf("生成 CA 证书失败：%w", err)
			}
			return fmt.Errorf("failed to generate CA: %w", err)
		}

		fmt.Printf(uiText(lang, "CA 证书已生成：%s\n", "CA certificate generated at %s\n"), caCertPath)

		// Ask about trusting (default: system, since many CLI tools won't trust user-only stores)
		printCARiskHint(lang, os.Stdout)
		fmt.Println()
		fmt.Println(uiText(lang, "\n是否将 CA 证书安装到信任库？", "\nInstall CA certificate to trust store?"))
		fmt.Println(uiText(lang, "  1) 系统信任库（需要 sudo，推荐）", "  1) System trust store (sudo, recommended)"))
		fmt.Println(uiText(lang, "  2) 用户信任库（无需 sudo）", "  2) User trust store (no sudo)"))
		fmt.Println(uiText(lang, "  3) 跳过", "  3) Skip"))
		fmt.Print(uiText(lang, "选择 [1]: ", "Choose [1]: "))
		choice, _ := reader.ReadString('\n')
		choice = strings.TrimSpace(choice)

		var mode cert.TrustInstallMode
		switch choice {
		case "", "1":
			mode = cert.TrustInstallModeSystem
		case "2":
			mode = cert.TrustInstallModeUser
		case "3":
			mode = ""
		default:
			fmt.Println(uiText(lang, "无效选项，已跳过。", "Invalid choice, skipping."))
			mode = ""
		}

		if mode != "" {
			if err := cert.InstallCAToTrustStore(caCertPath, mode); err != nil {
				fmt.Printf(uiText(lang, "安装 CA 失败：%v\n", "Failed to install CA: %v\n"), err)
				fmt.Println(uiText(lang, "你可能需要运行：vibeguard trust --mode system", "You may need to run: vibeguard trust --mode system"))
			} else {
				fmt.Printf(uiText(lang, "CA 证书已安装（%s）！\n", "CA certificate installed (%s)!\n"), mode)
			}
		}
	}

	fmt.Println(uiText(lang, "\n初始化完成！运行 'vibeguard start' 开始使用。", "\nSetup complete! Run 'vibeguard start' to begin."))
	return nil
}

// printCARiskHint prints a short security note about the local CA before it is
// trusted: the private key is only as protected as this user account, and how to
// remove the trust later. Used by `vibeguard trust` and the init wizard.
func printCARiskHint(lang string, w io.Writer) {
	caKeyPath := filepath.Join(config.GetConfigDir(), "ca.key")
	fmt.Fprintln(w, uiText(lang, "安全提示：", "Security note:"))
	fmt.Fprintf(w, uiText(lang,
		"  - CA 私钥位于 %s（权限 0600 仅防其他用户；以你身份运行的恶意软件仍可读取并冒签证书，请保管好本机环境）。\n",
		"  - The CA private key lives at %s (mode 0600 only keeps out other users; malware running as you can still read it and mint certificates — keep this machine clean)."),
		caKeyPath)
	fmt.Fprintln(w, uiText(lang,
		"  - 卸载/移除信任：运行 uninstall.sh（Windows 用 uninstall.ps1），它会尝试自动从信任库移除 \"VibeGuard CA\"；也可手动从系统/用户信任库删除该证书。",
		"  - To uninstall/remove trust later: run uninstall.sh (uninstall.ps1 on Windows), which tries to remove \"VibeGuard CA\" from the trust store automatically; you can also delete that certificate from the system/user trust store manually."))
}

func runTrust(cmd *cobra.Command, args []string) error {
	lang := uiLang()
	configDir := config.GetConfigDir()
	caCertPath := filepath.Join(configDir, "ca.crt")

	// Check if CA cert exists
	if _, err := os.Stat(caCertPath); os.IsNotExist(err) {
		if lang == "zh" {
			return fmt.Errorf("未找到 CA 证书：%s。请先运行 'vibeguard init'", caCertPath)
		}
		return fmt.Errorf("CA certificate not found at %s. Run 'vibeguard init' first", caCertPath)
	}

	printCARiskHint(lang, os.Stdout)
	fmt.Println()

	fmt.Printf(uiText(lang, "正在安装 CA 证书（来源：%s）\n", "Installing CA certificate from %s\n"), caCertPath)
	fmt.Println(uiText(lang, "可能会提示输入管理员权限...", "This may prompt for administrator privileges..."))

	mode := cert.TrustInstallMode(strings.ToLower(strings.TrimSpace(trustMode)))
	switch mode {
	case cert.TrustInstallModeAuto, cert.TrustInstallModeUser, cert.TrustInstallModeSystem:
	default:
		if lang == "zh" {
			return fmt.Errorf("无效的 --mode %q（可选：system|user|auto）", trustMode)
		}
		return fmt.Errorf("invalid --mode %q (expected: system|user|auto)", trustMode)
	}

	if err := cert.InstallCAToTrustStore(caCertPath, mode); err != nil {
		if lang == "zh" {
			return fmt.Errorf("安装 CA 失败：%w", err)
		}
		return fmt.Errorf("failed to install CA: %w", err)
	}

	fmt.Println(uiText(lang, "CA 证书安装成功！", "CA certificate installed successfully!"))
	return nil
}

func runTest(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	// Dry-run mode: full detection pipeline from the real config.
	if text := strings.TrimSpace(testText); text != "" {
		if len(args) > 0 {
			return errors.New(uiText(lang,
				"--text 模式不接受位置参数（用法：vibeguard test --text \"要检测的文本\"）。",
				"--text mode takes no positional arguments (usage: vibeguard test --text \"text to check\")."))
		}
		return runTestDryRun(cmd, lang, text)
	}

	if len(args) != 2 {
		return errors.New(uiText(lang,
			"用法：vibeguard test <pattern> <text>，或 vibeguard test --text \"要检测的文本\"。",
			"usage: vibeguard test <pattern> <text>, or vibeguard test --text \"text to check\"."))
	}

	pattern := args[0]
	text := args[1]

	// Create a minimal session manager
	sess := session.NewManager(0, 1000)
	eng := redact.NewEngine(sess, "__VG_")

	// Keywords only: replace the keyword substring itself to avoid overly-broad regex-style matches.
	eng.AddKeyword(pattern, "TEST")

	// Perform redaction
	redacted, count := eng.Redact([]byte(text))

	fmt.Printf("Original: %s\n", text)
	fmt.Printf("Redacted: %s\n", string(redacted))
	fmt.Printf("Matches:  %d\n", count)

	if count > 0 {
		fmt.Println("\nPlaceholders registered:")
		// Note: We can't easily iterate the session, so just note that they exist
		fmt.Printf("  %d mapping(s) stored\n", sess.Size())
	}

	return nil
}

// loadRulesConfig loads the effective config with pattern at-rest decryption configured,
// mirroring the daemon's setup in runProxy: the storage key is derived from the CA
// private key so `rules list` shows plaintext while values on disk stay encrypted
// (and stay compatible with Admin UI writes).
func loadRulesConfig(lang string) (*config.Manager, error) {
	cfg, err := config.Load(cfgFile)
	if err != nil {
		return nil, fmt.Errorf(uiText(lang, "加载配置失败：%v", "Failed to load config: %v"), err)
	}

	configDir := config.GetConfigDir()
	caCertPath := filepath.Join(configDir, "ca.crt")
	caKeyPath := filepath.Join(configDir, "ca.key")

	// If a config file already exists but the CA private key is missing, any previously
	// encrypted keyword values would be undecryptable (a freshly generated CA derives a
	// different key), so refuse with a clear hint instead of silently generating a new CA.
	if _, err := os.Stat(caKeyPath); err != nil && rulesConfigFileExists() {
		_ = cfg.Close()
		return nil, fmt.Errorf(uiText(lang,
			"未找到 CA 私钥：%s，无法解密配置中可能存在的加密关键词。请先运行 'vibeguard init' 或 'vibeguard start' 初始化（注意：由旧 CA 加密的密文将无法恢复）。",
			"CA private key not found at %s; cannot decrypt any encrypted keywords in the config. Run 'vibeguard init' or 'vibeguard start' to set up first (note: ciphertext encrypted by a previous CA cannot be recovered)."), caKeyPath)
	}

	ca, err := cert.LoadOrGenerateCA(caCertPath, caKeyPath)
	if err != nil {
		_ = cfg.Close()
		return nil, fmt.Errorf(uiText(lang, "加载/生成 CA 证书失败：%v", "Failed to load/generate CA: %v"), err)
	}
	key, err := ca.DeriveStorageKey()
	if err != nil {
		_ = cfg.Close()
		return nil, fmt.Errorf(uiText(lang, "派生配置加密密钥失败：%v", "Failed to derive the pattern storage key: %v"), err)
	}
	if err := cfg.SetPatternEncryptionKey(key); err != nil {
		_ = cfg.Close()
		return nil, fmt.Errorf(uiText(lang, "配置关键词加密失败：%v", "Failed to configure pattern encryption: %v"), err)
	}
	// Reload so persisted ciphertext is decrypted into plaintext in memory;
	// subsequent Update() calls write ciphertext back to disk.
	if err := cfg.Load(); err != nil {
		_ = cfg.Close()
		return nil, fmt.Errorf(uiText(lang,
			"解密配置中的关键词失败：%v（CA 私钥可能已更换，旧密文无法解密）",
			"Failed to decrypt keywords in the config: %v (the CA private key may have changed; old ciphertext cannot be decrypted)"), err)
	}
	return cfg, nil
}

// rulesConfigFileExists reports whether the target config file (global, or the one
// given via --config) already exists on disk.
func rulesConfigFileExists() bool {
	p := strings.TrimSpace(cfgFile)
	if p == "" {
		p = config.ConfigPath()
	} else if strings.HasPrefix(p, "~/") {
		if home, err := os.UserHomeDir(); err == nil && strings.TrimSpace(home) != "" {
			p = filepath.Join(home, p[2:])
		}
	}
	_, err := os.Stat(p)
	return err == nil
}

// warnIfProjectConfigMerged warns that a project-level .vibeguard.yaml in the working
// directory is merged into the effective config, and Manager.Update persists the merged
// result into the global config file.
func warnIfProjectConfigMerged(lang string, w io.Writer) {
	if _, err := os.Stat(config.ProjectConfigPath()); err == nil {
		fmt.Fprintln(w, uiText(lang,
			"警告：当前目录存在项目级配置 .vibeguard.yaml；其关键词会并入生效配置，并随本次写入一并保存到全局配置。",
			"Warning: a project-level .vibeguard.yaml exists in the current directory; its keywords are merged into the effective config and will be persisted into the global config on save."))
	}
}

func printRulesHotReloadHint(lang string, w io.Writer) {
	fmt.Fprintln(w, uiText(lang,
		"提示：运行中的代理会自动热加载新配置，无需重启。",
		"Tip: a running proxy hot-reloads the new config automatically; no restart needed."))
}

func runRulesList(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	cfg, err := loadRulesConfig(lang)
	if err != nil {
		return err
	}
	defer func() { _ = cfg.Close() }()

	keywords := cfg.Get().Patterns.Keywords
	if len(keywords) == 0 {
		fmt.Fprintln(cmd.OutOrStdout(), uiText(lang, "当前没有配置任何关键词（patterns.keywords 为空）。", "No keywords configured (patterns.keywords is empty)."))
		return nil
	}

	fmt.Fprintf(cmd.OutOrStdout(), uiText(lang, "共 %d 个关键词：\n", "%d keyword(s):\n"), len(keywords))
	for _, kw := range keywords {
		fmt.Fprintf(cmd.OutOrStdout(), "  - %s (category: %s)\n", kw.Value, kw.Category)
	}
	return nil
}

func runRulesAdd(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	value := config.SanitizePatternValue(args[0])
	if value == "" {
		return errors.New(uiText(lang, "关键词不能为空（或仅包含不可见字符）。", "Keyword must not be empty (or contains only invisible characters)."))
	}
	category := config.SanitizeCategory(rulesCategory)
	if category == "" {
		category = "TEXT"
	}

	cfg, err := loadRulesConfig(lang)
	if err != nil {
		return err
	}
	defer func() { _ = cfg.Close() }()

	for _, kw := range cfg.Get().Patterns.Keywords {
		if kw.Value == value {
			return fmt.Errorf(uiText(lang,
				"关键词 %q 已存在（分类：%s），未重复添加。",
				"Keyword %q already exists (category: %s); not added again."), value, kw.Category)
		}
	}

	warnIfProjectConfigMerged(lang, cmd.ErrOrStderr())

	if err := cfg.Update(func(c *config.Config) {
		c.Patterns.Keywords = append(c.Patterns.Keywords, config.KeywordPattern{Value: value, Category: category})
	}); err != nil {
		return fmt.Errorf(uiText(lang, "写入配置失败：%v", "Failed to write config: %v"), err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), uiText(lang, "已添加关键词 %q（分类：%s）。\n", "Added keyword %q (category: %s).\n"), value, category)
	printRulesHotReloadHint(lang, cmd.OutOrStdout())
	return nil
}

func runRulesRemove(cmd *cobra.Command, args []string) error {
	lang := uiLang()

	value := config.SanitizePatternValue(args[0])
	if value == "" {
		return errors.New(uiText(lang, "关键词不能为空（或仅包含不可见字符）。", "Keyword must not be empty (or contains only invisible characters)."))
	}

	cfg, err := loadRulesConfig(lang)
	if err != nil {
		return err
	}
	defer func() { _ = cfg.Close() }()

	existing := cfg.Get().Patterns.Keywords
	kept := make([]config.KeywordPattern, 0, len(existing))
	removed := 0
	for _, kw := range existing {
		if kw.Value == value {
			removed++
			continue
		}
		kept = append(kept, kw)
	}
	if removed == 0 {
		return fmt.Errorf(uiText(lang,
			"未找到关键词 %q（可用 'vibeguard rules list' 查看当前关键词）。",
			"Keyword %q not found (use 'vibeguard rules list' to see current keywords)."), value)
	}

	warnIfProjectConfigMerged(lang, cmd.ErrOrStderr())

	if err := cfg.Update(func(c *config.Config) {
		c.Patterns.Keywords = kept
	}); err != nil {
		return fmt.Errorf(uiText(lang, "写入配置失败：%v", "Failed to write config: %v"), err)
	}

	fmt.Fprintf(cmd.OutOrStdout(), uiText(lang, "已删除关键词 %q（%d 条）。\n", "Removed keyword %q (%d).\n"), value, removed)
	printRulesHotReloadHint(lang, cmd.OutOrStdout())
	return nil
}
