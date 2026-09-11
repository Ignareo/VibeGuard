package log

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
)

// Setup initializes the logger with file output
func Setup(logPath string, level string) error {
	logPath = ExpandPath(logPath)

	// Ensure log directory exists
	logDir := filepath.Dir(logPath)
	if err := os.MkdirAll(logDir, 0700); err != nil {
		return err
	}

	// Open log file (logs may contain previews of sensitive matches: owner-only).
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	// Tighten permissions on pre-existing log files too (mode only applies on creation).
	_ = os.Chmod(logPath, 0600)

	// Parse log level
	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	// Create handler that writes to both stderr and file
	handler := slog.NewTextHandler(io.MultiWriter(os.Stderr, logFile), &slog.HandlerOptions{
		Level: slogLevel,
	})

	slog.SetDefault(slog.New(handler))
	return nil
}

// SetFileOnly switches to file-only logging (no stderr)
func SetFileOnly(logPath string, level string) error {
	logPath = ExpandPath(logPath)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return err
	}
	// Tighten permissions on pre-existing log files too (mode only applies on creation).
	_ = os.Chmod(logPath, 0600)

	var slogLevel slog.Level
	switch level {
	case "debug":
		slogLevel = slog.LevelDebug
	case "info":
		slogLevel = slog.LevelInfo
	case "warn":
		slogLevel = slog.LevelWarn
	case "error":
		slogLevel = slog.LevelError
	default:
		slogLevel = slog.LevelInfo
	}

	handler := slog.NewTextHandler(logFile, &slog.HandlerOptions{
		Level: slogLevel,
	})

	slog.SetDefault(slog.New(handler))
	return nil
}

// ExpandPath expands "~/" in paths (current user only), avoiding writing logs into a literal "~" directory under a relative path.
func ExpandPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return path
	}
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return home
		}
		return path
	}
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~"+string(os.PathSeparator)) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			return filepath.Join(home, path[2:])
		}
	}
	return path
}
