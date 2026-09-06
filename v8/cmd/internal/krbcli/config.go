package krbcli

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
)

// LoadConfig loads the first usable path from KRB5_CONFIG or the platform default.
func LoadConfig() (*config.Config, error) {
	paths := configPaths()
	var lastErr error
	for _, path := range paths {
		cfg, err := config.Load(path)
		if err == nil {
			return cfg, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = errors.New("no Kerberos configuration path configured")
	}
	return nil, lastErr
}

func configPaths() []string {
	if value := os.Getenv("KRB5_CONFIG"); value != "" {
		return nonEmptyStrings(strings.Split(value, string(os.PathListSeparator)))
	}
	if runtime.GOOS == "windows" {
		if root := os.Getenv("ProgramData"); root != "" {
			return []string{filepath.Join(root, "MIT", "Kerberos5", "krb5.ini")}
		}
		return []string{"C:\\ProgramData\\MIT\\Kerberos5\\krb5.ini"}
	}
	return []string{"/etc/krb5.conf"}
}

func nonEmptyStrings(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

// ParseDuration parses MIT duration forms used by kinit flags.
func ParseDuration(value string) (time.Duration, error) {
	const maxDuration = time.Duration(1<<63 - 1)
	if value == "" {
		return 0, errors.New("empty duration")
	}
	if daysAt := strings.IndexByte(value, 'd'); daysAt >= 0 {
		days, err := strconv.ParseUint(value[:daysAt], 10, 31)
		if err != nil {
			return 0, errors.New("invalid duration")
		}
		if days > uint64(maxDuration/(24*time.Hour)) {
			return 0, errors.New("duration out of range")
		}
		duration := time.Duration(days) * 24 * time.Hour
		rest := time.Duration(0)
		if daysAt+1 < len(value) {
			rest, err = time.ParseDuration(value[daysAt+1:])
			if err != nil {
				return 0, errors.New("invalid duration")
			}
		}
		if rest > maxDuration-duration {
			return 0, errors.New("duration out of range")
		}
		return duration + rest, nil
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return duration, nil
	}
	if strings.Contains(value, ":") {
		var hours, minutes, seconds int64
		var err error
		parts := strings.Split(value, ":")
		if len(parts) < 2 || len(parts) > 3 {
			return 0, errors.New("invalid duration")
		}
		if hours, err = strconv.ParseInt(parts[0], 10, 64); err != nil || hours < 0 {
			return 0, errors.New("invalid duration")
		}
		if minutes, err = strconv.ParseInt(parts[1], 10, 64); err != nil || minutes < 0 || minutes > 59 {
			return 0, errors.New("invalid duration")
		}
		if len(parts) == 3 {
			if seconds, err = strconv.ParseInt(parts[2], 10, 64); err != nil || seconds < 0 || seconds > 59 {
				return 0, errors.New("invalid duration")
			}
		}
		if hours > int64(maxDuration/time.Hour) {
			return 0, errors.New("duration out of range")
		}
		return time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second, nil
	}
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errors.New("invalid duration")
	}
	if seconds > uint64(maxDuration/time.Second) {
		return 0, errors.New("duration out of range")
	}
	return time.Duration(seconds) * time.Second, nil
}
