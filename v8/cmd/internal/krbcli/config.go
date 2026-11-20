// Package krbcli provides shared helpers for the gokrb5 command-line tools.
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
		if err != nil {
			lastErr = err
			continue
		}
		if cfg == nil {
			//nolint:staticcheck // Preserve the existing CLI error text.
			lastErr = errors.New("Kerberos configuration loader returned nil configuration")
			continue
		}
		return cfg, nil
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

const maxDuration = time.Duration(1<<63 - 1)

var (
	errInvalidDuration = errors.New("invalid duration")
	errDurationRange   = errors.New("duration out of range")
)

// ParseDuration parses MIT duration forms used by kinit flags.
func ParseDuration(value string) (time.Duration, error) {
	if value == "" {
		return 0, errors.New("empty duration")
	}
	if days, suffix, found := strings.Cut(value, "d"); found {
		return parseDayDuration(days, suffix)
	}
	if duration, err := time.ParseDuration(value); err == nil {
		return duration, nil
	}
	if hours, remainder, found := strings.Cut(value, ":"); found {
		return parseClockDuration(hours, remainder)
	}
	seconds, err := strconv.ParseUint(value, 10, 64)
	if err != nil {
		return 0, errInvalidDuration
	}
	if seconds > uint64(maxDuration/time.Second) {
		return 0, errDurationRange
	}
	return time.Duration(seconds) * time.Second, nil
}

func parseDayDuration(value, suffix string) (time.Duration, error) {
	const day = 24 * time.Hour
	days, err := strconv.ParseUint(value, 10, 31)
	if err != nil {
		return 0, errInvalidDuration
	}
	if days > uint64(maxDuration/day) {
		return 0, errDurationRange
	}
	duration := time.Duration(days) * day
	if suffix == "" {
		return duration, nil
	}
	rest, err := time.ParseDuration(suffix)
	if err != nil {
		return 0, errInvalidDuration
	}
	if rest > maxDuration-duration {
		return 0, errDurationRange
	}
	return duration + rest, nil
}

func parseClockDuration(hourText, remainder string) (time.Duration, error) {
	minuteText, secondText, hasSeconds := strings.Cut(remainder, ":")
	hours, err := strconv.ParseInt(hourText, 10, 64)
	if err != nil || hours < 0 {
		return 0, errInvalidDuration
	}
	minutes, err := parseClockField(minuteText)
	if err != nil {
		return 0, err
	}
	var seconds int64
	if hasSeconds {
		seconds, err = parseClockField(secondText)
		if err != nil {
			return 0, err
		}
	}
	if hours > int64(maxDuration/time.Hour) {
		return 0, errDurationRange
	}
	return time.Duration(hours)*time.Hour + time.Duration(minutes)*time.Minute + time.Duration(seconds)*time.Second, nil
}

func parseClockField(value string) (int64, error) {
	const maxClockField = 59
	field, err := strconv.ParseInt(value, 10, 64)
	if err != nil || field < 0 || field > maxClockField {
		return 0, errInvalidDuration
	}
	return field, nil
}
