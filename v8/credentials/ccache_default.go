package credentials

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/config"
)

const defaultCCacheName = "FILE:/tmp/krb5cc_%{uid}"

// DefaultCCacheName resolves the default FILE credential cache path.
func DefaultCCacheName(cfg *config.Config) (string, error) {
	name := os.Getenv("KRB5CCNAME")
	if name == "" && cfg != nil {
		name = cfg.LibDefaults.DefaultCCacheName
	}
	if name == "" {
		name = defaultCCacheName
	}
	return resolveCCacheName(name)
}

// ResolveCCacheName resolves a FILE credential cache name to a filesystem path.
func ResolveCCacheName(name string) (string, error) {
	return resolveCCacheName(name)
}

func resolveCCacheName(name string) (string, error) {
	if name == "" {
		return "", errors.New("credential cache path is empty")
	}
	if path, ok := strings.CutPrefix(name, "FILE:"); ok {
		name = path
	} else if index := strings.IndexByte(name, ':'); index >= 0 && !isWindowsDriveName(name, index) {
		return "", fmt.Errorf("unsupported credential cache type %q", name[:index])
	}
	uid, euid := currentCacheUIDs()
	username := ""
	if current, err := user.Current(); err == nil {
		username = current.Username
	}
	name = strings.NewReplacer(
		"%{uid}", uid,
		"%{euid}", euid,
		"%{username}", username,
		"%{TEMP}", os.TempDir(),
	).Replace(name)
	if name == "" {
		return "", errors.New("credential cache path is empty")
	}
	if strings.Contains(name, "%{") {
		return "", fmt.Errorf("unsupported parameter in credential cache name %q", name)
	}
	return name, nil
}

func isWindowsDriveName(name string, colon int) bool {
	if colon != 1 || len(name) <= 2 {
		return false
	}
	drive := name[0]
	isLetter := (drive >= 'A' && drive <= 'Z') || (drive >= 'a' && drive <= 'z')
	return isLetter && (name[2] == '\\' || name[2] == '/')
}
