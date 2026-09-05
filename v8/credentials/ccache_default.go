package credentials

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/jcmturner/gokrb5/v8/config"
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
	if strings.HasPrefix(name, "FILE:") {
		name = strings.TrimPrefix(name, "FILE:")
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
	return colon == 1 && len(name) > 2 && ((name[0] >= 'A' && name[0] <= 'Z') || (name[0] >= 'a' && name[0] <= 'z')) && (name[2] == '\\' || name[2] == '/')
}
