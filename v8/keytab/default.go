package keytab

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/config"
)

const (
	defaultKeytabName       = "FILE:/etc/krb5.keytab"
	defaultClientKeytabName = "FILE:/var/kerberos/krb5/user/%{euid}/client.keytab"
)

var defaultClientKeytabNames = []string{
	defaultClientKeytabName,
	"FILE:/etc/krb5/user/%{euid}/client.keytab",
	"FILE:/var/lib/krb5/user/%{euid}/client.keytab",
}

// ResolveName resolves a FILE or WRFILE keytab name to a filesystem path.
// The writable result reports whether the WRFILE type was requested.
func ResolveName(name string, cfg *config.Config) (path string, writable bool, err error) {
	if name == "" {
		name = defaultKeytabName
		if cfg != nil && cfg.LibDefaults.DefaultKeytabName != "" {
			name = cfg.LibDefaults.DefaultKeytabName
		}
	}
	switch {
	case strings.HasPrefix(name, "FILE:"):
		name = strings.TrimPrefix(name, "FILE:")
	case strings.HasPrefix(name, "WRFILE:"):
		name = strings.TrimPrefix(name, "WRFILE:")
		writable = true
	case !isWindowsDrivePath(name) && strings.Contains(strings.SplitN(name, "/", 2)[0], ":"):
		return "", false, fmt.Errorf("unsupported keytab type in %q", name)
	}
	if name == "" {
		return "", false, errors.New("keytab path is empty")
	}
	uid, euid := currentUIDs()
	username := ""
	if current, userErr := user.Current(); userErr == nil {
		username = current.Username
	}
	name = strings.NewReplacer(
		"%{uid}", uid,
		"%{euid}", euid,
		"%{username}", username,
	).Replace(name)
	if strings.Contains(name, "%{") {
		return "", false, fmt.Errorf("unsupported parameter in keytab name %q", name)
	}
	return name, writable, nil
}

func isWindowsDrivePath(name string) bool {
	return len(name) >= 2 && name[1] == ':' &&
		(('A' <= name[0] && name[0] <= 'Z') || ('a' <= name[0] && name[0] <= 'z'))
}

// LoadDefault loads the default acceptor keytab.
func LoadDefault(cfg *config.Config) (*Keytab, error) {
	name := os.Getenv("KRB5_KTNAME")
	if name == "" && cfg != nil {
		name = cfg.LibDefaults.DefaultKeytabName
	}
	if name == "" {
		name = defaultKeytabName
	}
	return Load(name)
}

// LoadDefaultClient loads the default client keytab.
func LoadDefaultClient(cfg *config.Config) (*Keytab, error) {
	name := os.Getenv("KRB5_CLIENT_KTNAME")
	if name == "" && cfg != nil {
		name = cfg.LibDefaults.DefaultClientKeytabName
	}
	if name == "" {
		name = defaultClientKeytabName
	}
	if name == defaultClientKeytabName {
		name = firstExistingKeytabName(defaultClientKeytabNames)
	}
	return Load(name)
}

func firstExistingKeytabName(names []string) string {
	for _, name := range names {
		path, _, err := ResolveName(name, nil)
		if err != nil {
			return name
		}
		if _, statErr := os.Stat(path); statErr == nil || !os.IsNotExist(statErr) {
			return name
		}
	}
	return names[0]
}
