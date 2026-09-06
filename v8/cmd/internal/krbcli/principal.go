package krbcli

import (
	"errors"
	"net"
	"os"
	"os/user"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/keytab"
)

// ResolvePrincipal applies kinit's explicit, cache, keytab, and local-user defaults.
func ResolvePrincipal(value, cacheName string, keytabLogin, enterprise bool, cfg *config.Config) (keytab.Principal, error) {
	if value != "" {
		return parsePrincipalWithDefaultRealm(value, enterprise, cfg)
	}
	if keytabLogin {
		hostname, err := canonicalHostname()
		if err != nil {
			return keytab.Principal{}, err
		}
		return parsePrincipalWithDefaultRealm("host/"+hostname, false, cfg)
	}
	if cacheName != "" {
		if cache, err := credentials.LoadCCache(cacheName); err == nil &&
			cache.DefaultPrincipal.Realm != "" && len(cache.DefaultPrincipal.PrincipalName.NameString) > 0 {
			return keytab.Principal{
				Realm:      cache.DefaultPrincipal.Realm,
				Components: append([]string(nil), cache.DefaultPrincipal.PrincipalName.NameString...),
				NameType:   cache.DefaultPrincipal.PrincipalName.NameType,
			}, nil
		}
	}
	current, err := user.Current()
	if err != nil || current.Username == "" {
		return keytab.Principal{}, errors.New("unable to determine default client principal")
	}
	return parsePrincipalWithDefaultRealm(current.Username, false, cfg)
}

func parsePrincipalWithDefaultRealm(value string, enterprise bool, cfg *config.Config) (keytab.Principal, error) {
	if enterprise && strings.Count(value, "@") < 2 {
		if cfg == nil || cfg.LibDefaults.DefaultRealm == "" {
			return keytab.Principal{}, errors.New("enterprise principal has no realm and no default realm is configured")
		}
		value += "@" + cfg.LibDefaults.DefaultRealm
	}
	principal, err := keytab.ParsePrincipal(value)
	if err != nil {
		return principal, err
	}
	if principal.Realm == "" && cfg != nil {
		principal.Realm = cfg.LibDefaults.DefaultRealm
	}
	if principal.Realm == "" {
		return principal, errors.New("principal has no realm and no default realm is configured")
	}
	return principal, nil
}

func canonicalHostname() (string, error) {
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	if canonical, lookupErr := net.LookupCNAME(hostname); lookupErr == nil && canonical != "" {
		hostname = canonical
	}
	return strings.TrimSuffix(strings.ToLower(hostname), "."), nil
}
