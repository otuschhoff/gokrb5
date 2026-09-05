// Package ad discovers the Active Directory domain and credentials used by the
// AD integration tests from the host's FQDN and the repository root.
package ad

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/test"
)

// Environment variables that override Active Directory test discovery.
const (
	RealmEnvVar        = "TESTAD_REALM"
	DirEnvVar          = "TESTAD_DIR"
	KeytabEnvVar       = "TESTAD_KEYTAB"
	UserFileEnvVar     = "TESTAD_USER_FILE"
	PasswordFileEnvVar = "TESTAD_PASSWORD_FILE"
)

// Default credential file names, resolved relative to the repository root.
const (
	KeytabFile   = "krb5.keytab"
	UserFile     = "user"
	PasswordFile = "pw"
)

// Env describes the Active Directory domain discovered for integration tests.
type Env struct {
	// Realm is the upper-case Kerberos realm derived from the host's DNS domain.
	Realm string
	// Domain is the lower-case DNS domain of the host.
	Domain string
	// HostFQDN is the fully qualified name of the local host.
	HostFQDN string
	// User and UserRealm are parsed from the user principal file.
	User      string
	UserRealm string
	// Password is read from the password file.
	Password string
	// Keytab is the service keytab loaded from KeytabPath.
	Keytab     *keytab.Keytab
	KeytabPath string
	// Config discovers KDCs for Realm through DNS SRV records.
	Config *config.Config
}

// Environment skips the test unless TESTAD is set, then discovers the AD
// domain from the host's FQDN and loads credentials from the repository root.
func Environment(t *testing.T) *Env {
	t.Helper()
	test.AD(t)
	env, err := Discover()
	if err != nil {
		t.Fatalf("AD integration environment: %v", err)
	}
	return env
}

// Discover resolves the AD test environment without a testing.T.
func Discover() (*Env, error) {
	fqdn, err := hostFQDN()
	if err != nil {
		return nil, err
	}
	domain := strings.ToLower(domainOf(fqdn))
	realm := os.Getenv(RealmEnvVar)
	if realm == "" {
		if domain == "" {
			return nil, fmt.Errorf("cannot derive AD domain from host name %q; set %s", fqdn, RealmEnvVar)
		}
		realm = strings.ToUpper(domain)
	}
	if domain == "" {
		domain = strings.ToLower(realm)
	}

	keytabPath, userPath, passwordPath, err := credentialPaths()
	if err != nil {
		return nil, err
	}
	kt, err := keytab.Load(keytabPath)
	if err != nil {
		return nil, fmt.Errorf("load keytab %s: %v", keytabPath, err)
	}
	userLine, err := readTrimmedFile(userPath)
	if err != nil {
		return nil, err
	}
	user, userRealm := userLine, realm
	if at := strings.LastIndex(userLine, "@"); at > 0 {
		user, userRealm = userLine[:at], userLine[at+1:]
	}
	if user == "" {
		return nil, fmt.Errorf("user file %s does not contain a principal", userPath)
	}
	password, err := readTrimmedFile(passwordPath)
	if err != nil {
		return nil, err
	}

	cfg := config.New()
	cfg.LibDefaults.DefaultRealm = realm
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.UDPPreferenceLimit = 1
	cfg.DomainRealm[domain] = realm
	cfg.DomainRealm["."+domain] = realm

	return &Env{
		Realm:      realm,
		Domain:     domain,
		HostFQDN:   fqdn,
		User:       user,
		UserRealm:  userRealm,
		Password:   password,
		Keytab:     kt,
		KeytabPath: keytabPath,
		Config:     cfg,
	}, nil
}

// ServicePrincipal returns the keytab principal used as the test service,
// preferring host/<fqdn> in the discovered realm.
func (e *Env) ServicePrincipal() (keytab.Principal, error) {
	principals := e.Keytab.Principals()
	if len(principals) == 0 {
		return keytab.Principal{}, errors.New("keytab contains no principals")
	}
	best := 0
	for i := range principals {
		if scoreOf(principals[i], e) > scoreOf(principals[best], e) {
			best = i
		}
	}
	return principals[best], nil
}

func scoreOf(p keytab.Principal, e *Env) int {
	score := 0
	if strings.EqualFold(p.Realm, e.Realm) {
		score += 4
	}
	if len(p.Components) == 2 && strings.EqualFold(p.Components[0], "host") {
		score += 2
		if strings.EqualFold(p.Components[1], e.HostFQDN) {
			score += 1
		}
		if p.Components[0] == "host" && strings.Contains(p.Components[1], ".") {
			score += 1
		}
	}
	return score
}

// ServiceSPN returns the service principal as "service/host".
func (e *Env) ServiceSPN() (string, error) {
	p, err := e.ServicePrincipal()
	if err != nil {
		return "", err
	}
	return strings.Join(p.Components, "/"), nil
}

// MachineAccountPrincipal returns the computer account (sAMAccountName ending
// in '$') from the keytab, which is the only keytab name AD accepts as an
// AS-REQ client name.
func (e *Env) MachineAccountPrincipal() (keytab.Principal, bool) {
	for _, p := range e.Keytab.Principals() {
		if len(p.Components) == 1 && strings.HasSuffix(p.Components[0], "$") && strings.EqualFold(p.Realm, e.Realm) {
			return p, true
		}
	}
	return keytab.Principal{}, false
}

func hostFQDN() (string, error) {
	name, err := os.Hostname()
	if err != nil {
		return "", fmt.Errorf("hostname: %v", err)
	}
	if strings.Contains(name, ".") {
		return strings.TrimSuffix(name, "."), nil
	}
	if cname, err := net.LookupCNAME(name); err == nil && strings.Contains(cname, ".") {
		return strings.TrimSuffix(cname, "."), nil
	}
	if domain := resolvConfDomain(); domain != "" {
		return name + "." + domain, nil
	}
	return name, nil
}

func domainOf(fqdn string) string {
	if i := strings.Index(fqdn, "."); i >= 0 {
		return fqdn[i+1:]
	}
	return ""
}

func resolvConfDomain() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer f.Close()
	var search string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 2 {
			continue
		}
		switch fields[0] {
		case "domain":
			return strings.TrimSuffix(fields[1], ".")
		case "search":
			if search == "" {
				search = strings.TrimSuffix(fields[1], ".")
			}
		}
	}
	return search
}

func credentialPaths() (keytabPath, userPath, passwordPath string, err error) {
	dir := os.Getenv(DirEnvVar)
	if dir == "" {
		dir, err = findRepoRoot()
		if err != nil {
			return "", "", "", err
		}
	}
	keytabPath = envOr(KeytabEnvVar, filepath.Join(dir, KeytabFile))
	userPath = envOr(UserFileEnvVar, filepath.Join(dir, UserFile))
	passwordPath = envOr(PasswordFileEnvVar, filepath.Join(dir, PasswordFile))
	for _, p := range []string{keytabPath, userPath, passwordPath} {
		if _, statErr := os.Stat(p); statErr != nil {
			return "", "", "", fmt.Errorf("AD credential file %s: %v", p, statErr)
		}
	}
	return keytabPath, userPath, passwordPath, nil
}

// findRepoRoot walks up from the working directory to the first directory
// holding the keytab file, or to the git top level.
func findRepoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, KeytabFile)); err == nil {
			return dir, nil
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("repository root with %s not found above %s; set %s", KeytabFile, dir, DirEnvVar)
		}
		dir = parent
	}
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func readTrimmedFile(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(b), "\r\n"), nil
}
