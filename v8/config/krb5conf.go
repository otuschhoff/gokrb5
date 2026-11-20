// Package config implements KRB5 client and service configuration as described at https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html
package config

import (
	"bufio"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/user"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

// Config represents the KRB5 configuration.
type Config struct {
	LibDefaults LibDefaults
	Realms      []Realm
	DomainRealm DomainRealm
	// CaPaths
	// AppDefaults
	// Plugins
}

// WeakETypeList is a list of encryption types that have been deemed weak.
const WeakETypeList = "des-cbc-crc des-cbc-md4 des-cbc-md5 des-cbc-raw des3-cbc-raw des-hmac-sha1 " +
	"arcfour-hmac-exp rc4-hmac-exp arcfour-hmac-md5-exp des " +
	"des3-cbc-md5 des3-cbc-sha1 des3-cbc-sha1-kd arcfour-hmac rc4-hmac arcfour-hmac-md5"

const defaultEnctypes = "aes256-cts-hmac-sha1-96 aes128-cts-hmac-sha1-96"

// New creates a new config struct instance.
func New() *Config {
	d := make(DomainRealm)
	return &Config{
		LibDefaults: newLibDefaults(),
		DomainRealm: d,
	}
}

// LibDefaults represents the [libdefaults] section of the configuration.
type LibDefaults struct {
	ADSite          string
	AllowWeakCrypto bool // allows explicitly configured legacy enctypes; default false
	// ap_req_checksum_type int //unlikely to support this
	Canonicalize            bool          // default false
	CCacheType              int           // default is 4. unlikely to implement older
	Clockskew               time.Duration // max allowed skew in seconds, default 300
	DefaultCCacheName       string        // default FILE:/tmp/krb5cc_%{uid}
	DefaultClientKeytabName string        // default is build-time configurable in MIT krb5
	DefaultKeytabName       string        // default /etc/krb5.keytab
	DefaultRealm            string
	DefaultTGSEnctypes      []string // default AES256 then AES128 (RFC 3962)
	DefaultTktEnctypes      []string // default AES256 then AES128 (RFC 3962)
	DefaultTGSEnctypeIDs    []int32
	DefaultTktEnctypeIDs    []int32
	DNSCanonicalizeHostname bool // default true
	DNSLookupKDC            bool // default false
	DNSLookupRealm          bool
	ExtraAddresses          []net.IP       // Not implementing yet
	Forwardable             bool           // default false
	IgnoreAcceptorHostname  bool           // default false
	K5LoginAuthoritative    bool           // default false
	K5LoginDirectory        string         // default user's home directory. Must be owned by the user or root
	KDCDefaultOptions       asn1.BitString // default 0x00000010 (KDC_OPT_RENEWABLE_OK)
	KDCTimeSync             int            // default 1
	// kdc_req_checksum_type int //unlikely to implement as for very old KDCs
	NoAddresses         bool     // default true
	PermittedEnctypes   []string // default AES256 then AES128 (RFC 3962)
	PermittedEnctypeIDs []int32
	// plugin_base_dir string //not supporting plugins
	PreferredPreauthTypes []int         // default “17, 16, 15, 14”, which forces libkrb5 to attempt to use PKINIT if it is supported
	PKINITAnchors         []string      `json:"-"`
	PKINITIdentities      []string      `json:"-"`
	PKINITKDCHostname     string        `json:"-"`
	PKINITEKUChecking     string        `json:"-"`
	PKINITRequireCRLCheck bool          `json:"-"`
	PKINITDHMinBits       int           `json:"-"`
	PKINITPool            []string      `json:"-"`
	Proxiable             bool          // default false
	RDNS                  bool          // default true
	RealmTryDomains       int           // default -1
	RequestPAC            bool          // default true
	RenewLifetime         time.Duration // default 0
	SafeChecksumType      int           // default 8
	TicketLifetime        time.Duration // default 1 day
	UDPPreferenceLimit    int           // 1 means to always use tcp. MIT krb5 has a default value of 1465, and it prevents user setting more than 32700.
	VerifyAPReqNofail     bool          // default false
}

// Create a new LibDefaults struct.
func newLibDefaults() LibDefaults {
	var hdir string
	usr, _ := user.Current()
	if usr != nil {
		hdir = usr.HomeDir
	}
	opts := asn1.BitString{}
	opts.Bytes, _ = hex.DecodeString("00000010")
	opts.BitLength = len(opts.Bytes) * 8
	l := LibDefaults{
		CCacheType:              4,
		Clockskew:               time.Duration(300) * time.Second,
		DefaultCCacheName:       "FILE:/tmp/krb5cc_%{uid}",
		DefaultClientKeytabName: "FILE:/var/kerberos/krb5/user/%{euid}/client.keytab",
		DefaultKeytabName:       "/etc/krb5.keytab",
		DefaultTGSEnctypes:      strings.Fields(defaultEnctypes),
		DefaultTktEnctypes:      strings.Fields(defaultEnctypes),
		DNSCanonicalizeHostname: true,
		K5LoginDirectory:        hdir,
		KDCDefaultOptions:       opts,
		KDCTimeSync:             1,
		NoAddresses:             true,
		PermittedEnctypes:       strings.Fields(defaultEnctypes),
		PKINITEKUChecking:       "kdc",
		PKINITDHMinBits:         2048,
		RDNS:                    true,
		RealmTryDomains:         -1,
		RequestPAC:              true,
		SafeChecksumType:        8,
		TicketLifetime:          time.Duration(24) * time.Hour,
		UDPPreferenceLimit:      1465,
		PreferredPreauthTypes:   []int{17, 16, 15, 14},
	}
	l.DefaultTGSEnctypeIDs = parseETypes(l.DefaultTGSEnctypes, l.AllowWeakCrypto)
	l.DefaultTktEnctypeIDs = parseETypes(l.DefaultTktEnctypes, l.AllowWeakCrypto)
	l.PermittedEnctypeIDs = parseETypes(l.PermittedEnctypes, l.AllowWeakCrypto)
	return l
}

// Parse the lines of the [libdefaults] section of the configuration into the LibDefaults struct.
func (l *LibDefaults) parseLines(lines []string) error {
	for _, line := range lines {
		// Remove comments after the values
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(line, "=") {
			return InvalidErrorf("libdefaults section line (%s)", line)
		}

		p := strings.Split(line, "=")
		key := strings.TrimSpace(strings.ToLower(p[0]))
		if err := l.parseOption(key, p[1], line); err != nil {
			return err
		}
	}
	l.DefaultTGSEnctypeIDs = parseETypes(l.DefaultTGSEnctypes, l.AllowWeakCrypto)
	l.DefaultTktEnctypeIDs = parseETypes(l.DefaultTktEnctypes, l.AllowWeakCrypto)
	l.PermittedEnctypeIDs = parseETypes(l.PermittedEnctypes, l.AllowWeakCrypto)
	return nil
}

// Realm represents an entry in the [realms] section of the configuration.
type Realm struct {
	Realm       string
	AdminServer []string
	// auth_to_local //Not implementing for now
	// auth_to_local_names //Not implementing for now
	DefaultDomain string
	KDC           []string
	KPasswdServer []string // default admin_server:464
	MasterKDC     []string
}

// Parse the lines of a [realms] entry into the Realm struct.
func (r *Realm) parseLines(name string, lines []string) error {
	var err error
	r.Realm = name
	var adminServerFinal bool
	var KDCFinal bool
	var kpasswdServerFinal bool
	var masterKDCFinal bool
	var ignore bool
	var c int // counts the depth of blocks within brackets { }
	for _, line := range lines {
		if ignore && c > 0 && !strings.Contains(line, "{") && !strings.Contains(line, "}") {
			continue
		}
		// Remove comments after the values
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = line[:idx]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if !strings.Contains(line, "=") && !strings.Contains(line, "}") {
			return InvalidErrorf("realms section line (%s)", line)
		}
		if strings.Contains(line, "v4_") {
			ignore = true
			err = UnsupportedDirective{"v4 configurations are not supported"}
		}
		if strings.Contains(line, "{") {
			c++
			if ignore {
				continue
			}
		}
		if strings.Contains(line, "}") {
			c--
			if c < 0 {
				return InvalidErrorf("unpaired curly brackets")
			}
			if ignore {
				if c < 1 {
					c = 0
					ignore = false
				}
				continue
			}
		}

		p := strings.Split(line, "=")
		key := strings.TrimSpace(strings.ToLower(p[0]))
		v := strings.TrimSpace(p[1])
		switch key {
		case "admin_server":
			appendUntilFinal(&r.AdminServer, v, &adminServerFinal)
		case "default_domain":
			r.DefaultDomain = v
		case "kdc":
			if !strings.Contains(v, ":") {
				// No port number specified default to 88
				if strings.HasSuffix(v, `*`) {
					v = strings.TrimSpace(strings.TrimSuffix(v, `*`)) + ":88*"
				} else {
					v = strings.TrimSpace(v) + ":88"
				}
			}
			appendUntilFinal(&r.KDC, v, &KDCFinal)
		case "kpasswd_server":
			appendUntilFinal(&r.KPasswdServer, v, &kpasswdServerFinal)
		case "master_kdc":
			appendUntilFinal(&r.MasterKDC, v, &masterKDCFinal)
		}
	}
	// default for Kpasswd_server = admin_server:464
	if len(r.KPasswdServer) < 1 {
		for _, a := range r.AdminServer {
			s := strings.Split(a, ":")
			r.KPasswdServer = append(r.KPasswdServer, s[0]+":464")
		}
	}
	return err
}

// Parse the lines of the [realms] section of the configuration into an slice of Realm structs.
func parseRealms(lines []string) ([]Realm, error) {
	var realms []Realm
	var err error
	var name string
	var start int
	var c int
	for i, l := range lines {
		// Remove comments after the values
		if idx := strings.IndexAny(l, "#;"); idx != -1 {
			l = l[:idx]
		}
		l = strings.TrimSpace(l)
		if l == "" {
			continue
		}
		// if strings.Contains(l, "v4_") {
		//	return nil, errors.New("v4 configurations are not supported in Realms section")
		//}
		if strings.Contains(l, "{") {
			c++
			if !strings.Contains(l, "=") {
				return nil, fmt.Errorf("realm configuration line invalid: %s", l)
			}
			if c == 1 {
				start = i
				p := strings.Split(l, "=")
				name = strings.TrimSpace(p[0])
			}
		}
		if strings.Contains(l, "}") {
			if c < 1 {
				// but not started a block!!!
				return nil, errors.New("invalid Realms section in configuration")
			}
			c--
			if c == 0 {
				var r Realm
				e := r.parseLines(name, lines[start+1:i])
				if e != nil {
					var ud UnsupportedDirective
					if !errors.As(e, &ud) {
						err = e
						return realms, err
					}
					err = e
				}
				realms = append(realms, r)
			}
		}
	}
	return realms, err
}

// DomainRealm maps the domains to realms representing the [domain_realm] section of the configuration.
type DomainRealm map[string]string

// Parse the lines of the [domain_realm] section of the configuration and add to the mapping.
func (d *DomainRealm) parseLines(lines []string) error {
	for _, line := range lines {
		// Remove comments after the values
		if idx := strings.IndexAny(line, "#;"); idx != -1 {
			line = line[:idx]
		}
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.Contains(line, "=") {
			return InvalidErrorf("realm line (%s)", line)
		}
		p := strings.Split(line, "=")
		domain := strings.TrimSpace(strings.ToLower(p[0]))
		realm := strings.TrimSpace(p[1])
		d.addMapping(domain, realm)
	}
	return nil
}

// Add a domain to realm mapping.
func (d *DomainRealm) addMapping(domain, realm string) {
	(*d)[domain] = realm
}

// ResolveRealm resolves the kerberos realm for the specified domain name from the domain to realm mapping.
// The most specific mapping is returned.
func (c *Config) ResolveRealm(domainName string) string {
	domainName = strings.TrimSuffix(domainName, ".")

	// Try to match the entire hostname first
	if r, ok := c.DomainRealm[domainName]; ok {
		return r
	}

	// Try to match all DNS domain parts
	periods := strings.Count(domainName, ".") + 1
	for i := 2; i <= periods; i++ {
		z := strings.SplitN(domainName, ".", i)
		if r, ok := c.DomainRealm["."+z[len(z)-1]]; ok {
			return r
		}
	}
	return ""
}

// Load the KRB5 configuration from the specified file path.
func Load(cfgPath string) (*Config, error) {
	fh, err := os.Open(cfgPath) // #nosec G304 -- path is an explicit API/test/config input, not request-derived traversal.
	if err != nil {
		return nil, errors.New("configuration file could not be opened: " + cfgPath + " " + err.Error())
	}
	cfg, parseErr := NewFromScanner(bufio.NewScanner(fh))
	closeErr := fh.Close()
	if err := errors.Join(parseErr, closeErr); err != nil {
		return cfg, err
	}
	return cfg, nil
}

// NewFromString creates a new Config struct from a string.
func NewFromString(s string) (*Config, error) {
	reader := strings.NewReader(s)
	return NewFromReader(reader)
}

// NewFromReader creates a new Config struct from an io.Reader.
func NewFromReader(r io.Reader) (*Config, error) {
	scanner := bufio.NewScanner(r)
	return NewFromScanner(scanner)
}

// NewFromScanner creates a new Config struct from a bufio.Scanner.
func NewFromScanner(scanner *bufio.Scanner) (*Config, error) {
	c := New()
	scanned := scanConfigSections(scanner)
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading Kerberos configuration: %w", err)
	}

	var warning error
	for i, start := range scanned.starts {
		end := len(scanned.lines)
		if i+1 < len(scanned.starts) {
			end = scanned.starts[i+1]
		}
		sectionWarning, err := parseConfigSection(c, scanned.names[start], scanned.lines[start:end])
		if err != nil {
			return nil, err
		}
		if sectionWarning != nil {
			warning = sectionWarning
		}
	}
	return c, warning
}

const realmsSectionName = "realms"

type scannedConfigSections struct {
	lines  []string
	starts []int
	names  map[int]string
}

func scanConfigSections(scanner *bufio.Scanner) scannedConfigSections {
	scanned := scannedConfigSections{
		lines:  []string{},
		starts: []int{},
		names:  make(map[int]string),
	}
	commentLine := regexp.MustCompile(`^\s*(#|;|\n)`)
	libdefaultsSection := regexp.MustCompile(`^\s*\[libdefaults\]\s*`)
	realmsSection := regexp.MustCompile(`^\s*\[realms\]\s*`)
	domainRealmSection := regexp.MustCompile(`^\s*\[domain_realm\]\s*`)
	unknownSection := regexp.MustCompile(`^\s*\[.*\]\s*`)
	for scanner.Scan() {
		line := scanner.Text()
		var section string
		switch {
		case commentLine.MatchString(line):
			continue
		case libdefaultsSection.MatchString(line):
			section = "libdefaults"
		case realmsSection.MatchString(line):
			section = realmsSectionName
		case domainRealmSection.MatchString(line):
			section = "domain_realm"
		case unknownSection.MatchString(line):
			section = "unknown_section"
		default:
			scanned.lines = append(scanned.lines, line)
			continue
		}
		// Headers at the same offset use the last header's name.
		start := len(scanned.lines)
		scanned.names[start] = section
		scanned.starts = append(scanned.starts, start)
	}
	return scanned
}

// parseConfigSection returns an unsupported-directive warning separately from a fatal error.
func parseConfigSection(c *Config, section string, lines []string) (error, error) {
	var err error
	var realms []Realm
	switch section {
	case "libdefaults":
		err = c.LibDefaults.parseLines(lines)
	case realmsSectionName:
		realms, err = parseRealms(lines)
	case "domain_realm":
		err = c.DomainRealm.parseLines(lines)
		section = "domaain_realm" // Preserve the existing diagnostic spelling.
	}
	if err != nil {
		if _, ok := errors.AsType[UnsupportedDirective](err); !ok {
			return nil, fmt.Errorf("error processing %s section: %w", section, err)
		}
	}
	if section == realmsSectionName {
		c.Realms = realms
	}
	return err, nil
}

// parseETypes resolves supported names before applying policy so aliases cannot bypass it.
func parseETypes(names []string, allowWeak bool) []int32 {
	var eti []int32
	for _, name := range names {
		id := etypeID.EtypeSupported(name)
		// These are the only supported enctypes deprecated by RFC 8429.
		weak := id == etypeID.RC4_HMAC || id == etypeID.DES3_CBC_SHA1_KD
		if id == 0 || (weak && !allowWeak) {
			continue
		}
		eti = append(eti, id)
	}
	return eti
}

// parseDuration reads the duration formats accepted by krb5.conf.
func parseDuration(s string) (time.Duration, error) {
	s = strings.ReplaceAll(strings.TrimSpace(s), " ", "")

	if days, suffix, ok := strings.Cut(s, "d"); ok {
		return parseDayDuration(days, suffix)
	}

	// handle Nm[Ns]
	d, err := time.ParseDuration(s)
	if err == nil {
		return d, nil
	}

	// handle N
	v, err := strconv.ParseUint(s, 10, 32)
	if err == nil && v > 0 {
		return time.Duration(v) * time.Second, nil
	}

	if strings.Contains(s, ":") {
		return parseColonDuration(s)
	}
	return 0, errors.New("invalid time duration value")
}

func parseDayDuration(days, suffix string) (time.Duration, error) {
	const hoursPerDay = 24
	n, err := strconv.ParseUint(days, 10, 32)
	if err != nil {
		return 0, errors.New("invalid time duration")
	}
	d := time.Duration(n*hoursPerDay) * time.Hour
	if suffix == "" {
		return d, nil
	}
	extra, err := time.ParseDuration(suffix)
	if err != nil {
		return 0, errors.New("invalid time duration")
	}
	return d + extra, nil
}

func parseColonDuration(s string) (time.Duration, error) {
	const (
		hoursAndMinutes = 2
		withSeconds     = 3
	)
	parts := strings.Split(s, ":")
	if len(parts) != hoursAndMinutes && len(parts) != withSeconds {
		return 0, errors.New("invalid time duration value")
	}
	var values [withSeconds]int64
	for i, part := range parts {
		n, err := strconv.ParseInt(part, 10, 16)
		if err != nil {
			return 0, errors.New("invalid time duration value")
		}
		values[i] = n
	}
	return time.Duration(values[0])*time.Hour +
		time.Duration(values[1])*time.Minute +
		time.Duration(values[2])*time.Second, nil
}

// Parse possible boolean values to golang bool.
func parseBoolean(s string) (bool, error) {
	s = strings.TrimSpace(s)
	v, err := strconv.ParseBool(s)
	if err == nil {
		return v, nil
	}
	switch strings.ToLower(s) {
	case "yes":
		return true, nil
	case "y":
		return true, nil
	case "no":
		return false, nil
	case "n":
		return false, nil
	}
	return false, errors.New("invalid boolean value")
}

// Parse array of strings but stop if an asterisk is placed at the end of a line.
func appendUntilFinal(s *[]string, value string, final *bool) {
	if *final {
		return
	}
	if last := len(value) - 1; last >= 0 && value[last] == '*' {
		*final = true
		value = value[:len(value)-1]
	}
	*s = append(*s, value)
}

// JSON encodes the configuration without its PKINIT settings.
func (c *Config) JSON() (string, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", fmt.Errorf("encode Kerberos configuration JSON: %w", err)
	}
	return string(b), nil
}
