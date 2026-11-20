// Package config implements KRB5 client and service configuration as described at
// https://web.mit.edu/kerberos/krb5-latest/doc/admin/conf_files/krb5_conf.html.
package config

import (
	"bufio"
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

	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
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

const (
	defaultCCacheType         = 4
	defaultClockskew          = 5 * time.Minute
	defaultTicketLifetime     = 24 * time.Hour
	defaultUDPPreferenceLimit = 1465
)

// New creates a new config struct instance.
func New() *Config {
	d := make(DomainRealm)
	return &Config{
		LibDefaults: newLibDefaults(),
		Realms:      nil, // Preserve the JSON null when no realms are configured.
		DomainRealm: d,
	}
}

// NewFromString parses Kerberos configuration text.
// It returns warnings and fatal errors as described by [NewFromScanner].
func NewFromString(s string) (*Config, error) {
	reader := strings.NewReader(s)
	return NewFromReader(reader)
}

// NewFromReader parses Kerberos configuration from r without closing it.
// It returns warnings and fatal errors as described by [NewFromScanner].
func NewFromReader(r io.Reader) (*Config, error) {
	scanner := bufio.NewScanner(r)
	return NewFromScanner(scanner)
}

// NewFromScanner parses Kerberos configuration from a scanner that yields one
// line per token. To configure the scanner's buffer and token size limit,
// call [bufio.Scanner.Buffer] before passing the scanner in.
//
// It returns a config and a nil error if parsing succeeds
// without warnings. If parsing succeeds with [UnsupportedDirective] warnings,
// it returns the config and the last warning. A scanner failure or fatal
// parse error returns a nil config.
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
	// PreferredPreauthTypes defaults to 17, 16, 15, 14, which forces libkrb5
	// to attempt PKINIT if it is supported.
	PreferredPreauthTypes []int
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
	// UDPPreferenceLimit of 1 means to always use TCP. MIT krb5 defaults to
	// 1465 and does not allow values above 32700.
	UDPPreferenceLimit int
	VerifyAPReqNofail  bool // default false
}

// Create a new LibDefaults struct.
func newLibDefaults() LibDefaults {
	var hdir string
	usr, _ := user.Current()
	if usr != nil {
		hdir = usr.HomeDir
	}
	optionBytes := []byte{0x00, 0x00, 0x00, 0x10}
	opts := asn1.BitString{
		Bytes:     optionBytes,
		BitLength: len(optionBytes) * bitsPerByte,
	}
	l := LibDefaults{
		CCacheType:              defaultCCacheType,
		Clockskew:               defaultClockskew,
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
		SafeChecksumType:        int(chksumtype.RSA_MD5_DES),
		TicketLifetime:          defaultTicketLifetime,
		UDPPreferenceLimit:      defaultUDPPreferenceLimit,
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

type realmLineState struct {
	depth     int
	isIgnored bool
	hasV4     bool
}

type realmFinalValues struct {
	adminServer   bool
	kdc           bool
	kpasswdServer bool
	masterKDC     bool
}

// parseLines applies directives in order and returns a warning for legacy v4 settings.
func (r *Realm) parseLines(name string, lines []string) error {
	r.Realm = name
	var state realmLineState
	var final realmFinalValues
	for _, line := range lines {
		line = state.directiveLine(line)
		if line == "" {
			continue
		}
		skip, err := state.skipDirective(line)
		if err != nil {
			return err
		}
		if !skip {
			applyRealmDirective(r, line, &final)
		}
	}
	defaultRealmKPasswdServers(r)
	if state.hasV4 {
		return UnsupportedDirective{text: "v4 configurations are not supported"}
	}
	return nil
}

func (s *realmLineState) directiveLine(line string) string {
	// Legacy blocks check the raw line for braces before stripping comments.
	inIgnoredBlock := s.isIgnored && s.depth > 0
	if inIgnoredBlock && !strings.ContainsAny(line, "{}") {
		return ""
	}
	if idx := strings.IndexAny(line, "#;"); idx != -1 {
		line = line[:idx]
	}
	return strings.TrimSpace(line)
}

func (s *realmLineState) skipDirective(line string) (bool, error) {
	closesBlock := strings.Contains(line, "}")
	if !closesBlock && !strings.Contains(line, "=") {
		return false, InvalidErrorf("realms section line (%s)", line)
	}
	if strings.Contains(line, "v4_") {
		s.isIgnored = true
		s.hasV4 = true
	}
	if strings.Contains(line, "{") {
		s.depth++
		if s.isIgnored {
			return true, nil
		}
	}
	if !closesBlock {
		return false, nil
	}
	return s.closeBlock()
}

func (s *realmLineState) closeBlock() (bool, error) {
	s.depth--
	if s.depth < 0 {
		return false, InvalidErrorf("unpaired curly brackets")
	}
	if !s.isIgnored {
		return false, nil
	}
	if s.depth == 0 {
		s.isIgnored = false
	}
	return true, nil
}

func applyRealmDirective(r *Realm, line string, final *realmFinalValues) {
	parts := strings.Split(line, "=")
	key := strings.TrimSpace(strings.ToLower(parts[0]))
	value := strings.TrimSpace(parts[1])
	switch key {
	case "admin_server":
		appendUntilFinal(&r.AdminServer, value, &final.adminServer)
	case "default_domain":
		r.DefaultDomain = value
	case "kdc":
		appendUntilFinal(&r.KDC, realmKDCWithDefaultPort(value), &final.kdc)
	case "kpasswd_server":
		appendUntilFinal(&r.KPasswdServer, value, &final.kpasswdServer)
	case "master_kdc":
		appendUntilFinal(&r.MasterKDC, value, &final.masterKDC)
	}
}

func realmKDCWithDefaultPort(value string) string {
	if strings.Contains(value, ":") {
		return value
	}
	if host, isFinal := strings.CutSuffix(value, "*"); isFinal {
		return strings.TrimSpace(host) + ":88*"
	}
	return strings.TrimSpace(value) + ":88"
}

func defaultRealmKPasswdServers(r *Realm) {
	if len(r.KPasswdServer) != 0 {
		return
	}
	for _, server := range r.AdminServer {
		host, _, _ := strings.Cut(server, ":")
		r.KPasswdServer = append(r.KPasswdServer, host+":464")
	}
}

type realmBlock struct {
	name  string
	start int
	depth int
}

// advance reports whether the line closes the outer block. Each line contributes
// at most one opening and one closing brace, in that order.
func (b *realmBlock) advance(i int, line string) (bool, error) {
	if idx := strings.IndexAny(line, "#;"); idx != -1 {
		line = line[:idx]
	}
	line = strings.TrimSpace(line)
	if strings.Contains(line, "{") {
		b.depth++
		name, _, ok := strings.Cut(line, "=")
		if !ok {
			return false, fmt.Errorf("realm configuration line invalid: %s", line)
		}
		if b.depth == 1 {
			b.start = i
			b.name = strings.TrimSpace(name)
		}
	}
	if !strings.Contains(line, "}") {
		return false, nil
	}
	if b.depth == 0 {
		return false, errors.New("invalid Realms section in configuration")
	}
	b.depth--
	return b.depth == 0, nil
}

// parseRealms parses completed realm blocks in order and retains the last warning.
func parseRealms(lines []string) ([]Realm, error) {
	var realms []Realm
	var warning error
	var block realmBlock
	for i, line := range lines {
		closed, err := block.advance(i, line)
		if err != nil {
			return nil, err
		}
		if !closed {
			continue
		}
		var r Realm
		if err := r.parseLines(block.name, lines[block.start+1:i]); err != nil {
			if _, ok := errors.AsType[UnsupportedDirective](err); !ok {
				return realms, err
			}
			warning = err
		}
		realms = append(realms, r)
	}
	return realms, warning
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

// ResolveRealm looks up domainName in the [DomainRealm] map. It removes one
// trailing dot before checking for an exact match, then checks dot-prefixed
// domain suffixes from most to least specific. Matching is case-sensitive.
// If no mapping matches, ResolveRealm returns "" rather than the default realm.
func (c *Config) ResolveRealm(domainName string) string {
	domainName = strings.TrimSuffix(domainName, ".")

	if r, ok := c.DomainRealm[domainName]; ok {
		return r
	}

	for i, ch := range domainName {
		if ch != '.' {
			continue
		}
		if r, ok := c.DomainRealm[domainName[i:]]; ok {
			return r
		}
	}
	return ""
}

// Load parses Kerberos configuration from cfgPath and closes the file.
// It returns the config, if any, from [NewFromScanner]. A file-open error
// returns a nil config. Parse warnings and errors are joined with any
// file-close error, so use [errors.AsType] to check for [UnsupportedDirective]
// rather than a direct type assertion. A close error can accompany a non-nil
// config even if parsing succeeded without a warning.
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
