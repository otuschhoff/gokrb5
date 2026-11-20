// Command gokinit obtains and caches an initial Kerberos ticket (kinit).
package main

import (
	"bufio"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/cmd/internal/krbcli"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const usageLine = "usage: gokinit [-V] [-l lifetime] [-r renewable_life] [-f | -F] [-p | -P] [-a | -A] " +
	"[-C] [-E] [-v] [-R] [-k [-i | -t keytab_file]] [-c cache_name] [-S service_name] " +
	"[-X attribute=value] [--password-stdin] [--no-request-enc-pa-rep] [principal]"

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }
func (values *stringList) Set(value string) error {
	*values = append(*values, value)
	return nil
}

type boolChoice struct {
	set   bool
	value bool
}

type choiceValue struct {
	choice *boolChoice
	value  bool
}

func (v choiceValue) String() string { return strconv.FormatBool(v.choice.value) }
func (v choiceValue) Set(string) error {
	v.choice.set = true
	v.choice.value = v.value
	return nil
}
func (v choiceValue) IsBoolFlag() bool { return true }

type initOptions struct {
	verbose              bool
	lifetime             string
	renewLifetime        string
	forwardable          boolChoice
	proxiable            boolChoice
	addresses            boolChoice
	canonicalize         bool
	enterprise           bool
	validate             bool
	renew                bool
	useKeytab            bool
	clientKeytab         bool
	keytabName           string
	cacheName            string
	service              string
	passwordStdin        bool
	disablePAReqEncPARep bool
	pkinitOptions        stringList
	principal            string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	opts, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		_, _ = fmt.Fprintf(stderr, "gokinit: %v\n", err)
		return 1
	}
	if opts.validate {
		_, _ = fmt.Fprintln(stderr, "gokinit: -v not supported")
		return 1
	}
	cfg, err := krbcli.LoadConfig()
	if err != nil {
		return fail(stderr, err, "loading Kerberos configuration")
	}
	cacheName := opts.cacheName
	if cacheName == "" {
		cacheName, err = credentials.DefaultCCacheName(cfg)
		if err != nil {
			return fail(stderr, err, "resolving credentials cache")
		}
	}
	if opts.renew {
		return renewCredentials(cacheName, cfg, opts.verbose, stdout, stderr)
	}
	return acquireCredentials(opts, cfg, cacheName, stdin, stdout, stderr)
}

func acquireCredentials(
	opts initOptions, cfg *config.Config, cacheName string, stdin io.Reader, stdout, stderr io.Writer,
) int {
	principal, err := krbcli.ResolvePrincipal(opts.principal, cacheName, opts.useKeytab, opts.enterprise, cfg)
	if err != nil {
		return fail(stderr, err, "resolving client principal")
	}
	passwordInput := bufio.NewReader(stdin)
	clientSettings, usingPKINIT, err := loadPKINITSettings(opts, cfg, passwordInput, stderr)
	if err != nil {
		return fail(stderr, err, "loading PKINIT identity")
	}
	if opts.disablePAReqEncPARep {
		clientSettings = append(clientSettings, client.DisablePAReqEncPARep(true))
	}
	cl := client.NewFromPrincipalName(types.PrincipalName{
		NameType:   principal.NameType,
		NameString: append([]string(nil), principal.Components...),
	}, principal.Realm, cfg, clientSettings...)
	if opts.useKeytab {
		kt, loadErr := loadKeytab(opts, cfg)
		if loadErr != nil {
			return fail(stderr, loadErr, "while resolving keytab")
		}
		cl.Credentials.WithKeytab(kt)
	} else if !usingPKINIT {
		password, readErr := krbcli.ReadPassword(
			"Password for "+principal.String()+": ", passwordInput, stderr, opts.passwordStdin,
		)
		if readErr != nil {
			return fail(stderr, readErr, "while reading password")
		}
		cl.Credentials.WithPassword(password)
	}
	requestOptions, err := asRequestOptions(opts, cfg)
	if err != nil {
		return fail(stderr, err, "parsing options")
	}
	if !loginWithPasswordRetry(cl, requestOptions, opts, principal, passwordInput, stderr) {
		return 1
	}
	return writeCache(cl, cacheName, opts.verbose, stdout, stderr)
}

func loginWithPasswordRetry(
	cl *client.Client, request messages.ASReqOptions, opts initOptions,
	principal keytab.Principal, stdin io.Reader, stderr io.Writer,
) bool {
	err := cl.LoginWithOptions(request)
	if err != nil && !opts.useKeytab && isPasswordExpired(err) {
		if changeErr := changeExpiredPassword(cl, principal.String(), stdin, stderr, opts.passwordStdin); changeErr != nil {
			fail(stderr, changeErr, "while changing password")
			return false
		}
		err = cl.LoginWithOptions(request)
	}
	if err != nil {
		_, _ = fmt.Fprintf(stderr, "kinit: %s while getting initial credentials\n",
			krbcli.InitialCredentialErrorText(err, principal.String(), principal.Realm))
		return false
	}
	return true
}

func parseArgs(args []string, stderr io.Writer) (initOptions, error) {
	var opts initOptions
	args = expandKeytabArgs(args)
	fs := flag.NewFlagSet("gokinit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprintln(stderr, usageLine) }
	fs.BoolVar(&opts.verbose, "V", false, "verbose output")
	fs.StringVar(&opts.lifetime, "l", "", "ticket lifetime")
	fs.StringVar(&opts.renewLifetime, "r", "", "renewable lifetime")
	fs.Var(choiceValue{&opts.forwardable, true}, "f", "forwardable")
	fs.Var(choiceValue{&opts.forwardable, false}, "F", "not forwardable")
	fs.Var(choiceValue{&opts.proxiable, true}, "p", "proxiable")
	fs.Var(choiceValue{&opts.proxiable, false}, "P", "not proxiable")
	fs.Var(choiceValue{&opts.addresses, true}, "a", "include addresses")
	fs.Var(choiceValue{&opts.addresses, false}, "A", "omit addresses")
	fs.BoolVar(&opts.canonicalize, "C", false, "canonicalize")
	fs.BoolVar(&opts.enterprise, "E", false, "enterprise principal")
	fs.BoolVar(&opts.validate, "v", false, "validate credentials")
	fs.BoolVar(&opts.renew, "R", false, "renew credentials")
	fs.BoolVar(&opts.useKeytab, "k", false, "use keytab")
	fs.BoolVar(&opts.clientKeytab, "i", false, "use default client keytab")
	fs.StringVar(&opts.keytabName, "t", "", "keytab name")
	fs.StringVar(&opts.cacheName, "c", "", "credential cache name")
	fs.StringVar(&opts.service, "S", "", "service principal")
	fs.BoolVar(&opts.passwordStdin, "password-stdin", false, "read password from standard input")
	fs.BoolVar(&opts.disablePAReqEncPARep, "no-request-enc-pa-rep", false, "omit PA-REQ-ENC-PA-REP")
	fs.Var(&opts.pkinitOptions, "X", "PKINIT attribute=value")
	if err := fs.Parse(args); err != nil {
		return opts, fmt.Errorf("parse options: %w", err)
	}
	if fs.NArg() > 1 {
		return opts, errors.New("too many arguments")
	}
	if fs.NArg() == 1 {
		opts.principal = fs.Arg(0)
	}
	return validateOptions(opts)
}

func validateOptions(opts initOptions) (initOptions, error) {
	if opts.clientKeytab || opts.keytabName != "" {
		opts.useKeytab = true
	}
	if opts.clientKeytab && opts.keytabName != "" {
		return opts, errors.New("-i and -t are mutually exclusive")
	}
	if opts.renew && (opts.useKeytab || opts.principal != "" || opts.passwordStdin || len(opts.pkinitOptions) != 0) {
		return opts, errors.New("-R cannot be combined with credential acquisition options")
	}
	return opts, nil
}

var errNilConfig = errors.New("Kerberos configuration is nil") //nolint:staticcheck // Preserve CLI error text.

func loadPKINITSettings(
	opts initOptions, cfg *config.Config, stdin io.Reader, stderr io.Writer,
) ([]func(*client.Settings), bool, error) {
	if cfg == nil {
		return nil, false, errNilConfig
	}
	identities, anchors, err := pkinitSources(opts.pkinitOptions, cfg)
	if err != nil {
		return nil, false, err
	}
	if len(identities) == 0 {
		return nil, false, nil
	}
	if len(identities) != 1 {
		return nil, false, errors.New("exactly one PKINIT identity is supported")
	}
	identity, err := loadPKINITIdentity(identities[0], stdin, stderr, opts.passwordStdin)
	if err != nil {
		return nil, false, err
	}
	if len(anchors) == 0 {
		return nil, false, errors.New("PKINIT trust anchors are required")
	}
	roots, err := loadPKINITCertPool(anchors, "anchor")
	if err != nil {
		return nil, false, err
	}
	intermediates, err := loadPKINITCertPool(cfg.LibDefaults.PKINITPool, "certificate pool")
	if err != nil {
		return nil, false, err
	}
	var policy pkinit.KDCCertificatePolicy
	policy.Roots = roots
	policy.Intermediates = intermediates
	policy.Hostname = cfg.LibDefaults.PKINITKDCHostname
	policy.EKUChecking = pkinit.KDCEKUChecking(cfg.LibDefaults.PKINITEKUChecking)
	policy.RequireRevocation = cfg.LibDefaults.PKINITRequireCRLCheck
	return []func(*client.Settings){
		client.PKINITIdentity(identity),
		client.PKINITKDCCertificatePolicy(policy),
		client.PKINITMinimumDHBits(cfg.LibDefaults.PKINITDHMinBits),
	}, true, nil
}

func pkinitSources(options stringList, cfg *config.Config) ([]string, []string, error) {
	var identities, anchors []string
	for _, option := range options {
		name, value, found := strings.Cut(option, "=")
		if !found || value == "" {
			return nil, nil, fmt.Errorf("invalid -X option %q", option)
		}
		switch name {
		case "X509_user_identity":
			identities = append(identities, value)
		case "X509_anchors":
			anchors = append(anchors, value)
		default:
			return nil, nil, fmt.Errorf("unsupported -X option %q", name)
		}
	}
	if len(identities) == 0 {
		identities = append(identities, cfg.LibDefaults.PKINITIdentities...)
	}
	if len(anchors) == 0 {
		anchors = append(anchors, cfg.LibDefaults.PKINITAnchors...)
	}
	return identities, anchors, nil
}

func loadPKINITCertPool(sources []string, kind string) (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	for _, source := range sources {
		path, err := pkinitFilePath(source)
		if err != nil {
			return nil, err
		}
		data, err := os.ReadFile(path) // #nosec G304 -- FILE: paths are explicit user configuration inputs.
		if err != nil {
			return nil, fmt.Errorf("read PKINIT %s %q: %w", kind, path, err)
		}
		if !pool.AppendCertsFromPEM(data) {
			return nil, fmt.Errorf("PKINIT %s %q contains no certificates", kind, path)
		}
	}
	return pool, nil
}

func loadPKINITIdentity(source string, stdin io.Reader, stderr io.Writer, allowStdin bool) (*pkinit.Identity, error) {
	switch {
	case strings.HasPrefix(source, "FILE:"):
		const maxIdentityPaths = 2
		paths := strings.SplitN(strings.TrimPrefix(source, "FILE:"), ",", maxIdentityPaths)
		certificate, err := os.ReadFile(paths[0])
		if err != nil {
			return nil, fmt.Errorf("read PKINIT certificate: %w", err)
		}
		key := certificate
		if len(paths) == maxIdentityPaths {
			key, err = os.ReadFile(paths[1])
			if err != nil {
				return nil, fmt.Errorf("read PKINIT private key: %w", err)
			}
		}
		block, _ := pem.Decode(key)
		if !hasLegacyPEMEncryption(block) {
			return decodePKINITPEM(certificate, key, nil)
		}
		pin, readErr := readPKINITPIN(stdin, stderr, allowStdin)
		if readErr != nil {
			return nil, readErr
		}
		return decodePKINITPEM(certificate, key, []byte(pin))
	case strings.HasPrefix(source, "PKCS12:"):
		return loadPKINITPKCS12(strings.TrimPrefix(source, "PKCS12:"), stdin, stderr, allowStdin)
	default:
		return nil, fmt.Errorf("unsupported PKINIT identity source %q", source)
	}
}

func hasLegacyPEMEncryption(block *pem.Block) bool {
	if block == nil {
		return false
	}
	// Match the legacy RFC 1423 marker only to decide whether to prompt for a PIN.
	_, encrypted := block.Headers["DEK-Info"]
	return encrypted
}

func loadPKINITPKCS12(path string, stdin io.Reader, stderr io.Writer, allowStdin bool) (*pkinit.Identity, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- PKCS12: paths are explicit user configuration inputs.
	if err != nil {
		return nil, fmt.Errorf("read PKINIT PKCS#12 identity: %w", err)
	}
	identity, err := pkinit.FromPKCS12(data, "")
	if err == nil {
		return identity, nil
	}
	pin, readErr := readPKINITPIN(stdin, stderr, allowStdin)
	if readErr != nil {
		return nil, readErr
	}
	identity, err = pkinit.FromPKCS12(data, pin)
	if err != nil {
		return nil, fmt.Errorf("decode PKINIT PKCS#12 identity: %w", err)
	}
	return identity, nil
}

func decodePKINITPEM(certificate, key, password []byte) (*pkinit.Identity, error) {
	identity, err := pkinit.FromPEM(certificate, key, password)
	if err != nil {
		return nil, fmt.Errorf("decode PKINIT PEM identity: %w", err)
	}
	return identity, nil
}

func readPKINITPIN(stdin io.Reader, stderr io.Writer, allowStdin bool) (string, error) {
	pin, err := krbcli.ReadPassword("PIN for PKINIT identity: ", stdin, stderr, allowStdin)
	if err != nil {
		return "", fmt.Errorf("read PKINIT identity PIN: %w", err)
	}
	return pin, nil
}

func pkinitFilePath(source string) (string, error) {
	if !strings.HasPrefix(source, "FILE:") || len(source) == len("FILE:") {
		return "", fmt.Errorf("unsupported PKINIT anchor source %q", source)
	}
	return strings.TrimPrefix(source, "FILE:"), nil
}

func expandKeytabArgs(args []string) []string {
	expanded := make([]string, 0, len(args)+1)
	for _, arg := range args {
		switch arg {
		case "-kt":
			expanded = append(expanded, "-k", "-t")
		case "-ki":
			expanded = append(expanded, "-k", "-i")
		default:
			expanded = append(expanded, arg)
		}
	}
	return expanded
}

func asRequestOptions(opts initOptions, cfg *config.Config) (messages.ASReqOptions, error) {
	var result messages.ASReqOptions
	if cfg == nil {
		return result, errNilConfig
	}
	if err := setRequestLifetimes(&result, opts); err != nil {
		return result, err
	}
	if opts.forwardable.set {
		result.Forwardable = &opts.forwardable.value
	}
	if opts.proxiable.set {
		result.Proxiable = &opts.proxiable.value
	}
	addresses, err := requestAddresses(opts.addresses, cfg)
	if err != nil {
		return result, err
	}
	result.Addresses = addresses
	if opts.canonicalize {
		result.Canonicalize = &opts.canonicalize
	}
	if opts.enterprise {
		result.Enterprise = &opts.enterprise
	}
	if opts.service != "" {
		name, err := requestServicePrincipal(opts.service)
		if err != nil {
			return result, err
		}
		result.ServicePrincipal = &name
	}
	return result, nil
}

func setRequestLifetimes(request *messages.ASReqOptions, opts initOptions) error {
	if opts.lifetime != "" {
		value, err := parseLifetime(opts.lifetime, "ticket")
		if err != nil {
			return err
		}
		request.Lifetime = &value
	}
	if opts.renewLifetime != "" {
		value, err := parseLifetime(opts.renewLifetime, "renewable")
		if err != nil {
			return err
		}
		request.RenewLifetime = &value
	}
	return nil
}

func parseLifetime(value, kind string) (time.Duration, error) {
	lifetime, err := krbcli.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s lifetime %q", kind, value)
	}
	return lifetime, nil
}

func requestAddresses(choice boolChoice, cfg *config.Config) ([]types.HostAddress, error) {
	if !choice.set {
		return nil, nil
	}
	if !choice.value {
		return []types.HostAddress{}, nil
	}
	addresses, err := types.LocalHostAddresses()
	if err != nil {
		return nil, fmt.Errorf("collect local ticket addresses: %w", err)
	}
	return append(addresses, types.HostAddressesFromNetIPs(cfg.LibDefaults.ExtraAddresses)...), nil
}

func requestServicePrincipal(value string) (types.PrincipalName, error) {
	service, err := keytab.ParsePrincipal(value)
	if err != nil {
		return types.PrincipalName{}, fmt.Errorf("invalid service principal: %w", err)
	}
	return types.PrincipalName{
		NameType:   service.NameType,
		NameString: append([]string(nil), service.Components...),
	}, nil
}

func loadKeytab(opts initOptions, cfg *config.Config) (*keytab.Keytab, error) {
	if opts.keytabName != "" {
		kt, err := keytab.Load(opts.keytabName)
		if err != nil {
			return kt, fmt.Errorf("load explicit keytab: %w", err)
		}
		return kt, nil
	}
	if opts.clientKeytab {
		kt, err := keytab.LoadDefaultClient(cfg)
		if err != nil {
			return kt, fmt.Errorf("load default client keytab: %w", err)
		}
		return kt, nil
	}
	kt, err := keytab.LoadDefault(cfg)
	if err != nil {
		return kt, fmt.Errorf("load default keytab: %w", err)
	}
	return kt, nil
}

func isPasswordExpired(err error) bool {
	kdcErr, ok := krbcli.KDCError(err)
	return ok && kdcErr.ErrorCode == errorcode.KDC_ERR_KEY_EXPIRED
}

func changeExpiredPassword(
	cl *client.Client, principal string, stdin io.Reader, stderr io.Writer, passwordStdin bool,
) error {
	if _, err := fmt.Fprintln(stderr, "Password expired.  You must change it now."); err != nil {
		return fmt.Errorf("write password expiration notice: %w", err)
	}
	first, err := krbcli.ReadPassword("Enter new password: ", stdin, stderr, passwordStdin)
	if err != nil {
		return fmt.Errorf("read new password: %w", err)
	}
	second, err := krbcli.ReadPassword("Enter it again: ", stdin, stderr, passwordStdin)
	if err != nil {
		return fmt.Errorf("read password confirmation: %w", err)
	}
	if first != second {
		return errors.New("Password mismatch") //nolint:staticcheck // Preserve CLI error text.
	}
	ok, err := cl.ChangePasswd(first)
	if err != nil {
		return fmt.Errorf("change expired password: %w", err)
	}
	if !ok {
		return fmt.Errorf("password change failed for %s", principal)
	}
	return nil
}

func writeCache(cl *client.Client, cacheName string, verbose bool, stdout, stderr io.Writer) int {
	cache, err := cl.CCache()
	if err != nil {
		return fail(stderr, err, "while creating credentials cache")
	}
	if err := cache.WriteFile(cacheName); err != nil {
		return fail(stderr, err, "while storing credentials")
	}
	if verbose {
		if _, err := fmt.Fprintf(stdout, "Using default cache: %s\n", displayCacheName(cacheName)); err != nil {
			return fail(stderr, err, "while reporting cached credentials")
		}
		if _, err := fmt.Fprintf(stdout, "Using principal: %s@%s\n",
			cl.Credentials.CName().PrincipalNameString(), cl.Credentials.Domain()); err != nil {
			return fail(stderr, err, "while reporting cached credentials")
		}
		if _, err := fmt.Fprintln(stdout, "Authenticated to Kerberos v5"); err != nil {
			return fail(stderr, err, "while reporting cached credentials")
		}
	}
	return 0
}

func renewCredentials(cacheName string, cfg *config.Config, verbose bool, stdout, stderr io.Writer) int {
	cache, err := credentials.LoadCCache(cacheName)
	if err != nil {
		return fail(stderr, err, "while renewing credentials")
	}
	cl, err := client.NewFromCCache(cache, cfg)
	if err != nil {
		return fail(stderr, err, "while renewing credentials")
	}
	if err := cl.Renew(); err != nil {
		return fail(stderr, err, "while renewing credentials")
	}
	return writeCache(cl, cacheName, verbose, stdout, stderr)
}

func displayCacheName(name string) string {
	prefix, _, _ := strings.Cut(name, "/")
	if strings.Contains(prefix, ":") {
		return name
	}
	return "FILE:" + name
}

func fail(stderr io.Writer, err error, context string) int {
	_, _ = fmt.Fprintf(stderr, "kinit: %s %s\n", krbcli.ErrorText(err), context)
	return 1
}
