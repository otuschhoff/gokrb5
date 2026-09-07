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

const usageLine = "usage: gokinit [-V] [-l lifetime] [-r renewable_life] [-f | -F] [-p | -P] [-a | -A] [-C] [-E] [-v] [-R] [-k [-i | -t keytab_file]] [-c cache_name] [-S service_name] [-X attribute=value] [--password-stdin] [--no-request-enc-pa-rep] [principal]"

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
		} else {
			fmt.Fprintf(stderr, "gokinit: %v\n", err)
		}
		return 1
	}
	if opts.validate {
		fmt.Fprintln(stderr, "gokinit: -v not supported")
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
		password, readErr := krbcli.ReadPassword("Password for "+principal.String()+": ", passwordInput, stderr, opts.passwordStdin)
		if readErr != nil {
			return fail(stderr, readErr, "while reading password")
		}
		cl.Credentials.WithPassword(password)
	}
	requestOptions, err := asRequestOptions(opts, cfg)
	if err != nil {
		return fail(stderr, err, "parsing options")
	}
	if err := cl.LoginWithOptions(requestOptions); err != nil {
		if !opts.useKeytab && isPasswordExpired(err) {
			if changeErr := changeExpiredPassword(cl, principal.String(), passwordInput, stderr, opts.passwordStdin); changeErr != nil {
				return fail(stderr, changeErr, "while changing password")
			}
			if err = cl.LoginWithOptions(requestOptions); err == nil {
				return writeCache(cl, cacheName, opts.verbose, stdout, stderr)
			}
		}
		fmt.Fprintf(stderr, "kinit: %s while getting initial credentials\n", krbcli.InitialCredentialErrorText(err, principal.String(), principal.Realm))
		return 1
	}
	return writeCache(cl, cacheName, opts.verbose, stdout, stderr)
}

func parseArgs(args []string, stderr io.Writer) (initOptions, error) {
	var opts initOptions
	args = expandKeytabArgs(args)
	fs := flag.NewFlagSet("gokinit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, usageLine) }
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
		return opts, err
	}
	if fs.NArg() > 1 {
		return opts, errors.New("too many arguments")
	}
	if fs.NArg() == 1 {
		opts.principal = fs.Arg(0)
	}
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

func loadPKINITSettings(opts initOptions, cfg *config.Config, stdin io.Reader, stderr io.Writer) ([]func(*client.Settings), bool, error) {
	identities := append([]string(nil), cfg.LibDefaults.PKINITIdentities...)
	anchors := append([]string(nil), cfg.LibDefaults.PKINITAnchors...)
	if len(opts.pkinitOptions) != 0 {
		identitySpecified, anchorsSpecified := false, false
		for _, option := range opts.pkinitOptions {
			name, value, found := strings.Cut(option, "=")
			if !found || value == "" {
				return nil, false, fmt.Errorf("invalid -X option %q", option)
			}
			switch name {
			case "X509_user_identity":
				if !identitySpecified {
					identities = nil
					identitySpecified = true
				}
				identities = append(identities, value)
			case "X509_anchors":
				if !anchorsSpecified {
					anchors = nil
					anchorsSpecified = true
				}
				anchors = append(anchors, value)
			default:
				return nil, false, fmt.Errorf("unsupported -X option %q", name)
			}
		}
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
	roots := x509.NewCertPool()
	for _, source := range anchors {
		path, err := pkinitFilePath(source)
		if err != nil {
			return nil, false, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false, fmt.Errorf("read PKINIT anchor %q: %w", path, err)
		}
		if !roots.AppendCertsFromPEM(data) {
			return nil, false, fmt.Errorf("PKINIT anchor %q contains no certificates", path)
		}
	}
	intermediates := x509.NewCertPool()
	for _, source := range cfg.LibDefaults.PKINITPool {
		path, err := pkinitFilePath(source)
		if err != nil {
			return nil, false, err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, false, fmt.Errorf("read PKINIT certificate pool %q: %w", path, err)
		}
		if !intermediates.AppendCertsFromPEM(data) {
			return nil, false, fmt.Errorf("PKINIT certificate pool %q contains no certificates", path)
		}
	}
	settings := []func(*client.Settings){
		client.PKINITIdentity(identity),
		client.PKINITKDCCertificatePolicy(pkinit.KDCCertificatePolicy{
			Roots: roots, Intermediates: intermediates, Hostname: cfg.LibDefaults.PKINITKDCHostname,
			EKUChecking:       pkinit.KDCEKUChecking(cfg.LibDefaults.PKINITEKUChecking),
			RequireRevocation: cfg.LibDefaults.PKINITRequireCRLCheck,
		}),
		client.PKINITMinimumDHBits(cfg.LibDefaults.PKINITDHMinBits),
	}
	return settings, true, nil
}

func loadPKINITIdentity(source string, stdin io.Reader, stderr io.Writer, allowStdin bool) (*pkinit.Identity, error) {
	switch {
	case strings.HasPrefix(source, "FILE:"):
		paths := strings.SplitN(strings.TrimPrefix(source, "FILE:"), ",", 2)
		certificate, err := os.ReadFile(paths[0])
		if err != nil {
			return nil, fmt.Errorf("read PKINIT certificate: %w", err)
		}
		key := certificate
		if len(paths) == 2 {
			key, err = os.ReadFile(paths[1])
			if err != nil {
				return nil, fmt.Errorf("read PKINIT private key: %w", err)
			}
		}
		block, _ := pem.Decode(key)
		if block == nil || !x509.IsEncryptedPEMBlock(block) {
			return pkinit.FromPEM(certificate, key, nil)
		}
		pin, readErr := krbcli.ReadPassword("PIN for PKINIT identity: ", stdin, stderr, allowStdin)
		if readErr != nil {
			return nil, readErr
		}
		return pkinit.FromPEM(certificate, key, []byte(pin))
	case strings.HasPrefix(source, "PKCS12:"):
		path := strings.TrimPrefix(source, "PKCS12:")
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read PKINIT PKCS#12 identity: %w", err)
		}
		identity, err := pkinit.FromPKCS12(data, "")
		if err == nil {
			return identity, nil
		}
		pin, readErr := krbcli.ReadPassword("PIN for PKINIT identity: ", stdin, stderr, allowStdin)
		if readErr != nil {
			return nil, readErr
		}
		return pkinit.FromPKCS12(data, pin)
	default:
		return nil, fmt.Errorf("unsupported PKINIT identity source %q", source)
	}
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
	if opts.lifetime != "" {
		value, err := krbcli.ParseDuration(opts.lifetime)
		if err != nil {
			return result, fmt.Errorf("invalid ticket lifetime %q", opts.lifetime)
		}
		result.Lifetime = &value
	}
	if opts.renewLifetime != "" {
		value, err := krbcli.ParseDuration(opts.renewLifetime)
		if err != nil {
			return result, fmt.Errorf("invalid renewable lifetime %q", opts.renewLifetime)
		}
		result.RenewLifetime = &value
	}
	if opts.forwardable.set {
		result.Forwardable = &opts.forwardable.value
	}
	if opts.proxiable.set {
		result.Proxiable = &opts.proxiable.value
	}
	if opts.addresses.set {
		if opts.addresses.value {
			addresses, err := types.LocalHostAddresses()
			if err != nil {
				return result, err
			}
			result.Addresses = append(addresses, types.HostAddressesFromNetIPs(cfg.LibDefaults.ExtraAddresses)...)
		} else {
			result.Addresses = []types.HostAddress{}
		}
	}
	if opts.canonicalize {
		result.Canonicalize = &opts.canonicalize
	}
	if opts.enterprise {
		result.Enterprise = &opts.enterprise
	}
	if opts.service != "" {
		service, err := keytab.ParsePrincipal(opts.service)
		if err != nil {
			return result, fmt.Errorf("invalid service principal: %v", err)
		}
		name := types.PrincipalName{NameType: service.NameType, NameString: append([]string(nil), service.Components...)}
		result.ServicePrincipal = &name
	}
	return result, nil
}

func loadKeytab(opts initOptions, cfg *config.Config) (*keytab.Keytab, error) {
	if opts.keytabName != "" {
		return keytab.Load(opts.keytabName)
	}
	if opts.clientKeytab {
		return keytab.LoadDefaultClient(cfg)
	}
	return keytab.LoadDefault(cfg)
}

func isPasswordExpired(err error) bool {
	kdcErr, ok := krbcli.KDCError(err)
	return ok && kdcErr.ErrorCode == errorcode.KDC_ERR_KEY_EXPIRED
}

func changeExpiredPassword(cl *client.Client, principal string, stdin io.Reader, stderr io.Writer, passwordStdin bool) error {
	fmt.Fprintln(stderr, "Password expired.  You must change it now.")
	first, err := krbcli.ReadPassword("Enter new password: ", stdin, stderr, passwordStdin)
	if err != nil {
		return err
	}
	second, err := krbcli.ReadPassword("Enter it again: ", stdin, stderr, passwordStdin)
	if err != nil {
		return err
	}
	if first != second {
		return errors.New("Password mismatch")
	}
	ok, err := cl.ChangePasswd(first)
	if err != nil {
		return err
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
		fmt.Fprintf(stdout, "Using default cache: %s\n", displayCacheName(cacheName))
		fmt.Fprintf(stdout, "Using principal: %s@%s\n", cl.Credentials.CName().PrincipalNameString(), cl.Credentials.Domain())
		fmt.Fprintln(stdout, "Authenticated to Kerberos v5")
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
	if strings.Contains(strings.SplitN(name, "/", 2)[0], ":") {
		return name
	}
	return "FILE:" + name
}

func fail(stderr io.Writer, err error, context string) int {
	fmt.Fprintf(stderr, "kinit: %s %s\n", krbcli.ErrorText(err), context)
	return 1
}
