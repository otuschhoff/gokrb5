package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/jcmturner/gokrb5/v8/client"
	"github.com/jcmturner/gokrb5/v8/cmd/internal/krbcli"
	"github.com/jcmturner/gokrb5/v8/config"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/errorcode"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
	"github.com/jcmturner/gokrb5/v8/types"
)

const usageLine = "usage: gokinit [-V] [-l lifetime] [-r renewable_life] [-f | -F] [-p | -P] [-a | -A] [-C] [-E] [-v] [-R] [-k [-i | -t keytab_file]] [-c cache_name] [-S service_name] [--password-stdin] [principal]"

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
	verbose       bool
	lifetime      string
	renewLifetime string
	forwardable   boolChoice
	proxiable     boolChoice
	addresses     boolChoice
	canonicalize  bool
	enterprise    bool
	validate      bool
	renew         bool
	useKeytab     bool
	clientKeytab  bool
	keytabName    string
	cacheName     string
	service       string
	passwordStdin bool
	principal     string
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
	cl := client.NewFromPrincipalName(types.PrincipalName{
		NameType:   principal.NameType,
		NameString: append([]string(nil), principal.Components...),
	}, principal.Realm, cfg)
	passwordInput := bufio.NewReader(stdin)
	if opts.useKeytab {
		kt, loadErr := loadKeytab(opts, cfg)
		if loadErr != nil {
			return fail(stderr, loadErr, "while resolving keytab")
		}
		cl.Credentials.WithKeytab(kt)
	} else {
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
				return writeCache(cl, cacheName, false, opts.verbose, stdout, stderr)
			}
		}
		return fail(stderr, err, "while getting initial credentials")
	}
	return writeCache(cl, cacheName, opts.useKeytab, opts.verbose, stdout, stderr)
}

func parseArgs(args []string, stderr io.Writer) (initOptions, error) {
	var opts initOptions
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
	if opts.renew && (opts.useKeytab || opts.principal != "" || opts.passwordStdin) {
		return opts, errors.New("-R cannot be combined with credential acquisition options")
	}
	return opts, nil
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

func writeCache(cl *client.Client, cacheName string, keytabLogin, verbose bool, stdout, stderr io.Writer) int {
	cache, err := cl.CCache()
	if err != nil {
		return fail(stderr, err, "while creating credentials cache")
	}
	if keytabLogin {
		entries := cache.GetEntries()
		if len(entries) > 0 {
			start := entries[0].StartTime
			if start.IsZero() {
				start = entries[0].AuthTime
			}
			refresh := start.Add(entries[0].EndTime.Sub(start) / 2).Unix()
			if err := cache.SetConfig("refresh_time", "", strconv.FormatInt(refresh, 10)); err != nil {
				return fail(stderr, err, "while setting refresh time")
			}
		}
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
	return writeCache(cl, cacheName, false, verbose, stdout, stderr)
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
