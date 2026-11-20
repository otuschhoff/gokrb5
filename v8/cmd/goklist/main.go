// Command goklist lists the contents of a Kerberos keytab (klist -k).
package main

import (
	"cmp"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/otuschhoff/gokrb5/v8/cmd/internal/krbcli"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
)

const usageLine = "usage: goklist [-e] [-s] [-c cache_name] | [-k [-t] [-K] [-e] [keytab_name]]"

type listOptions struct {
	keytab        bool
	showTimestamp bool
	showKeys      bool
	showEtypes    bool
	silent        bool
	cacheName     string
	name          string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	opts, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		if !opts.silent {
			_, _ = fmt.Fprintf(stderr, "goklist: %v\n", err)
		}
		return 1
	}
	if opts.keytab {
		return listKeytab(opts, stdout, stderr)
	}
	return listCache(opts, stdout, stderr)
}

func parseArgs(args []string, stderr io.Writer) (listOptions, error) {
	var opts listOptions
	fs := flag.NewFlagSet("goklist", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { _, _ = fmt.Fprintln(stderr, usageLine) }
	fs.BoolVar(&opts.keytab, "k", false, "list keytab")
	fs.BoolVar(&opts.showTimestamp, "t", false, "show keytab timestamps")
	fs.BoolVar(&opts.showKeys, "K", false, "show key values")
	fs.BoolVar(&opts.showEtypes, "e", false, "show encryption types")
	fs.BoolVar(&opts.silent, "s", false, "silent status")
	fs.StringVar(&opts.cacheName, "c", "", "credential cache name")
	if err := fs.Parse(args); err != nil {
		return opts, fmt.Errorf("parse options: %w", err)
	}
	if fs.NArg() > 1 {
		return opts, errors.New("too many arguments")
	}
	if fs.NArg() == 1 {
		opts.name = fs.Arg(0)
	}
	if opts.keytab && opts.cacheName != "" {
		return opts, errors.New("-k and -c are mutually exclusive")
	}
	if !opts.keytab && (opts.showTimestamp || opts.showKeys) {
		return opts, errors.New("-t and -K require -k")
	}
	return opts, nil
}

func listKeytab(opts listOptions, stdout, stderr io.Writer) int {
	name := opts.name
	var kt *keytab.Keytab
	var err error
	if name == "" {
		cfg, _ := krbcli.LoadConfig()
		kt, err = keytab.LoadDefault(cfg)
	} else {
		kt, err = keytab.Load(name)
	}
	if err != nil {
		return fail(stderr, err, opts.silent)
	}
	if !opts.silent {
		if _, err := fmt.Fprint(stdout, kt.Klist(opts.showTimestamp, opts.showKeys, opts.showEtypes)); err != nil {
			return fail(stderr, err, opts.silent)
		}
	}
	return 0
}

func listCache(opts listOptions, stdout, stderr io.Writer) int {
	name := cmp.Or(opts.cacheName, opts.name)
	if name == "" {
		cfg, err := krbcli.LoadConfig()
		if err != nil {
			return fail(stderr, err, opts.silent)
		}
		defaultName, err := credentials.DefaultCCacheName(cfg)
		if err != nil {
			return fail(stderr, err, opts.silent)
		}
		name = defaultName
	}
	cache, err := credentials.LoadCCache(name)
	if err != nil {
		return fail(stderr, err, opts.silent)
	}
	entries := cache.GetEntries()
	if opts.silent {
		return cacheStatus(entries, time.Now().UTC())
	}
	if code := writeCacheHeader(stdout, stderr, name, cache.DefaultPrincipal); code != 0 {
		return code
	}
	for _, entry := range entries {
		if code := writeCacheEntry(stdout, stderr, entry, opts.showEtypes); code != 0 {
			return code
		}
	}
	return 0
}

func cacheStatus(entries []*credentials.Credential, now time.Time) int {
	for _, entry := range entries {
		if now.Before(entry.EndTime) {
			return 0
		}
	}
	return 1
}

func writeCacheHeader(stdout, stderr io.Writer, name string, principal credentials.Principal) int {
	if _, err := fmt.Fprintf(stdout, "Ticket cache: %s\n", displayCacheName(name)); err != nil {
		return fail(stderr, err, false)
	}
	if _, err := fmt.Fprintf(stdout, "Default principal: %s\n\n", principalString(principal)); err != nil {
		return fail(stderr, err, false)
	}
	if _, err := fmt.Fprintln(stdout, "Valid starting     Expires            Service principal"); err != nil {
		return fail(stderr, err, false)
	}
	return 0
}

func writeCacheEntry(stdout, stderr io.Writer, entry *credentials.Credential, showEtypes bool) int {
	start := entry.StartTime
	if start.IsZero() {
		start = entry.AuthTime
	}
	if _, err := fmt.Fprintf(stdout, "%s  %s  %s\n",
		formatTime(start), formatTime(entry.EndTime), principalString(entry.Server)); err != nil {
		return fail(stderr, err, false)
	}
	if !entry.RenewTill.IsZero() && entry.RenewTill.Unix() > 0 {
		if _, err := fmt.Fprintf(stdout, "\trenew until %s\n", formatTime(entry.RenewTill)); err != nil {
			return fail(stderr, err, false)
		}
	}
	if showEtypes {
		var ticketEType int32
		var ticket messages.Ticket
		if err := ticket.Unmarshal(entry.Ticket); err == nil {
			ticketEType = ticket.EncPart.EType
		}
		if _, err := fmt.Fprintf(stdout, "\tEtype (skey, tkt): %s, %s\n",
			etypeID.ETypeToString(entry.Key.KeyType), etypeID.ETypeToString(ticketEType)); err != nil {
			return fail(stderr, err, false)
		}
	}
	return 0
}

func principalString(principal credentials.Principal) string {
	return keytab.Principal{
		Realm:      principal.Realm,
		Components: principal.PrincipalName.NameString,
		NameType:   principal.PrincipalName.NameType,
	}.String()
}

func formatTime(value time.Time) string {
	return value.Local().Format("01/02/06 15:04:05")
}

func displayCacheName(name string) string {
	prefix, _, _ := strings.Cut(name, "/")
	if strings.Contains(prefix, ":") {
		return name
	}
	return "FILE:" + name
}

func fail(stderr io.Writer, err error, silent bool) int {
	if !silent {
		_, _ = fmt.Fprintf(stderr, "goklist: %s\n", krbcli.ErrorText(err))
	}
	return 1
}
