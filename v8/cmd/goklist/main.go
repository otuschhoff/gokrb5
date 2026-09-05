package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/jcmturner/gokrb5/v8/cmd/internal/krbcli"
	"github.com/jcmturner/gokrb5/v8/credentials"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/keytab"
	"github.com/jcmturner/gokrb5/v8/messages"
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
		if err == flag.ErrHelp {
			return 0
		}
		if !opts.silent {
			fmt.Fprintf(stderr, "goklist: %v\n", err)
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
	fs.Usage = func() { fmt.Fprintln(stderr, usageLine) }
	fs.BoolVar(&opts.keytab, "k", false, "list keytab")
	fs.BoolVar(&opts.showTimestamp, "t", false, "show keytab timestamps")
	fs.BoolVar(&opts.showKeys, "K", false, "show key values")
	fs.BoolVar(&opts.showEtypes, "e", false, "show encryption types")
	fs.BoolVar(&opts.silent, "s", false, "silent status")
	fs.StringVar(&opts.cacheName, "c", "", "credential cache name")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() > 1 {
		return opts, fmt.Errorf("too many arguments")
	}
	if fs.NArg() == 1 {
		opts.name = fs.Arg(0)
	}
	if opts.keytab && opts.cacheName != "" {
		return opts, fmt.Errorf("-k and -c are mutually exclusive")
	}
	if !opts.keytab && (opts.showTimestamp || opts.showKeys) {
		return opts, fmt.Errorf("-t and -K require -k")
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
		fmt.Fprint(stdout, kt.Klist(opts.showTimestamp, opts.showKeys, opts.showEtypes))
	}
	return 0
}

func listCache(opts listOptions, stdout, stderr io.Writer) int {
	name := opts.cacheName
	if name == "" {
		name = opts.name
	}
	if name == "" {
		cfg, err := krbcli.LoadConfig()
		if err != nil {
			return fail(stderr, err, opts.silent)
		}
		name, err = credentials.DefaultCCacheName(cfg)
		if err != nil {
			return fail(stderr, err, opts.silent)
		}
	}
	cache, err := credentials.LoadCCache(name)
	if err != nil {
		return fail(stderr, err, opts.silent)
	}
	entries := cache.GetEntries()
	if opts.silent {
		now := time.Now().UTC()
		for _, entry := range entries {
			if now.Before(entry.EndTime) {
				return 0
			}
		}
		return 1
	}
	fmt.Fprintf(stdout, "Ticket cache: %s\n", displayCacheName(name))
	fmt.Fprintf(stdout, "Default principal: %s\n\n", principalString(cache.DefaultPrincipal))
	fmt.Fprintln(stdout, "Valid starting     Expires            Service principal")
	for _, entry := range entries {
		start := entry.StartTime
		if start.IsZero() {
			start = entry.AuthTime
		}
		fmt.Fprintf(stdout, "%s  %s  %s\n", formatTime(start), formatTime(entry.EndTime), principalString(entry.Server))
		if !entry.RenewTill.IsZero() && entry.RenewTill.Unix() > 0 {
			fmt.Fprintf(stdout, "\trenew until %s\n", formatTime(entry.RenewTill))
		}
		if opts.showEtypes {
			ticketEType := int32(0)
			var ticket messages.Ticket
			if err := ticket.Unmarshal(entry.Ticket); err == nil {
				ticketEType = ticket.EncPart.EType
			}
			fmt.Fprintf(stdout, "\tEtype (skey, tkt): %s, %s\n", etypeID.ETypeToString(entry.Key.KeyType), etypeID.ETypeToString(ticketEType))
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
	if strings.Contains(strings.SplitN(name, "/", 2)[0], ":") {
		return name
	}
	return "FILE:" + name
}

func fail(stderr io.Writer, err error, silent bool) int {
	if !silent {
		fmt.Fprintf(stderr, "goklist: %s\n", krbcli.ErrorText(err))
	}
	return 1
}
