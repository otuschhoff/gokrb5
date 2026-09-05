package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/jcmturner/gokrb5/v8/cmd/internal/krbcli"
	"github.com/jcmturner/gokrb5/v8/credentials"
)

const usageLine = "usage: gokdestroy [-A] [-q] [-c cache_name]"

type destroyOptions struct {
	all       bool
	quiet     bool
	cacheName string
}

func main() {
	os.Exit(run(os.Args[1:], os.Stderr))
}

func run(args []string, stderr io.Writer) int {
	opts, err := parseArgs(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		} else {
			fmt.Fprintf(stderr, "gokdestroy: %v\n", err)
		}
		return 1
	}
	if opts.all {
		return destroyAllFileCaches(stderr, opts.quiet)
	}
	name := opts.cacheName
	if name == "" {
		cfg, err := krbcli.LoadConfig()
		if err != nil {
			return fail(stderr, err, opts.quiet)
		}
		name, err = credentials.DefaultCCacheName(cfg)
		if err != nil {
			return fail(stderr, err, opts.quiet)
		}
	}
	path, err := credentials.ResolveCCacheName(name)
	if err != nil {
		return fail(stderr, err, opts.quiet)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fail(stderr, err, opts.quiet)
	}
	return 0
}

func destroyAllFileCaches(stderr io.Writer, quiet bool) int {
	cfg, err := krbcli.LoadConfig()
	if err != nil {
		return fail(stderr, err, quiet)
	}
	name, err := credentials.DefaultCCacheName(cfg)
	if err != nil {
		return fail(stderr, err, quiet)
	}
	path, err := credentials.ResolveCCacheName(name)
	if err != nil {
		return fail(stderr, err, quiet)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fail(stderr, err, quiet)
	}
	return 0
}

func parseArgs(args []string, stderr io.Writer) (destroyOptions, error) {
	var opts destroyOptions
	fs := flag.NewFlagSet("gokdestroy", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprintln(stderr, usageLine) }
	fs.BoolVar(&opts.all, "A", false, "destroy all caches")
	fs.BoolVar(&opts.quiet, "q", false, "quiet")
	fs.StringVar(&opts.cacheName, "c", "", "credential cache name")
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() != 0 {
		return opts, errors.New("unexpected argument")
	}
	if opts.all && opts.cacheName != "" {
		return opts, errors.New("-A and -c are mutually exclusive")
	}
	return opts, nil
}

func fail(stderr io.Writer, err error, quiet bool) int {
	if !quiet {
		fmt.Fprintf(stderr, "gokdestroy: %s while destroying cache\n", krbcli.ErrorText(err))
	}
	return 1
}
