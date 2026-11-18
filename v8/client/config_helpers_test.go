package client

import (
	"testing"

	"github.com/otuschhoff/gokrb5/v8/config"
)

func mustClientTestConfig(t testing.TB, content string) *config.Config {
	t.Helper()
	cfg, err := config.NewFromString(content)
	if err != nil {
		t.Fatal(err)
	}
	if cfg == nil {
		t.Fatal("NewFromString returned nil config without error")
	}
	return cfg
}
