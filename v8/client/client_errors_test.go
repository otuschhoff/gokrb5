package client

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/keytab"
)

type diagnosticFailureWriter struct {
	prefix string
	cause  error
	short  bool
}

func (w diagnosticFailureWriter) Write(data []byte) (int, error) {
	if !bytes.HasPrefix(data, []byte(w.prefix)) {
		return len(data), nil
	}
	if w.short {
		return len(data) - 1, nil
	}
	return 0, w.cause
}

func TestPrintLogsOutputFailure(t *testing.T) {
	var logged bytes.Buffer
	kerberos := NewWithPassword("user", "EXAMPLE.COM", "password", config.New(), Logger(log.New(&logged, "", 0)))
	cause := errors.New("injected diagnostic failure")
	kerberos.Print(diagnosticFailureWriter{prefix: "Credentials:", cause: cause})
	if !strings.Contains(logged.String(), cause.Error()) {
		t.Fatalf("diagnostic failure not logged: %s", logged.String())
	}
}

func TestDiagnosticsRetainsEncodingFailure(t *testing.T) {
	kerberos := NewWithPassword("user", "EXAMPLE.COM", "password", config.New())
	kerberos.Credentials.SetValidUntil(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC))
	err := kerberos.Diagnostics(io.Discard)
	if _, ok := errors.AsType[*json.MarshalerError](err); !ok {
		t.Fatalf("diagnostic encoding failure lost: %v", err)
	}
}

func TestDiagnosticsRetainsValidationAndWriterFailures(t *testing.T) {
	cause := errors.New("injected diagnostic failure")
	cfg := config.New()
	cfg.Realms = []config.Realm{{Realm: "EXAMPLE.COM", KDC: []string{"127.0.0.1:88"}}}
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{17}
	cfg.LibDefaults.PreferredPreauthTypes = nil
	keys := keytab.New()
	if err := keys.AddEntry("user", "EXAMPLE.COM", "test password", time.Now(), 1, 18); err != nil {
		t.Fatal(err)
	}
	kerberos := NewWithKeytab("user", "EXAMPLE.COM", keys, cfg)
	err := kerberos.Diagnostics(diagnosticFailureWriter{prefix: "UDP KDCs:", cause: cause})
	if !errors.Is(err, cause) || !strings.Contains(err.Error(), "default_tkt_enctypes specifies 17") {
		t.Fatalf("validation or output failure lost: %v", err)
	}
}

func TestDiagnosticsRetainsWriterFailures(t *testing.T) {
	cause := errors.New("injected diagnostic output failure")
	for _, tt := range []struct {
		name   string
		writer diagnosticFailureWriter
		want   error
	}{
		{name: "client details", writer: diagnosticFailureWriter{prefix: "Credentials:", cause: cause}, want: cause},
		{name: "UDP diagnostics", writer: diagnosticFailureWriter{prefix: "UDP KDCs:", cause: cause}, want: cause},
		{name: "TCP diagnostics", writer: diagnosticFailureWriter{prefix: "TCP KDCs:", cause: cause}, want: cause},
		{name: "short write", writer: diagnosticFailureWriter{prefix: "Credentials:", short: true}, want: io.ErrShortWrite},
		{name: "short TCP write", writer: diagnosticFailureWriter{prefix: "TCP KDCs:", short: true}, want: io.ErrShortWrite},
	} {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.New()
			cfg.Realms = []config.Realm{{Realm: "EXAMPLE.COM", KDC: []string{"127.0.0.1:88"}}}
			kerberos := NewWithPassword("user", "EXAMPLE.COM", "password", cfg)
			if err := kerberos.Diagnostics(tt.writer); !errors.Is(err, tt.want) {
				t.Fatalf("diagnostic error = %v, want %v", err, tt.want)
			}
		})
	}
}
