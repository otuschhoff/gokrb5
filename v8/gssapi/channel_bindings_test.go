package gssapi

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestTLSChannelBindings(t *testing.T) {
	if _, err := TLSServerEndPoint(tls.ConnectionState{}); err == nil {
		t.Fatal("missing peer certificate accepted")
	}
	for _, algorithm := range []x509.SignatureAlgorithm{x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA} {
		state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{{Raw: []byte("certificate"), SignatureAlgorithm: algorithm}}}
		bindings, err := TLSServerEndPoint(state)
		if err != nil || !bytes.HasPrefix(bindings.ApplicationData, []byte("tls-server-end-point:")) {
			t.Fatalf("TLS server endpoint for %v = %x, %v", algorithm, bindings.ApplicationData, err)
		}
		wantLength := len("tls-server-end-point:") + 32
		if algorithm == x509.SHA384WithRSA {
			wantLength += 16
		} else if algorithm == x509.SHA512WithRSA {
			wantLength += 32
		}
		if len(bindings.ApplicationData) != wantLength {
			t.Fatalf("binding length for %v = %d, want %d", algorithm, len(bindings.ApplicationData), wantLength)
		}
	}
	if _, err := TLSUnique(tls.ConnectionState{}); err == nil {
		t.Fatal("missing TLS unique data accepted")
	}
	unique, err := TLSUnique(tls.ConnectionState{TLSUnique: []byte{1, 2, 3}})
	if err != nil || !bytes.Equal(unique.ApplicationData, append([]byte("tls-unique:"), 1, 2, 3)) {
		t.Fatalf("TLS unique = %x, %v", unique.ApplicationData, err)
	}
}

func TestContextFlagsAndNegoExKeys(t *testing.T) {
	flags := NewContextFlags()
	if flags.BitLength != 32 || len(flags.Bytes) != 4 {
		t.Fatalf("context flags = %+v", flags)
	}
	original := []byte{1, 2, 3, 4}
	context := &SecurityContext{key: types.EncryptionKey{KeyType: 17, KeyValue: original}}
	key, ok := context.NegoExKey()
	if !ok || !bytes.Equal(key.KeyValue, original) {
		t.Fatalf("NEGOEX key = %+v, %v", key, ok)
	}
	key.KeyValue[0] = 9
	verifyKey, ok := context.NegoExVerifyKey()
	if !ok || verifyKey.KeyValue[0] != 1 || original[0] != 1 {
		t.Fatal("NEGOEX key exposed internal storage")
	}
}
