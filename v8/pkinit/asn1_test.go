package pkinit

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
)

func TestPKINITDEREncodings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		marshal func() ([]byte, error)
		wantHex string
	}{
		{
			name:    "request",
			marshal: PAPKAsReq{SignedAuthPack: []byte("signed"), TrustedCertifiers: nil, KDCPkID: nil}.Marshal,
			wantHex: "300880067369676e6564",
		},
		{
			name: "dh reply",
			marshal: PAPKAsRep{
				DHInfo: &DHRepInfo{DHSignedData: []byte("signed"), ServerDHNonce: nil, KDF: nil}, EncKeyPack: nil,
			}.Marshal,
			wantHex: "a00a300880067369676e6564",
		},
		{
			name:    "rsa reply",
			marshal: PAPKAsRep{DHInfo: nil, EncKeyPack: []byte("key")}.Marshal,
			wantHex: "81036b6579",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			der, err := tt.marshal()
			if err != nil {
				t.Fatal(err)
			}
			if got := hex.EncodeToString(der); got != tt.wantHex {
				t.Errorf("DER = %s, want %s", got, tt.wantHex)
			}
		})
	}
}

func TestPKINITDERDecodeErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name, context string
		decode        func([]byte) error
		der           []byte
	}{
		{
			name:    "truncated request",
			context: "decode PKINIT DER value",
			decode:  new(PAPKAsReq).Unmarshal,
			der:     []byte{0x30},
		},
		{
			name:    "truncated sequence field",
			context: "decode PKINIT DER sequence field",
			decode:  new(AuthPack).Unmarshal,
			der:     []byte{0x30, 0x01, 0xa0},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			err := tt.decode(tt.der)
			if _, ok := errors.AsType[asn1.SyntaxError](err); !ok || !strings.Contains(err.Error(), tt.context) {
				t.Fatalf("want %q with ASN.1 syntax cause, got %v", tt.context, err)
			}
		})
	}
}

func TestPKINITDERMarshalErrors(t *testing.T) {
	t.Parallel()

	pack := AuthPack{
		PKAuthenticator: PKAuthenticator{
			CUSec: 0, CTime: time.Date(2026, 9, 6, 12, 34, 56, 0, time.UTC), Nonce: 0,
			PAChecksum: []byte{1}, FreshnessToken: nil,
		},
		ClientPublicValue: nil,
		SupportedCMSTypes: nil,
		ClientDHNonce:     nil,
		SupportedKDFs:     []KDFAlgorithmID{{ID: asn1.ObjectIdentifier{1}}},
	}
	var keyInfo KDCDHKeyInfo
	keyInfo.DHKeyExpiration = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
	tests := []struct {
		name, context string
		marshal       func() ([]byte, error)
	}{
		{name: "invalid kdf oid", context: "marshal PKINIT field [4]", marshal: pack.Marshal},
		{name: "out-of-range expiry", context: "marshal PKINIT KDCDHKeyInfo", marshal: keyInfo.Marshal},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			der, err := tt.marshal()
			_, typed := errors.AsType[asn1.StructuralError](err)
			if der != nil || !typed || !strings.Contains(err.Error(), tt.context) {
				t.Fatalf("want no output and %q with ASN.1 structural cause, got %x, %v", tt.context, der, err)
			}
		})
	}
}

func TestAuthPackRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 34, 56, 0, time.UTC)
	var parameters asn1.RawValue
	want := AuthPack{
		PKAuthenticator: PKAuthenticator{
			CUSec: 123456, CTime: now, Nonce: 0xfedcba98,
			PAChecksum: []byte("checksum"), FreshnessToken: []byte("fresh"),
		},
		ClientPublicValue: &SubjectPublicKeyInfo{
			Algorithm: AlgorithmIdentifier{
				Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}, Parameters: parameters,
			},
			SubjectPublicKey: asn1.BitString{Bytes: []byte{1, 2, 3}, BitLength: 24},
		},
		SupportedCMSTypes: nil,
		ClientDHNonce:     []byte("client nonce"),
		SupportedKDFs:     []KDFAlgorithmID{{ID: OIDKDFSHA512}, {ID: OIDKDFSHA384}, {ID: OIDKDFSHA256}},
	}
	encoded, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got AuthPack
	if ierr := got.Unmarshal(encoded); ierr != nil {
		t.Fatal(ierr)
	}
	reencoded, err := got.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(reencoded, encoded) {
		t.Fatalf("AuthPack re-encoding differs:\n%x\n%x", encoded, reencoded)
	}
	if len(got.SupportedKDFs) != 3 || !got.SupportedKDFs[2].ID.Equal(OIDKDFSHA256) {
		t.Fatalf("KDF extension was not preserved: %#v", got.SupportedKDFs)
	}
}

func TestPAPKAsRepChoices(t *testing.T) {
	tests := []PAPKAsRep{
		{
			DHInfo:     &DHRepInfo{DHSignedData: []byte("signed"), ServerDHNonce: []byte("server"), KDF: nil},
			EncKeyPack: nil,
		},
		{DHInfo: nil, EncKeyPack: []byte("enveloped")},
	}
	for _, want := range tests {
		encoded, err := want.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var got PAPKAsRep
		if ierr := got.Unmarshal(encoded); ierr != nil {
			t.Fatal(ierr)
		}
		reencoded, err := got.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(reencoded, encoded) {
			t.Fatalf("PA-PK-AS-REP re-encoding differs: %x != %x", encoded, reencoded)
		}
	}
}

func TestPAPKAsRepRejectsInvalidChoice(t *testing.T) {
	var reply PAPKAsRep
	if _, err := reply.Marshal(); err == nil {
		t.Fatal("accepted empty PA-PK-AS-REP")
	}
	var dhInfo DHRepInfo
	if _, err := (PAPKAsRep{DHInfo: &dhInfo, EncKeyPack: []byte{1}}).Marshal(); err == nil {
		t.Fatal("accepted PA-PK-AS-REP with both choices")
	}
	if err := reply.Unmarshal([]byte{0xa2, 0x00}); err == nil {
		t.Fatal("accepted unknown PA-PK-AS-REP choice")
	}
}

func TestPKINITRejectsInvalidConstraintsAndTrailingData(t *testing.T) {
	var pack AuthPack
	pack.PKAuthenticator = PKAuthenticator{
		CUSec: 1000000, CTime: time.Now().UTC(), Nonce: 1, PAChecksum: []byte{1}, FreshnessToken: nil,
	}
	if _, err := pack.Marshal(); err == nil {
		t.Fatal("marshaled invalid microseconds")
	}
	pack.PKAuthenticator.CUSec = 1
	encoded, err := pack.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, 0)
	if err := new(AuthPack).Unmarshal(encoded); err == nil {
		t.Fatal("accepted trailing DER data")
	}
}

func FuzzPKASRep(f *testing.F) {
	seeds := []PAPKAsRep{
		{DHInfo: &DHRepInfo{DHSignedData: []byte("signed"), ServerDHNonce: nil, KDF: nil}, EncKeyPack: nil},
		{DHInfo: nil, EncKeyPack: []byte("enveloped")},
	}
	for _, seed := range seeds {
		encoded, err := seed.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}
	f.Fuzz(func(_ *testing.T, b []byte) {
		var reply PAPKAsRep
		if reply.Unmarshal(b) == nil {
			_, _ = reply.Marshal()
		}
	})
}
