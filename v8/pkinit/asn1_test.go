package pkinit

import (
	"bytes"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
)

func TestAuthPackRoundTrip(t *testing.T) {
	now := time.Date(2026, 9, 6, 12, 34, 56, 0, time.UTC)
	want := AuthPack{
		PKAuthenticator: PKAuthenticator{
			CUSec: 123456, CTime: now, Nonce: 0xfedcba98,
			PAChecksum: []byte("checksum"), FreshnessToken: []byte("fresh"),
		},
		ClientPublicValue: &SubjectPublicKeyInfo{
			Algorithm:        AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}},
			SubjectPublicKey: asn1.BitString{Bytes: []byte{1, 2, 3}, BitLength: 24},
		},
		ClientDHNonce: []byte("client nonce"),
		SupportedKDFs: []KDFAlgorithmID{{ID: OIDKDFSHA512}, {ID: OIDKDFSHA384}, {ID: OIDKDFSHA256}},
	}
	encoded, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got AuthPack
	if err := got.Unmarshal(encoded); err != nil {
		t.Fatal(err)
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
		{DHInfo: &DHRepInfo{DHSignedData: []byte("signed"), ServerDHNonce: []byte("server")}},
		{EncKeyPack: []byte("enveloped")},
	}
	for _, want := range tests {
		encoded, err := want.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		var got PAPKAsRep
		if err := got.Unmarshal(encoded); err != nil {
			t.Fatal(err)
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
	if _, err := (PAPKAsRep{}).Marshal(); err == nil {
		t.Fatal("accepted empty PA-PK-AS-REP")
	}
	if _, err := (PAPKAsRep{DHInfo: &DHRepInfo{}, EncKeyPack: []byte{1}}).Marshal(); err == nil {
		t.Fatal("accepted PA-PK-AS-REP with both choices")
	}
	var reply PAPKAsRep
	if err := reply.Unmarshal([]byte{0xa2, 0x00}); err == nil {
		t.Fatal("accepted unknown PA-PK-AS-REP choice")
	}
}

func TestPKINITRejectsInvalidConstraintsAndTrailingData(t *testing.T) {
	pack := AuthPack{PKAuthenticator: PKAuthenticator{CUSec: 1000000, CTime: time.Now().UTC(), Nonce: 1, PAChecksum: []byte{1}}}
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
	for _, seed := range []PAPKAsRep{{DHInfo: &DHRepInfo{DHSignedData: []byte("signed")}}, {EncKeyPack: []byte("enveloped")}} {
		encoded, err := seed.Marshal()
		if err != nil {
			f.Fatal(err)
		}
		f.Add(encoded)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		var reply PAPKAsRep
		if reply.Unmarshal(b) == nil {
			_, _ = reply.Marshal()
		}
	})
}
