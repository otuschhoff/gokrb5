package pku2u

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/pkinit"
)

func TestTrustedCertifiersRoundTrip(t *testing.T) {
	t.Parallel()

	want := TrustedCertifiers{
		{SubjectName: []byte{1}, IssuerAndSerial: nil, SubjectKeyIdentifier: nil},
		{SubjectName: nil, IssuerAndSerial: []byte{2}, SubjectKeyIdentifier: nil},
		{SubjectName: nil, IssuerAndSerial: nil, SubjectKeyIdentifier: []byte{3}},
	}
	data, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	const wantDER = "300f300380010130038101023003820103"
	if gotDER := hex.EncodeToString(data); gotDER != wantDER {
		t.Fatalf("metadata DER = %s, want %s", gotDER, wantDER)
	}
	var got TrustedCertifiers
	if err := got.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata = %#v, want %#v", got, want)
	}
}

func TestTrustedCertifiersMarshalDERCompatibility(t *testing.T) {
	t.Parallel()
	for _, tt := range []struct {
		name     string
		metadata TrustedCertifiers
	}{
		{name: "nil list", metadata: nil},
		{name: "empty list", metadata: TrustedCertifiers{}},
		{name: "nil identifier", metadata: TrustedCertifiers{
			{SubjectName: nil, IssuerAndSerial: nil, SubjectKeyIdentifier: nil},
		}},
		{name: "empty and long identifiers", metadata: TrustedCertifiers{
			{SubjectName: []byte{}, IssuerAndSerial: make([]byte, 256), SubjectKeyIdentifier: []byte{1}},
		}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			want, err := asn1.Marshal([]pkinit.ExternalPrincipalIdentifier(tt.metadata))
			if err != nil {
				t.Fatal(err)
			}
			got, err := tt.metadata.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(want, got) {
				t.Fatalf("metadata DER = %x, fork DER = %x", got, want)
			}
		})
	}
}

func TestTrustedCertifiersUnmarshalRejectsNilDestination(t *testing.T) {
	t.Parallel()

	data, err := (TrustedCertifiers{}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var metadata *TrustedCertifiers
	const want = "PKU2U trusted-certifier destination is nil"
	if err := metadata.Unmarshal(data); err == nil || err.Error() != want {
		t.Fatalf("nil destination error = %v, want %q", err, want)
	}
}

func TestTrustedCertifiersUnmarshalPreservesReceiverOnError(t *testing.T) {
	t.Parallel()

	const identifierError = "PKU2U trusted certifier must contain exactly one identifier"
	for _, tt := range []struct {
		name        string
		encoded     string
		expectedErr string
	}{
		{name: "missing identifier after valid entry", encoded: "300730038001013000", expectedErr: identifierError},
		{name: "multiple identifiers", encoded: "30083006800101810102", expectedErr: identifierError},
		{
			name:        "trailing byte",
			encoded:     "3005300380010100",
			expectedErr: "PKU2U trusted certifiers contain 1 trailing bytes",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := hex.DecodeString(tt.encoded)
			if err != nil {
				t.Fatal(err)
			}
			metadata := TrustedCertifiers{{SubjectName: []byte{9}, IssuerAndSerial: nil, SubjectKeyIdentifier: nil}}
			err = metadata.Unmarshal(data)
			if err == nil || err.Error() != tt.expectedErr {
				t.Fatalf("Unmarshal = %v, want %q", err, tt.expectedErr)
			}
			const originalDER = "30053003800109"
			got, err := metadata.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			if gotDER := hex.EncodeToString(got); gotDER != originalDER {
				t.Fatalf("receiver DER = %s, want %s", gotDER, originalDER)
			}
		})
	}
}

func TestTrustedCertifiersSelectIdentity(t *testing.T) {
	root, leaf, key := testCertificateChain(t)
	identity, err := pkinit.NewIdentity(leaf, []*x509.Certificate{root}, key, false)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)
	metadata := TrustedCertifiersFromPool(pool)
	if len(metadata) != 1 || !bytes.Equal(metadata[0].SubjectName, root.RawSubject) ||
		metadata[0].IssuerAndSerial != nil || metadata[0].SubjectKeyIdentifier != nil {
		t.Fatalf("pool metadata did not contain exactly the root subject: %#v", metadata)
	}
	if !metadata.Accepts(identity) {
		t.Fatal("trusted issuer did not select identity")
	}
	metadata[0].SubjectName[0] ^= 1
	if metadata.Accepts(identity) {
		t.Fatal("untrusted issuer selected identity")
	}
	fresh := TrustedCertifiersFromPool(pool)
	if !fresh.Accepts(identity) {
		t.Fatal("mutating old metadata affected the pool subjects")
	}
}

func testCertificateChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	notBefore, notAfter := now.Add(-time.Hour), now.Add(time.Hour)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var rootTemplate x509.Certificate
	rootTemplate.SerialNumber = big.NewInt(1)
	rootTemplate.Subject.CommonName = "Root"
	rootTemplate.NotBefore = notBefore
	rootTemplate.NotAfter = notAfter
	rootTemplate.IsCA = true
	rootTemplate.BasicConstraintsValid = true
	rootTemplate.KeyUsage = x509.KeyUsageCertSign
	rootDER, err := x509.CreateCertificate(rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var leafTemplate x509.Certificate
	leafTemplate.SerialNumber = big.NewInt(2)
	leafTemplate.Subject.CommonName = "Peer"
	leafTemplate.NotBefore = notBefore
	leafTemplate.NotAfter = notAfter
	leafTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf, leafKey
}
