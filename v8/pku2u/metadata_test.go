package pku2u

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"reflect"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/pkinit"
)

func TestTrustedCertifiersRoundTrip(t *testing.T) {
	want := TrustedCertifiers{
		{SubjectName: []byte{1, 2, 3}},
		{SubjectKeyIdentifier: []byte{4, 5, 6}},
	}
	data, err := want.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var got TrustedCertifiers
	if err := got.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("metadata = %#v, want %#v", got, want)
	}
	if err := got.Unmarshal(append(data, 0)); err == nil {
		t.Fatal("accepted trailing metadata")
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
	if !metadata.Accepts(identity) {
		t.Fatal("trusted issuer did not select identity")
	}
	metadata[0].SubjectName[0] ^= 1
	if metadata.Accepts(identity) {
		t.Fatal("untrusted issuer selected identity")
	}
}

func testCertificateChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	now := time.Now()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rootTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
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
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "Peer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, &leafKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}
	return root, leaf, leafKey
}
