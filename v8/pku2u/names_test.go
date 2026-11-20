package pku2u

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
)

var (
	oidSubjectAlternativeName = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidUPN                    = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 20, 2, 3}
)

func TestPrincipalFromCertificateUPN(t *testing.T) {
	certificate := testCertificate(t, pkix.Name{CommonName: "Alice"}, upnSAN(t, "alice@example.com"))
	principal, err := PrincipalFromCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if principal.NameType != nametype.KRB_NT_ENTERPRISE || principal.PrincipalNameString() != "alice@example.com" {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestPrincipalFromCertificateSubjectFallback(t *testing.T) {
	certificate := testCertificate(t, pkix.Name{CommonName: "Peer", Organization: []string{"Example"}}, nil)
	principal, err := PrincipalFromCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if principal.NameType != nametype.KRB_NT_X500_PRINCIPAL || principal.PrincipalNameString() != "CN=Peer,O=Example" {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestPrincipalFromCertificateRejectsMissingIdentity(t *testing.T) {
	t.Parallel()

	var subject pkix.Name
	certificate := testCertificate(t, subject, nil)
	principal, err := PrincipalFromCertificate(certificate)
	const want = "PKU2U certificate has no principal name or subject"
	if err == nil || err.Error() != want {
		t.Fatalf("PrincipalFromCertificate error = %v, want %q", err, want)
	}
	if principal.NameType != 0 || principal.NameString != nil {
		t.Fatalf("PrincipalFromCertificate returned a nonzero principal: %#v", principal)
	}
}

func TestPrincipalFromCertificateRejectsNilCertificate(t *testing.T) {
	t.Parallel()

	principal, err := PrincipalFromCertificate(nil)
	const want = "read PKU2U certificate principal names: PKINIT certificate is required"
	if err == nil || err.Error() != want {
		t.Fatalf("PrincipalFromCertificate error = %v, want %q", err, want)
	}
	cause := errors.Unwrap(err)
	if cause == nil || cause.Error() != "PKINIT certificate is required" {
		t.Fatalf("PrincipalFromCertificate cause = %v, want PKINIT missing certificate error", cause)
	}
	if principal.NameType != 0 || principal.NameString != nil {
		t.Fatalf("PrincipalFromCertificate returned a nonzero principal: %#v", principal)
	}
}

func TestPrincipalFromCertificatePreservesSANError(t *testing.T) {
	t.Parallel()

	var certificate x509.Certificate
	certificate.Subject.CommonName = "Malformed SAN fixture"
	certificate.Extensions = []pkix.Extension{{
		Id:       oidSubjectAlternativeName,
		Critical: false,
		Value:    []byte{0x30, 0x01, 0xa0}, // A sequence containing an incomplete GeneralName.
	}}
	principal, err := PrincipalFromCertificate(&certificate)
	requirePKU2UError[asn1.SyntaxError](t, err, "read PKU2U certificate principal names:")
	if len(principal.NameString) != 0 {
		t.Fatal("invalid SAN fell back to the subject")
	}
}

func testCertificate(t *testing.T, subject pkix.Name, san []byte) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: subject,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if san != nil {
		template.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAlternativeName, Value: san}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate
}

func upnSAN(t *testing.T, upn string) []byte {
	t.Helper()
	upnDER, err := asn1.MarshalWithParams(upn, "utf8")
	if err != nil {
		t.Fatal(err)
	}
	typeDER, err := asn1.Marshal(oidUPN)
	if err != nil {
		t.Fatal(err)
	}
	valueDER, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: upnDER})
	if err != nil {
		t.Fatal(err)
	}
	otherName, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: append(typeDER, valueDER...)})
	if err != nil {
		t.Fatal(err)
	}
	san, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true, Bytes: otherName})
	if err != nil {
		t.Fatal(err)
	}
	return san
}
