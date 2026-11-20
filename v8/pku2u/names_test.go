package pku2u

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
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
	var subject pkix.Name
	subject.CommonName = "Alice"
	certificate := testCertificate(t, subject, upnSAN(t, "alice@example.com"))
	principal, err := PrincipalFromCertificate(certificate)
	if err != nil {
		t.Fatal(err)
	}
	if principal.NameType != nametype.KRB_NT_ENTERPRISE || principal.PrincipalNameString() != "alice@example.com" {
		t.Fatalf("principal = %#v", principal)
	}
}

func TestPrincipalFromCertificateSubjectFallback(t *testing.T) {
	var subject pkix.Name
	subject.CommonName = "Peer"
	subject.Organization = []string{"Example"}
	certificate := testCertificate(t, subject, nil)
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

func TestUPNSANFixtureDER(t *testing.T) {
	t.Parallel()

	const want = "3023a021060a2b060104018237140203a0130c11616c696365406578616d706c652e636f6d"
	if got := hex.EncodeToString(upnSAN(t, "alice@example.com")); got != want {
		t.Fatalf("UPN SAN DER = %s, want %s", got, want)
	}
}

func testCertificate(t *testing.T, subject pkix.Name, san []byte) *x509.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var template x509.Certificate
	template.SerialNumber = big.NewInt(1)
	template.Subject = subject
	template.NotBefore = time.Now().Add(-time.Hour)
	template.NotAfter = time.Now().Add(time.Hour)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	if san != nil {
		template.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAlternativeName, Critical: false, Value: san}}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
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
	valueDER := marshalConstructedDER(t, asn1.ClassContextSpecific, 0, upnDER)
	otherName := marshalConstructedDER(t, asn1.ClassContextSpecific, 0, append(typeDER, valueDER...))
	return marshalConstructedDER(t, asn1.ClassUniversal, asn1.TagSequence, otherName)
}

func marshalConstructedDER(t *testing.T, class, tag int, content []byte) []byte {
	t.Helper()

	encoded, err := asn1.Marshal(asn1.RawValue{
		Class:      class,
		Tag:        tag,
		IsCompound: true,
		Bytes:      content,
		FullBytes:  nil,
	})
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}
