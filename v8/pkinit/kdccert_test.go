package pkinit

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/ocsp"
)

const kdcTestRealm = "EXAMPLE.COM"

type closeErrorReader struct {
	io.Reader
}

func (closeErrorReader) Close() error { return errors.New("close failed") }

type readErrorCloser struct{}

func (readErrorCloser) Read([]byte) (int, error) { return 0, errors.New("read failed") }
func (readErrorCloser) Close() error             { return nil }

type countedRevocationBody struct {
	io.Reader
	closeErr error
	closes   int
}

func (body *countedRevocationBody) Close() error {
	body.closes++
	return body.closeErr
}

func TestReadRevocationBodyOwnsClose(t *testing.T) {
	closeErr := errors.New("injected close error")
	readErr := errors.New("injected read error")
	for _, tt := range []struct {
		name     string
		reader   io.Reader
		closeErr error
		wantErr  error
	}{
		{name: "success", reader: strings.NewReader("data"), closeErr: nil, wantErr: nil},
		{name: "close failure", reader: strings.NewReader("data"), closeErr: closeErr, wantErr: closeErr},
		{name: "read before close failure", reader: iotest.ErrReader(readErr), closeErr: closeErr, wantErr: readErr},
		{name: "oversized", reader: strings.NewReader("12345"), closeErr: nil, wantErr: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			body := &countedRevocationBody{Reader: tt.reader, closeErr: tt.closeErr, closes: 0}
			data, err := readRevocationBody(body, 4)
			if body.closes != 1 {
				t.Fatalf("Close called %d times, want 1", body.closes)
			}
			switch {
			case tt.name == "oversized":
				require.ErrorContains(t, err, "exceeds")
			case tt.wantErr != nil:
				require.ErrorIs(t, err, tt.wantErr)
				require.Nil(t, data)
			default:
				require.NoError(t, err)
				require.Equal(t, []byte("data"), data)
			}
		})
	}
}

func TestValidateKDCCertificate(t *testing.T) {
	root, signer, _ := testKDCChain(t, asn1.ObjectIdentifier(OIDPKINITKDC), "example.com", time.Now().Add(time.Hour))
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	verified := &VerifiedSignedData{Content: nil, Signer: signer, Certificates: []*x509.Certificate{signer}}
	var policy KDCCertificatePolicy
	policy.Roots = anchors
	policy.Realm = kdcTestRealm
	policy.CurrentTime = time.Now()
	chain, err := ValidateKDCCertificate(verified, policy)
	require.NoError(t, err)
	require.Len(t, chain, 2)
}

func TestValidateKDCCertificateRejectsPolicyViolations(t *testing.T) {
	root, signer, _ := testKDCChain(t, serverAuthOID(), "dc.example.com", time.Now().Add(time.Hour))
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	verified := &VerifiedSignedData{Content: nil, Signer: signer, Certificates: []*x509.Certificate{signer}}
	var policy KDCCertificatePolicy
	policy.Roots = anchors
	policy.Realm = kdcTestRealm
	policy.Hostname = "dc.example.com"
	_, err := ValidateKDCCertificate(verified, policy)
	require.ErrorContains(t, err, "lacks KDC Authentication")
	policy.Hostname = "other.example.com"
	policy.EKUChecking = KDCEKUServerAuth
	_, err = ValidateKDCCertificate(verified, policy)
	require.ErrorContains(t, err, "does not identify")
}

func TestReadRevocationBodyRejectsOversizeAndCloseErrors(t *testing.T) {
	data, err := readRevocationBody(io.NopCloser(strings.NewReader("data")), 4)
	require.NoError(t, err)
	require.Equal(t, []byte("data"), data)

	_, err = readRevocationBody(io.NopCloser(strings.NewReader("12345")), 4)
	require.ErrorContains(t, err, "exceeds")

	_, err = readRevocationBody(closeErrorReader{Reader: strings.NewReader("data")}, 4)
	require.ErrorContains(t, err, "close")

	_, err = readRevocationBody(readErrorCloser{}, 4)
	require.ErrorContains(t, err, "read")
}

func TestCheckOCSP(t *testing.T) {
	root, signer, rootKey := testRevocationChain(t)
	now := time.Now().UTC().Truncate(time.Second)
	var responseDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(responseDER)
	}))
	defer server.Close()
	signer.OCSPServer = []string{server.URL}

	responseDER = mustOCSPResponse(t, root, signer, rootKey, ocsp.Good, now)
	checked, err := checkOCSP(server.Client(), signer, root, now)
	require.NoError(t, err)
	require.True(t, checked)

	responseDER = mustOCSPResponse(t, root, signer, rootKey, ocsp.Revoked, now)
	checked, err = checkOCSP(server.Client(), signer, root, now)
	require.ErrorContains(t, err, "revoked")
	require.False(t, checked)
}

func TestCheckCRLs(t *testing.T) {
	root, signer, rootKey := testRevocationChain(t)
	now := time.Now().UTC().Truncate(time.Second)
	var responseDER []byte
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(responseDER)
	}))
	defer server.Close()
	signer.CRLDistributionPoints = []string{server.URL}

	responseDER = mustCRL(t, root, rootKey, now, nil)
	checked, err := checkCRLs(server.Client(), signer, root, now)
	require.NoError(t, err)
	require.True(t, checked)

	var entry x509.RevocationListEntry
	entry.SerialNumber = signer.SerialNumber
	entry.RevocationTime = now.Add(-time.Minute)
	responseDER = mustCRL(t, root, rootKey, now, []x509.RevocationListEntry{entry})
	checked, err = checkCRLs(server.Client(), signer, root, now)
	require.ErrorContains(t, err, "revoked")
	require.False(t, checked)
}

func TestCheckCRLsLegacyPolicy(t *testing.T) {
	root, signer, rootKey := testRevocationChain(t)
	now := time.Now().UTC().Truncate(time.Second)
	der := mustCRL(t, root, rootKey, now, nil)
	body := encodeIdentityPEM("X509 CRL", der)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = writer.Write(body)
	}))
	defer server.Close()
	signer.CRLDistributionPoints = []string{server.URL}

	// Validation historically checks the signature without imposing CRL-signing key usage.
	issuer := *root
	issuer.KeyUsage = x509.KeyUsageCertSign
	checked, err := checkCRLs(server.Client(), signer, &issuer, now)
	require.NoError(t, err)
	require.True(t, checked)
}

func TestRevocationTimeValid(t *testing.T) {
	now := time.Now().UTC()
	require.True(t, revocationTimeValid(now, now.Add(-time.Minute), now.Add(time.Minute)))
	require.False(t, revocationTimeValid(now, now.Add(time.Minute), now.Add(2*time.Minute)))
	require.False(t, revocationTimeValid(now, now.Add(-2*time.Minute), now.Add(-time.Minute)))
	require.False(t, revocationTimeValid(now, now.Add(-time.Minute), time.Time{}))
}

func testRevocationChain(t *testing.T) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	rootTemplate := new(x509.Certificate)
	rootTemplate.SerialNumber = big.NewInt(200)
	rootTemplate.Subject.CommonName = "root"
	rootTemplate.SubjectKeyId = []byte{1, 2, 3, 4}
	rootTemplate.NotBefore = now.Add(-time.Hour)
	rootTemplate.NotAfter = now.Add(2 * time.Hour)
	rootTemplate.IsCA = true
	rootTemplate.BasicConstraintsValid = true
	rootTemplate.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	signerTemplate := new(x509.Certificate)
	signerTemplate.SerialNumber = big.NewInt(201)
	signerTemplate.Subject.CommonName = "KDC"
	signerTemplate.NotBefore = now.Add(-time.Hour)
	signerTemplate.NotAfter = now.Add(time.Hour)
	signerTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, root, &signerKey.PublicKey, rootKey)
	require.NoError(t, err)
	signer, err := x509.ParseCertificate(signerDER)
	require.NoError(t, err)
	return root, signer, rootKey
}

func mustOCSPResponse(
	t *testing.T,
	issuer, certificate *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	status int,
	now time.Time,
) []byte {
	t.Helper()
	var template ocsp.Response
	template.Status = status
	template.SerialNumber = certificate.SerialNumber
	template.ThisUpdate = now.Add(-time.Minute)
	template.NextUpdate = now.Add(time.Minute)
	template.RevokedAt = now.Add(-time.Minute)
	response, err := ocsp.CreateResponse(issuer, issuer, template, issuerKey)
	require.NoError(t, err)
	return response
}

func mustCRL(
	t *testing.T,
	issuer *x509.Certificate,
	issuerKey *ecdsa.PrivateKey,
	now time.Time,
	entries []x509.RevocationListEntry,
) []byte {
	t.Helper()
	template := new(x509.RevocationList)
	template.Number = big.NewInt(1)
	template.ThisUpdate = now.Add(-time.Minute)
	template.NextUpdate = now.Add(time.Minute)
	template.RevokedCertificateEntries = entries
	list, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	require.NoError(t, err)
	return list
}

func testKDCChain(
	t *testing.T,
	eku asn1.ObjectIdentifier,
	dnsName string,
	notAfter time.Time,
) (*x509.Certificate, *x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	signerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	now := time.Now()
	rootTemplate := new(x509.Certificate)
	rootTemplate.SerialNumber = big.NewInt(100)
	rootTemplate.Subject.CommonName = "root"
	rootTemplate.NotBefore = now.Add(-time.Hour)
	rootTemplate.NotAfter = now.Add(2 * time.Hour)
	rootTemplate.IsCA = true
	rootTemplate.BasicConstraintsValid = true
	rootTemplate.KeyUsage = x509.KeyUsageCertSign
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)
	signerTemplate := new(x509.Certificate)
	signerTemplate.SerialNumber = big.NewInt(101)
	signerTemplate.Subject.CommonName = "KDC"
	signerTemplate.DNSNames = []string{dnsName}
	signerTemplate.NotBefore = now.Add(-time.Hour)
	signerTemplate.NotAfter = notAfter
	signerTemplate.KeyUsage = x509.KeyUsageDigitalSignature
	signerTemplate.ExtraExtensions = []pkix.Extension{
		{Id: oidExtendedKeyUsage, Critical: false, Value: mustMarshal(t, []asn1.ObjectIdentifier{eku})},
	}
	signerDER, err := x509.CreateCertificate(rand.Reader, signerTemplate, root, &signerKey.PublicKey, rootKey)
	require.NoError(t, err)
	signer, err := x509.ParseCertificate(signerDER)
	require.NoError(t, err)
	return root, signer, signerKey
}
