package pkinit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- independent check of the SHA-1 wire field defined by RFC 4556.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"
	"time"

	goforkasn1 "github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/config"
	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const clientTestRealm = "EXAMPLE.COM"

func TestProcessReplyRejectsNilExchange(t *testing.T) {
	encoded, err := (PAPKAsRep{
		DHInfo:     &DHRepInfo{DHSignedData: []byte{1}, ServerDHNonce: nil, KDF: nil},
		EncKeyPack: nil,
	}).Marshal()
	require.NoError(t, err)

	var exchange *Exchange
	_, err = exchange.ProcessReply(encoded, etypeID.AES256_CTS_HMAC_SHA1_96)
	require.ErrorContains(t, err, "exchange is nil")
}

func TestBeginExchangeBuildsBoundAuthPack(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	identity, err := NewIdentity(certificate, nil, key, true)
	require.NoError(t, err)
	req := testASRequest(t)
	bodyDER, err := req.ReqBody.Marshal()
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Microsecond)
	var options ExchangeOptions
	options.Identity = identity
	options.CurrentTime = now
	_, err = BeginExchange(&req, options)
	require.NoError(t, err)
	require.True(t, req.PAData.Contains(patype.PA_PK_AS_REQ))

	var request PAPKAsReq
	require.NoError(t, request.Unmarshal(req.PAData[len(req.PAData)-1].PADataValue))
	verified, err := VerifySignedData(request.SignedAuthPack, OIDPKINITAuthData)
	require.NoError(t, err)
	var authPack AuthPack
	require.NoError(t, authPack.Unmarshal(verified.Content))
	wantChecksum := sha1.Sum(bodyDER) // #nosec G401 -- RFC 4556 requires this expected wire digest.
	require.Equal(t, wantChecksum[:], authPack.PKAuthenticator.PAChecksum)
	require.Equal(t, int64(req.ReqBody.Nonce), authPack.PKAuthenticator.Nonce)
	require.Len(t, authPack.ClientDHNonce, 32)
	require.NotNil(t, authPack.ClientPublicValue)
}

func TestBeginExchangeRejectsUntrustedIdentityName(t *testing.T) {
	certificate, key := testClientCertificate(t, "bob@EXAMPLE.COM", oidClientAuth)
	identity, err := NewIdentity(certificate, nil, key, true)
	require.NoError(t, err)
	var req messages.ASReq
	req.ReqBody.Realm = clientTestRealm
	req.ReqBody.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	var options ExchangeOptions
	options.Identity = identity
	_, err = BeginExchange(&req, options)
	require.ErrorContains(t, err, "does not identify")
}

func TestProcessDHReply(t *testing.T) {
	identityCertificate, identityKey := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	identity, err := NewIdentity(identityCertificate, nil, identityKey, true)
	require.NoError(t, err)
	root, kdcCertificate, kdcKey := testKDCChain(
		t, asn1.ObjectIdentifier(OIDPKINITKDC), "example.com", time.Now().Add(time.Hour),
	)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	req := testASRequest(t)
	options := testTrustedKDCOptions(identity, anchors, ModeDH)
	exchange, err := BeginExchange(&req, options)
	require.NoError(t, err)

	serverKey, err := GenerateDHKey(MODPGroup14, 2048, rand.Reader)
	require.NoError(t, err)
	serverPublic, err := serverKey.PublicKey()
	require.NoError(t, err)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	keyInfoDER, err := (KDCDHKeyInfo{
		SubjectPublicKey: serverPublic.SubjectPublicKey,
		Nonce:            0,
		DHKeyExpiration:  expires,
	}).Marshal()
	require.NoError(t, err)
	signedKeyInfo, err := SignSignedData(OIDPKINITDHKeyData, keyInfoDER, []*x509.Certificate{kdcCertificate}, kdcKey)
	require.NoError(t, err)
	serverNonce := []byte("0123456789abcdef0123456789abcdef")
	replyDER, err := (PAPKAsRep{
		DHInfo:     &DHRepInfo{DHSignedData: signedKeyInfo, ServerDHNonce: serverNonce, KDF: nil},
		EncKeyPack: nil,
	}).Marshal()
	require.NoError(t, err)
	result, err := exchange.ProcessReply(replyDER, etypeID.AES256_CTS_HMAC_SHA1_96)
	require.NoError(t, err)

	clientPublic, err := exchange.dhKey.PublicKey()
	require.NoError(t, err)
	secret, err := serverKey.SharedSecret(clientPublic)
	require.NoError(t, err)
	want, err := DeriveLegacyReplyKey(secret, exchange.clientNonce, serverNonce, etypeID.AES256_CTS_HMAC_SHA1_96)
	require.NoError(t, err)
	require.Equal(t, want, result.ReplyKey)
	require.Equal(t, expires, result.DHKeyExpiration)
}

func TestAcceptExchangeAgreesOnDHReplyKey(t *testing.T) {
	clientCertificate, clientKey := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	clientIdentity, err := NewIdentity(clientCertificate, nil, clientKey, true)
	require.NoError(t, err)
	root, serverCertificate, serverKey := testKDCChain(
		t, asn1.ObjectIdentifier(OIDPKINITKDC), "example.com", time.Now().Add(time.Hour),
	)
	serverIdentity, err := NewIdentity(serverCertificate, nil, serverKey, false)
	require.NoError(t, err)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	req := testASRequest(t)
	clientOptions := testTrustedKDCOptions(clientIdentity, anchors, ModeDH)
	clientExchange, err := BeginExchange(&req, clientOptions)
	require.NoError(t, err)
	var serverOptions AcceptorOptions
	serverOptions.Identity = serverIdentity
	serverOptions.ValidateSigner = func(signed *VerifiedSignedData) error {
		if signed.Signer == nil || !signed.Signer.Equal(clientCertificate) {
			return errors.New("unexpected client signer")
		}
		return nil
	}
	acceptor, err := AcceptExchange(&req, serverOptions)
	require.NoError(t, err)
	clientResult, err := clientExchange.ProcessReply(acceptor.ReplyPAData, acceptor.ReplyKey.KeyType)
	require.NoError(t, err)
	require.Equal(t, acceptor.ReplyKey, clientResult.ReplyKey)
}

func TestAcceptExchangeRejectsInvalidRequests(t *testing.T) {
	clientCertificate, clientKey := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	clientIdentity, err := NewIdentity(clientCertificate, nil, clientKey, true)
	require.NoError(t, err)
	_, serverCertificate, serverKey := testKDCChain(
		t, asn1.ObjectIdentifier(OIDPKINITKDC), "example.com", time.Now().Add(time.Hour),
	)
	serverIdentity, err := NewIdentity(serverCertificate, nil, serverKey, false)
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Second)
	var serverOptions AcceptorOptions
	serverOptions.Identity = serverIdentity
	serverOptions.CurrentTime = now
	serverOptions.ClockSkew = time.Minute
	serverOptions.ValidateSigner = func(*VerifiedSignedData) error { return nil }
	accept := func(request *messages.ASReq) error {
		_, err := AcceptExchange(request, serverOptions)
		return err
	}
	var clientOptions ExchangeOptions
	clientOptions.Identity = clientIdentity
	clientOptions.CurrentTime = now

	t.Run("missing PA-PK-AS-REQ", func(t *testing.T) {
		request := testASRequest(t)
		require.ErrorContains(t, accept(&request), "missing PA-PK-AS-REQ")
	})
	t.Run("duplicate PA-PK-AS-REQ", func(t *testing.T) {
		request := beginTestASRequest(t, clientOptions)
		request.PAData = append(request.PAData, request.PAData[len(request.PAData)-1])
		require.ErrorContains(t, accept(&request), "duplicate")
	})
	t.Run("stale authenticator", func(t *testing.T) {
		options := clientOptions
		options.CurrentTime = now.Add(-2 * time.Minute)
		request := beginTestASRequest(t, options)
		require.ErrorContains(t, accept(&request), "clock skew")
	})
	t.Run("request body changed", func(t *testing.T) {
		request := beginTestASRequest(t, clientOptions)
		request.ReqBody.Nonce++
		require.ErrorContains(t, accept(&request), "does not bind")
	})
	t.Run("unsupported KDF", func(t *testing.T) {
		options := clientOptions
		options.SupportedKDFs = []KDFAlgorithmID{{ID: goforkasn1.ObjectIdentifier{1, 2, 3}}}
		request := beginTestASRequest(t, options)
		require.ErrorContains(t, accept(&request), "no supported KDF")
	})
	t.Run("RC4 only", func(t *testing.T) {
		request := testASRequest(t)
		request.ReqBody.EType = []int32{etypeID.RC4_HMAC}
		_, err := BeginExchange(&request, clientOptions)
		require.NoError(t, err)
		require.ErrorContains(t, accept(&request), "no supported AES")
	})
}

func TestProcessRSAReply(t *testing.T) {
	certificate, privateKey := testRSAIdentityCertificate(t)
	identity, err := NewIdentity(certificate, nil, privateKey, true)
	require.NoError(t, err)
	root, kdcCertificate, kdcKey := testKDCChain(
		t, asn1.ObjectIdentifier(OIDPKINITKDC), "example.com", time.Now().Add(time.Hour),
	)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	req := testASRequest(t)
	options := testTrustedKDCOptions(identity, anchors, ModeRSA)
	exchange, err := BeginExchange(&req, options)
	require.NoError(t, err)
	et, err := krbcrypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	require.NoError(t, err)
	replyKey := types.EncryptionKey{KeyType: et.GetETypeID(), KeyValue: make([]byte, et.GetKeyByteSize())}
	_, err = rand.Read(replyKey.KeyValue)
	require.NoError(t, err)
	checksum, err := et.GetChecksumHash(
		replyKey.KeyValue, exchange.request, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM,
	)
	require.NoError(t, err)
	packDER, err := (ReplyKeyPack{
		ReplyKey:   replyKey,
		ASChecksum: types.Checksum{CksumType: et.GetHashID(), Checksum: checksum},
	}).Marshal()
	require.NoError(t, err)
	signedPack, err := SignSignedData(OIDPKINITRKeyData, packDER, []*x509.Certificate{kdcCertificate}, kdcKey)
	require.NoError(t, err)
	encrypted, err := EncryptEnvelopedData(signedPack, certificate, AES256CBC)
	require.NoError(t, err)
	replyDER, err := (PAPKAsRep{DHInfo: nil, EncKeyPack: encrypted}).Marshal()
	require.NoError(t, err)
	result, err := exchange.ProcessReply(replyDER, replyKey.KeyType)
	require.NoError(t, err)
	require.Equal(t, replyKey, result.ReplyKey)
}

func testTrustedKDCOptions(identity *Identity, roots *x509.CertPool, mode Mode) ExchangeOptions {
	var options ExchangeOptions
	options.Identity = identity
	options.Mode = mode
	options.KDCCertificate.Roots = roots
	options.KDCCertificate.Realm = clientTestRealm
	return options
}

func testASRequest(t *testing.T) messages.ASReq {
	t.Helper()
	principal := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	req, err := messages.NewASReqForTGT(clientTestRealm, config.New(), principal)
	require.NoError(t, err)
	return req
}

func beginTestASRequest(t *testing.T, options ExchangeOptions) messages.ASReq {
	t.Helper()
	req := testASRequest(t)
	_, err := BeginExchange(&req, options)
	require.NoError(t, err)
	return req
}

func testRSAIdentityCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	var template x509.Certificate
	template.SerialNumber = big.NewInt(55)
	template.Subject.CommonName = "Alice"
	template.NotBefore = now.Add(-time.Hour)
	template.NotAfter = now.Add(time.Hour)
	template.KeyUsage = x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	template.ExtraExtensions = []pkix.Extension{
		{Id: oidExtendedKeyUsage, Critical: false, Value: mustMarshal(t, []asn1.ObjectIdentifier{oidClientAuth})},
		{Id: oidSubjectAlternativeName, Critical: false, Value: testUPNSAN(t, "alice@EXAMPLE.COM")},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate, privateKey
}
