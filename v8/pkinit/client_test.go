package pkinit

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/require"
)

func TestBeginExchangeBuildsBoundAuthPack(t *testing.T) {
	certificate, key := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	identity, err := NewIdentity(certificate, nil, key, true)
	require.NoError(t, err)
	cfg := config.New()
	req, err := messages.NewASReqForTGT("EXAMPLE.COM", cfg, types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"))
	require.NoError(t, err)
	bodyDER, err := req.ReqBody.Marshal()
	require.NoError(t, err)
	now := time.Now().UTC().Truncate(time.Microsecond)
	_, err = BeginExchange(&req, ExchangeOptions{Identity: identity, Mode: ModeDH, CurrentTime: now})
	require.NoError(t, err)
	require.True(t, req.PAData.Contains(patype.PA_PK_AS_REQ))

	var request PAPKAsReq
	require.NoError(t, request.Unmarshal(req.PAData[len(req.PAData)-1].PADataValue))
	verified, err := VerifySignedData(request.SignedAuthPack, OIDPKINITAuthData)
	require.NoError(t, err)
	var authPack AuthPack
	require.NoError(t, authPack.Unmarshal(verified.Content))
	wantChecksum := sha1.Sum(bodyDER)
	require.Equal(t, wantChecksum[:], authPack.PKAuthenticator.PAChecksum)
	require.Equal(t, int64(req.ReqBody.Nonce), authPack.PKAuthenticator.Nonce)
	require.Len(t, authPack.ClientDHNonce, 32)
	require.NotNil(t, authPack.ClientPublicValue)
}

func TestBeginExchangeRejectsUntrustedIdentityName(t *testing.T) {
	certificate, key := testClientCertificate(t, "bob@EXAMPLE.COM", oidClientAuth)
	identity, err := NewIdentity(certificate, nil, key, true)
	require.NoError(t, err)
	req := messages.ASReq{KDCReqFields: messages.KDCReqFields{ReqBody: messages.KDCReqBody{
		Realm: "EXAMPLE.COM", CName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"),
	}}}
	_, err = BeginExchange(&req, ExchangeOptions{Identity: identity})
	require.ErrorContains(t, err, "does not identify")
}

func TestProcessDHReply(t *testing.T) {
	identityCertificate, identityKey := testClientCertificate(t, "alice@EXAMPLE.COM", oidClientAuth)
	identity, err := NewIdentity(identityCertificate, nil, identityKey, true)
	require.NoError(t, err)
	root, kdcCertificate, kdcKey := testKDCChain(t, asn1.ObjectIdentifier(OIDPKINITKDC), "example.com", time.Now().Add(time.Hour))
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	req := testASRequest(t)
	exchange, err := BeginExchange(&req, ExchangeOptions{Identity: identity, Mode: ModeDH, KDCCertificate: KDCCertificatePolicy{Roots: anchors, Realm: "EXAMPLE.COM"}})
	require.NoError(t, err)

	serverKey, err := GenerateDHKey(MODPGroup14, 2048, rand.Reader)
	require.NoError(t, err)
	serverPublic, err := serverKey.PublicKey()
	require.NoError(t, err)
	expires := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	keyInfoDER, err := (KDCDHKeyInfo{SubjectPublicKey: serverPublic.SubjectPublicKey, Nonce: 0, DHKeyExpiration: expires}).Marshal()
	require.NoError(t, err)
	signedKeyInfo, err := SignSignedData(OIDPKINITDHKeyData, keyInfoDER, []*x509.Certificate{kdcCertificate}, kdcKey)
	require.NoError(t, err)
	serverNonce := []byte("0123456789abcdef0123456789abcdef")
	replyDER, err := (PAPKAsRep{DHInfo: &DHRepInfo{DHSignedData: signedKeyInfo, ServerDHNonce: serverNonce}}).Marshal()
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

func TestProcessRSAReply(t *testing.T) {
	certificate, privateKey := testRSAIdentityCertificate(t)
	identity, err := NewIdentity(certificate, nil, privateKey, true)
	require.NoError(t, err)
	root, kdcCertificate, kdcKey := testKDCChain(t, asn1.ObjectIdentifier(OIDPKINITKDC), "example.com", time.Now().Add(time.Hour))
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	req := testASRequest(t)
	exchange, err := BeginExchange(&req, ExchangeOptions{Identity: identity, Mode: ModeRSA, KDCCertificate: KDCCertificatePolicy{Roots: anchors, Realm: "EXAMPLE.COM"}})
	require.NoError(t, err)
	et, err := krbcrypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	require.NoError(t, err)
	replyKey := types.EncryptionKey{KeyType: et.GetETypeID(), KeyValue: make([]byte, et.GetKeyByteSize())}
	_, err = rand.Read(replyKey.KeyValue)
	require.NoError(t, err)
	checksum, err := et.GetChecksumHash(replyKey.KeyValue, exchange.request, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM)
	require.NoError(t, err)
	packDER, err := (ReplyKeyPack{ReplyKey: replyKey, ASChecksum: types.Checksum{CksumType: et.GetHashID(), Checksum: checksum}}).Marshal()
	require.NoError(t, err)
	signedPack, err := SignSignedData(OIDPKINITRKeyData, packDER, []*x509.Certificate{kdcCertificate}, kdcKey)
	require.NoError(t, err)
	encrypted, err := EncryptEnvelopedData(signedPack, certificate, AES256CBC)
	require.NoError(t, err)
	replyDER, err := (PAPKAsRep{EncKeyPack: encrypted}).Marshal()
	require.NoError(t, err)
	result, err := exchange.ProcessReply(replyDER, replyKey.KeyType)
	require.NoError(t, err)
	require.Equal(t, replyKey, result.ReplyKey)
}

func testASRequest(t *testing.T) messages.ASReq {
	t.Helper()
	req, err := messages.NewASReqForTGT("EXAMPLE.COM", config.New(), types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"))
	require.NoError(t, err)
	return req
}

func testRSAIdentityCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(55), Subject: pkix.Name{CommonName: "Alice"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtraExtensions: []pkix.Extension{
			{Id: oidExtendedKeyUsage, Value: mustMarshal(t, []asn1.ObjectIdentifier{oidClientAuth})},
			{Id: oidSubjectAlternativeName, Value: testUPNSAN(t, "alice@EXAMPLE.COM")},
		},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return certificate, privateKey
}
