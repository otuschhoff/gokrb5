package pkinit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"fmt"
	"io"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

var (
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
)

// Mode selects the PKINIT reply-key transport.
type Mode int

const (
	ModeDH Mode = iota
	ModeRSA
)

// ExchangeOptions controls one PKINIT AS exchange.
type ExchangeOptions struct {
	Identity          *Identity
	IdentityPolicy    IdentityPolicy
	ValidateIdentity  func(*Identity, types.PrincipalName, string) error
	KDCCertificate    KDCCertificatePolicy
	ValidateKDCSigner func(*VerifiedSignedData) error
	Mode              Mode
	DHGroup           int
	MinimumDHBits     int
	FreshnessToken    []byte
	OCSPResponse      []byte
	SupportedKDFs     []KDFAlgorithmID
	RequireFreshness  bool
	Random            io.Reader
	CurrentTime       time.Time
}

// AcceptorOptions controls generation of a DH PA-PK-AS-REP.
type AcceptorOptions struct {
	Identity       *Identity
	ValidateSigner func(*VerifiedSignedData) error
	MinimumDHBits  int
	Random         io.Reader
	CurrentTime    time.Time
	ClockSkew      time.Duration
}

// AcceptorResult contains the authenticated request identity and the reply
// key used to encrypt the AS-REP encrypted part.
type AcceptorResult struct {
	ReplyPAData []byte
	ReplyKey    types.EncryptionKey
	Signer      *x509.Certificate
	AuthPack    AuthPack
}

// Exchange retains the ephemeral state needed to authenticate a PKINIT reply.
type Exchange struct {
	options     ExchangeOptions
	dhKey       *DHKey
	clientNonce []byte
	requestBody []byte
	request     []byte
	client      KRB5PrincipalName
	server      KRB5PrincipalName
	nonce       int64
}

// ExchangeResult is the authenticated output of PA-PK-AS-REP processing.
type ExchangeResult struct {
	ReplyKey        types.EncryptionKey
	KDCSigner       *x509.Certificate
	DHKeyExpiration time.Time
}

// BeginExchange adds PA-PK-AS-REQ to req and captures its exact DER encoding.
func BeginExchange(req *messages.ASReq, options ExchangeOptions) (*Exchange, error) {
	if req == nil || options.Identity == nil {
		return nil, fmt.Errorf("PKINIT AS request and identity are required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.CurrentTime.IsZero() {
		options.CurrentTime = time.Now().UTC()
	}
	if options.ValidateIdentity != nil {
		if err := options.ValidateIdentity(options.Identity, req.ReqBody.CName, req.ReqBody.Realm); err != nil {
			return nil, err
		}
	} else {
		if err := options.Identity.ValidateForPrincipal(req.ReqBody.CName, req.ReqBody.Realm, options.IdentityPolicy); err != nil {
			return nil, err
		}
	}
	bodyDER, err := req.ReqBody.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT KDC request body: %w", err)
	}
	checksum := sha1.Sum(bodyDER)
	exchange := &Exchange{
		options: options, requestBody: bodyDER, nonce: int64(req.ReqBody.Nonce),
		client: KRB5PrincipalName{Realm: req.ReqBody.Realm, PrincipalName: req.ReqBody.CName},
		server: KRB5PrincipalName{Realm: req.ReqBody.Realm, PrincipalName: req.ReqBody.SName},
	}
	authPack := AuthPack{PKAuthenticator: PKAuthenticator{
		CUSec: int(options.CurrentTime.Nanosecond() / int(time.Microsecond)), CTime: options.CurrentTime,
		Nonce: exchange.nonce, PAChecksum: checksum[:], FreshnessToken: append([]byte(nil), options.FreshnessToken...),
	}}
	switch options.Mode {
	case ModeDH:
		group := options.DHGroup
		if group == 0 {
			group = MODPGroup14
		}
		minimumBits := options.MinimumDHBits
		if minimumBits == 0 {
			minimumBits = 2048
		}
		exchange.dhKey, err = GenerateDHKey(group, minimumBits, options.Random)
		if err != nil {
			return nil, err
		}
		publicKey, err := exchange.dhKey.PublicKey()
		if err != nil {
			return nil, err
		}
		exchange.clientNonce = make([]byte, 32)
		if _, err := io.ReadFull(options.Random, exchange.clientNonce); err != nil {
			return nil, fmt.Errorf("generate PKINIT client DH nonce: %w", err)
		}
		authPack.ClientPublicValue = &publicKey
		authPack.ClientDHNonce = append([]byte(nil), exchange.clientNonce...)
	case ModeRSA:
	default:
		return nil, fmt.Errorf("unsupported PKINIT mode %d", options.Mode)
	}
	switch options.Identity.Signer.Public().(type) {
	case *rsa.PublicKey:
		authPack.SupportedCMSTypes = []AlgorithmIdentifier{{Algorithm: oidSHA256WithRSA}}
	case *ecdsa.PublicKey:
		authPack.SupportedCMSTypes = []AlgorithmIdentifier{{Algorithm: oidECDSAWithSHA256}}
	default:
		return nil, fmt.Errorf("unsupported PKINIT signing key type %T", options.Identity.Signer.Public())
	}
	if options.SupportedKDFs == nil {
		authPack.SupportedKDFs = []KDFAlgorithmID{{ID: OIDKDFSHA512}, {ID: OIDKDFSHA384}, {ID: OIDKDFSHA256}}
	} else {
		authPack.SupportedKDFs = append([]KDFAlgorithmID(nil), options.SupportedKDFs...)
	}
	authPackDER, err := authPack.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT AuthPack: %w", err)
	}
	signedAuthPack, err := SignSignedData(OIDPKINITAuthData, authPackDER, options.Identity.CertificateChain(), options.Identity.Signer)
	if err != nil {
		return nil, err
	}
	pkRequestDER, err := (PAPKAsReq{SignedAuthPack: signedAuthPack}).Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PA-PK-AS-REQ: %w", err)
	}
	req.PAData = append(req.PAData, types.PAData{PADataType: patype.PA_PK_AS_REQ, PADataValue: pkRequestDER})
	if len(options.OCSPResponse) > 0 {
		req.PAData = append(req.PAData, types.PAData{PADataType: patype.PA_PK_OCSP_RESPONSE, PADataValue: append([]byte(nil), options.OCSPResponse...)})
	}
	exchange.request, err = req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT AS request: %w", err)
	}
	return exchange, nil
}

// AcceptExchange verifies a DH PA-PK-AS-REQ and creates the corresponding
// signed PA-PK-AS-REP. Certificate trust is supplied by ValidateSigner.
func AcceptExchange(req *messages.ASReq, options AcceptorOptions) (*AcceptorResult, error) {
	if req == nil || options.Identity == nil || options.ValidateSigner == nil {
		return nil, fmt.Errorf("PKINIT AS request, acceptor identity, and signer validator are required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.CurrentTime.IsZero() {
		options.CurrentTime = time.Now().UTC()
	}
	if options.ClockSkew == 0 {
		options.ClockSkew = 5 * time.Minute
	}
	if options.ClockSkew < 0 {
		return nil, fmt.Errorf("PKINIT clock skew must not be negative")
	}
	var paValue []byte
	for _, pa := range req.PAData {
		if pa.PADataType != patype.PA_PK_AS_REQ {
			continue
		}
		if paValue != nil {
			return nil, fmt.Errorf("PKINIT AS request contains duplicate PA-PK-AS-REQ values")
		}
		paValue = pa.PADataValue
	}
	if paValue == nil {
		return nil, fmt.Errorf("PKINIT AS request is missing PA-PK-AS-REQ")
	}
	var request PAPKAsReq
	if err := request.Unmarshal(paValue); err != nil {
		return nil, fmt.Errorf("decode PA-PK-AS-REQ: %w", err)
	}
	signed, err := VerifySignedData(request.SignedAuthPack, OIDPKINITAuthData)
	if err != nil {
		return nil, err
	}
	if err := options.ValidateSigner(signed); err != nil {
		return nil, err
	}
	var authPack AuthPack
	if err := authPack.Unmarshal(signed.Content); err != nil {
		return nil, fmt.Errorf("decode PKINIT AuthPack: %w", err)
	}
	if authPack.ClientPublicValue == nil {
		return nil, fmt.Errorf("PKINIT acceptor requires Diffie-Hellman key agreement")
	}
	if authPack.PKAuthenticator.CUSec < 0 || authPack.PKAuthenticator.CUSec >= 1000000 {
		return nil, fmt.Errorf("PKINIT authenticator microseconds are invalid")
	}
	authenticatorTime := authPack.PKAuthenticator.CTime.Add(time.Duration(authPack.PKAuthenticator.CUSec) * time.Microsecond)
	delta := options.CurrentTime.Sub(authenticatorTime)
	if delta < -options.ClockSkew || delta > options.ClockSkew {
		return nil, fmt.Errorf("PKINIT authenticator time exceeds permitted clock skew")
	}
	bodyDER, err := req.ReqBody.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT KDC request body: %w", err)
	}
	checksum := sha1.Sum(bodyDER)
	if !bytes.Equal(checksum[:], authPack.PKAuthenticator.PAChecksum) || authPack.PKAuthenticator.Nonce != int64(req.ReqBody.Nonce) {
		return nil, fmt.Errorf("PKINIT AuthPack does not bind the KDC request")
	}
	minimumBits := options.MinimumDHBits
	if minimumBits == 0 {
		minimumBits = 2048
	}
	serverKey, err := GenerateDHKeyForPeer(*authPack.ClientPublicValue, minimumBits, options.Random)
	if err != nil {
		return nil, err
	}
	secret, err := serverKey.SharedSecret(*authPack.ClientPublicValue)
	if err != nil {
		return nil, err
	}
	etypeID, err := selectPKINITReplyEType(req.ReqBody.EType)
	if err != nil {
		return nil, err
	}
	kdf, err := selectPKINITKDF(authPack.SupportedKDFs)
	if err != nil {
		return nil, err
	}
	serverPublic, err := serverKey.PublicKey()
	if err != nil {
		return nil, err
	}
	keyInfoDER, err := (KDCDHKeyInfo{SubjectPublicKey: serverPublic.SubjectPublicKey, Nonce: int64(req.ReqBody.Nonce)}).Marshal()
	if err != nil {
		return nil, err
	}
	signedKeyInfo, err := SignSignedData(OIDPKINITDHKeyData, keyInfoDER, options.Identity.CertificateChain(), options.Identity.Signer)
	if err != nil {
		return nil, err
	}
	replyPAData, err := (PAPKAsRep{DHInfo: &DHRepInfo{DHSignedData: signedKeyInfo, KDF: &kdf}}).Marshal()
	if err != nil {
		return nil, err
	}
	requestDER, err := req.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT AS request: %w", err)
	}
	replyKey, err := DeriveReplyKey(
		kdf, secret,
		KRB5PrincipalName{Realm: req.ReqBody.Realm, PrincipalName: req.ReqBody.CName},
		KRB5PrincipalName{Realm: req.ReqBody.Realm, PrincipalName: req.ReqBody.SName},
		requestDER, replyPAData, etypeID,
	)
	if err != nil {
		return nil, err
	}
	return &AcceptorResult{ReplyPAData: replyPAData, ReplyKey: replyKey, Signer: signed.Signer, AuthPack: authPack}, nil
}

func selectPKINITReplyEType(offered []int32) (int32, error) {
	for _, candidate := range offered {
		switch candidate {
		case etypeID.AES256_CTS_HMAC_SHA1_96,
			etypeID.AES128_CTS_HMAC_SHA1_96,
			etypeID.AES256_CTS_HMAC_SHA384_192,
			etypeID.AES128_CTS_HMAC_SHA256_128:
			return candidate, nil
		}
	}
	return 0, fmt.Errorf("PKINIT request offers no supported AES encryption type")
}

func selectPKINITKDF(offered []KDFAlgorithmID) (KDFAlgorithmID, error) {
	for _, preferred := range []asn1.ObjectIdentifier{OIDKDFSHA512, OIDKDFSHA384, OIDKDFSHA256, OIDKDFSHA1} {
		for _, candidate := range offered {
			if candidate.ID.Equal(preferred) {
				return KDFAlgorithmID{ID: append(asn1.ObjectIdentifier(nil), preferred...)}, nil
			}
		}
	}
	return KDFAlgorithmID{}, fmt.Errorf("PKINIT request offers no supported KDF")
}

// ProcessReply authenticates PA-PK-AS-REP and derives its AS reply key.
func (exchange *Exchange) ProcessReply(paValue []byte, replyEType int32) (*ExchangeResult, error) {
	var reply PAPKAsRep
	if err := reply.Unmarshal(paValue); err != nil {
		return nil, fmt.Errorf("decode PA-PK-AS-REP: %w", err)
	}
	if reply.DHInfo != nil {
		return exchange.processDHReply(reply.DHInfo, paValue, replyEType)
	}
	return exchange.processRSAReply(reply.EncKeyPack)
}

func (exchange *Exchange) processDHReply(reply *DHRepInfo, paValue []byte, replyEType int32) (*ExchangeResult, error) {
	if exchange.dhKey == nil {
		return nil, fmt.Errorf("KDC returned a DH reply to an RSA PKINIT request")
	}
	signed, err := VerifySignedData(reply.DHSignedData, OIDPKINITDHKeyData)
	if err != nil {
		return nil, err
	}
	if exchange.options.ValidateKDCSigner != nil {
		if err := exchange.options.ValidateKDCSigner(signed); err != nil {
			return nil, err
		}
	} else {
		if _, err := ValidateKDCCertificate(signed, exchange.options.KDCCertificate); err != nil {
			return nil, err
		}
	}
	var keyInfo KDCDHKeyInfo
	if err := keyInfo.Unmarshal(signed.Content); err != nil {
		return nil, fmt.Errorf("decode PKINIT KDC DH key info: %w", err)
	}
	if keyInfo.DHKeyExpiration.IsZero() {
		if keyInfo.Nonce != exchange.nonce || len(reply.ServerDHNonce) != 0 {
			return nil, fmt.Errorf("PKINIT ephemeral KDC DH key has inconsistent nonce or expiration fields")
		}
	} else {
		if keyInfo.Nonce != 0 || !keyInfo.DHKeyExpiration.After(exchange.options.CurrentTime) {
			return nil, fmt.Errorf("PKINIT reused KDC DH key has an invalid nonce or expiration")
		}
		et, err := krbcrypto.GetEtype(replyEType)
		if err != nil || len(reply.ServerDHNonce) < et.GetKeyByteSize() {
			return nil, fmt.Errorf("PKINIT reused KDC DH key has an insufficient server nonce")
		}
	}
	clientPublic, err := exchange.dhKey.PublicKey()
	if err != nil {
		return nil, err
	}
	secret, err := exchange.dhKey.SharedSecret(SubjectPublicKeyInfo{Algorithm: clientPublic.Algorithm, SubjectPublicKey: keyInfo.SubjectPublicKey})
	if err != nil {
		return nil, err
	}
	var replyKey types.EncryptionKey
	if reply.KDF == nil {
		replyKey, err = DeriveLegacyReplyKey(secret, exchange.clientNonce, reply.ServerDHNonce, replyEType)
	} else {
		replyKey, err = DeriveReplyKey(*reply.KDF, secret, exchange.client, exchange.server, exchange.request, paValue, replyEType)
	}
	if err != nil {
		return nil, err
	}
	return &ExchangeResult{ReplyKey: replyKey, KDCSigner: signed.Signer, DHKeyExpiration: keyInfo.DHKeyExpiration}, nil
}

func (exchange *Exchange) processRSAReply(encrypted []byte) (*ExchangeResult, error) {
	if exchange.dhKey != nil {
		return nil, fmt.Errorf("KDC returned an RSA reply to a DH PKINIT request")
	}
	decrypter, ok := exchange.options.Identity.Signer.(crypto.Decrypter)
	if !ok {
		return nil, fmt.Errorf("PKINIT RSA identity does not support decryption")
	}
	plaintext, err := DecryptEnvelopedData(encrypted, exchange.options.Identity.Certificate, decrypter)
	if err != nil {
		return nil, err
	}
	signed, err := VerifySignedData(plaintext, OIDPKINITRKeyData)
	if err != nil {
		return nil, err
	}
	if _, err := ValidateKDCCertificate(signed, exchange.options.KDCCertificate); err != nil {
		return nil, err
	}
	var pack ReplyKeyPack
	if err := pack.Unmarshal(signed.Content); err != nil {
		return nil, fmt.Errorf("decode PKINIT ReplyKeyPack: %w", err)
	}
	checksumType, err := krbcrypto.GetChksumEtype(pack.ASChecksum.CksumType)
	if err != nil || checksumType.GetETypeID() != pack.ReplyKey.KeyType {
		return nil, fmt.Errorf("PKINIT ReplyKeyPack checksum type does not match reply key")
	}
	if !checksumType.VerifyChecksum(pack.ReplyKey.KeyValue, exchange.request, pack.ASChecksum.Checksum, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM) {
		return nil, fmt.Errorf("PKINIT ReplyKeyPack request checksum is invalid")
	}
	return &ExchangeResult{ReplyKey: pack.ReplyKey, KDCSigner: signed.Signer}, nil
}
