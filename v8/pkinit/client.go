package pkinit

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505 -- RFC 4556 fixes the PKAuthenticator request-body digest.
	"crypto/x509"
	"errors"
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

const (
	defaultMinimumDHBits = 2048
	clientDHNonceSize    = 32
	defaultAcceptorSkew  = 5 * time.Minute
	microsecondsInSecond = int(time.Second / time.Microsecond)
)

// Mode selects the PKINIT reply-key transport.
type Mode int

const (
	// ModeDH is Diffie-Hellman key exchange mode (RFC 4556).
	ModeDH Mode = iota
	// ModeRSA is RSA encryption key transport mode (RFC 4556).
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
		return nil, errors.New("PKINIT AS request and identity are required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.CurrentTime.IsZero() {
		options.CurrentTime = time.Now().UTC()
	}
	if err := validateExchangeIdentity(&req.ReqBody, &options); err != nil {
		return nil, err
	}
	bodyDER, err := req.ReqBody.Marshal()
	if err != nil {
		return nil, fmt.Errorf("marshal PKINIT KDC request body: %w", err)
	}
	checksum := sha1.Sum(bodyDER) // #nosec G401 -- RFC 4556 paChecksum inside the signed AuthPack.
	exchange := &Exchange{
		options:     options,
		dhKey:       nil,
		clientNonce: nil,
		requestBody: bodyDER,
		request:     nil,
		client:      KRB5PrincipalName{Realm: req.ReqBody.Realm, PrincipalName: req.ReqBody.CName},
		server:      KRB5PrincipalName{Realm: req.ReqBody.Realm, PrincipalName: req.ReqBody.SName},
		nonce:       int64(req.ReqBody.Nonce),
	}
	var authPack AuthPack
	authPack.PKAuthenticator = PKAuthenticator{
		CUSec: options.CurrentTime.Nanosecond() / int(time.Microsecond), CTime: options.CurrentTime,
		Nonce: exchange.nonce, PAChecksum: checksum[:], FreshnessToken: append([]byte(nil), options.FreshnessToken...),
	}
	if err := exchange.prepareAuthPack(&authPack); err != nil {
		return nil, err
	}
	if err := exchange.addRequestPAData(req, &authPack); err != nil {
		return nil, err
	}
	return exchange, nil
}

// ProcessReply authenticates PA-PK-AS-REP and derives its AS reply key.
func (exchange *Exchange) ProcessReply(paValue []byte, replyEType int32) (*ExchangeResult, error) {
	if exchange == nil {
		return nil, errors.New("PKINIT exchange is nil")
	}
	var reply PAPKAsRep
	if err := reply.Unmarshal(paValue); err != nil {
		return nil, fmt.Errorf("decode PA-PK-AS-REP: %w", err)
	}
	if reply.DHInfo != nil {
		return exchange.processDHReply(reply.DHInfo, paValue, replyEType)
	}
	return exchange.processRSAReply(reply.EncKeyPack)
}

func validateExchangeIdentity(body *messages.KDCReqBody, options *ExchangeOptions) error {
	if options.ValidateIdentity != nil {
		return options.ValidateIdentity(options.Identity, body.CName, body.Realm)
	}
	return options.Identity.ValidateForPrincipal(body.CName, body.Realm, options.IdentityPolicy)
}

func (exchange *Exchange) prepareAuthPack(authPack *AuthPack) error {
	options := &exchange.options
	switch options.Mode {
	case ModeDH:
		if err := exchange.addClientDH(authPack); err != nil {
			return err
		}
	case ModeRSA:
	default:
		return fmt.Errorf("unsupported PKINIT mode %d", options.Mode)
	}
	var cmsType AlgorithmIdentifier
	switch options.Identity.Signer.Public().(type) {
	case *rsa.PublicKey:
		cmsType.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11} // sha256WithRSAEncryption
	case *ecdsa.PublicKey:
		cmsType.Algorithm = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2} // ecdsa-with-SHA256
	default:
		return fmt.Errorf("unsupported PKINIT signing key type %T", options.Identity.Signer.Public())
	}
	authPack.SupportedCMSTypes = []AlgorithmIdentifier{cmsType}
	if options.SupportedKDFs == nil {
		authPack.SupportedKDFs = []KDFAlgorithmID{{ID: OIDKDFSHA512}, {ID: OIDKDFSHA384}, {ID: OIDKDFSHA256}}
	} else {
		authPack.SupportedKDFs = append([]KDFAlgorithmID(nil), options.SupportedKDFs...)
	}
	return nil
}

func (exchange *Exchange) addClientDH(authPack *AuthPack) error {
	options := &exchange.options
	group := options.DHGroup
	if group == 0 {
		group = MODPGroup14
	}
	minimumBits := options.MinimumDHBits
	if minimumBits == 0 {
		minimumBits = defaultMinimumDHBits
	}
	dhKey, err := GenerateDHKey(group, minimumBits, options.Random)
	if err != nil {
		return err
	}
	exchange.dhKey = dhKey
	publicKey, err := dhKey.PublicKey()
	if err != nil {
		return err
	}
	exchange.clientNonce = make([]byte, clientDHNonceSize)
	if _, err := io.ReadFull(options.Random, exchange.clientNonce); err != nil {
		return fmt.Errorf("generate PKINIT client DH nonce: %w", err)
	}
	authPack.ClientPublicValue = &publicKey
	authPack.ClientDHNonce = append([]byte(nil), exchange.clientNonce...)
	return nil
}

func (exchange *Exchange) addRequestPAData(req *messages.ASReq, authPack *AuthPack) error {
	options := &exchange.options
	authPackDER, err := authPack.Marshal()
	if err != nil {
		return fmt.Errorf("marshal PKINIT AuthPack: %w", err)
	}
	signedAuthPack, err := SignSignedData(
		OIDPKINITAuthData,
		authPackDER,
		options.Identity.CertificateChain(),
		options.Identity.Signer,
	)
	if err != nil {
		return err
	}
	pkRequestDER, err := (PAPKAsReq{SignedAuthPack: signedAuthPack, TrustedCertifiers: nil, KDCPkID: nil}).Marshal()
	if err != nil {
		return fmt.Errorf("marshal PA-PK-AS-REQ: %w", err)
	}
	req.PAData = append(req.PAData, types.PAData{PADataType: patype.PA_PK_AS_REQ, PADataValue: pkRequestDER})
	if len(options.OCSPResponse) > 0 {
		req.PAData = append(req.PAData, types.PAData{
			PADataType:  patype.PA_PK_OCSP_RESPONSE,
			PADataValue: append([]byte(nil), options.OCSPResponse...),
		})
	}
	exchange.request, err = req.Marshal()
	if err != nil {
		return fmt.Errorf("marshal PKINIT AS request: %w", err)
	}
	return nil
}

// AcceptExchange verifies a DH PA-PK-AS-REQ and creates the corresponding
// signed PA-PK-AS-REP. Certificate trust is supplied by ValidateSigner.
func AcceptExchange(req *messages.ASReq, options AcceptorOptions) (*AcceptorResult, error) {
	if req == nil || options.Identity == nil || options.ValidateSigner == nil {
		return nil, errors.New("PKINIT AS request, acceptor identity, and signer validator are required")
	}
	options.setDefaults()
	if options.ClockSkew < 0 {
		return nil, errors.New("PKINIT clock skew must not be negative")
	}
	paValue, err := pkinitRequestPAData(req.PAData)
	if err != nil {
		return nil, err
	}
	authPack, signed, err := verifyPKINITAuthPack(paValue, options.ValidateSigner)
	if err != nil {
		return nil, err
	}
	if err = validatePKINITAuthPack(&authPack, &req.ReqBody, &options); err != nil {
		return nil, err
	}
	replyPAData, replyKey, err := buildPKINITDHReply(req, &authPack, &options)
	if err != nil {
		return nil, err
	}
	return &AcceptorResult{ReplyPAData: replyPAData, ReplyKey: replyKey, Signer: signed.Signer, AuthPack: authPack}, nil
}

func (options *AcceptorOptions) setDefaults() {
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.CurrentTime.IsZero() {
		options.CurrentTime = time.Now().UTC()
	}
	if options.ClockSkew == 0 {
		options.ClockSkew = defaultAcceptorSkew
	}
}

func pkinitRequestPAData(paData types.PADataSequence) ([]byte, error) {
	var paValue []byte
	for _, pa := range paData {
		if pa.PADataType != patype.PA_PK_AS_REQ {
			continue
		}
		if paValue != nil {
			return nil, errors.New("PKINIT AS request contains duplicate PA-PK-AS-REQ values")
		}
		paValue = pa.PADataValue
	}
	if paValue == nil {
		return nil, errors.New("PKINIT AS request is missing PA-PK-AS-REQ")
	}
	return paValue, nil
}

func verifyPKINITAuthPack(
	paValue []byte,
	validateSigner func(*VerifiedSignedData) error,
) (AuthPack, *VerifiedSignedData, error) {
	var request PAPKAsReq
	var authPack AuthPack
	if err := request.Unmarshal(paValue); err != nil {
		return authPack, nil, fmt.Errorf("decode PA-PK-AS-REQ: %w", err)
	}
	signed, err := VerifySignedData(request.SignedAuthPack, OIDPKINITAuthData)
	if err != nil {
		return authPack, nil, err
	}
	if err := validateSigner(signed); err != nil {
		return authPack, nil, err
	}
	if err := authPack.Unmarshal(signed.Content); err != nil {
		return authPack, nil, fmt.Errorf("decode PKINIT AuthPack: %w", err)
	}
	return authPack, signed, nil
}

func validatePKINITAuthPack(authPack *AuthPack, body *messages.KDCReqBody, options *AcceptorOptions) error {
	if authPack.ClientPublicValue == nil {
		return errors.New("PKINIT acceptor requires Diffie-Hellman key agreement")
	}
	auth := &authPack.PKAuthenticator
	if auth.CUSec < 0 || auth.CUSec >= microsecondsInSecond {
		return errors.New("PKINIT authenticator microseconds are invalid")
	}
	authenticatorTime := auth.CTime.Add(time.Duration(auth.CUSec) * time.Microsecond)
	delta := options.CurrentTime.Sub(authenticatorTime)
	if delta < -options.ClockSkew || delta > options.ClockSkew {
		return errors.New("PKINIT authenticator time exceeds permitted clock skew")
	}
	bodyDER, err := body.Marshal()
	if err != nil {
		return fmt.Errorf("marshal PKINIT KDC request body: %w", err)
	}
	checksum := sha1.Sum(bodyDER) // #nosec G401 -- verify the RFC 4556 paChecksum in the signed AuthPack.
	if !bytes.Equal(checksum[:], auth.PAChecksum) || auth.Nonce != int64(body.Nonce) {
		return errors.New("PKINIT AuthPack does not bind the KDC request")
	}
	return nil
}

func buildPKINITDHReply(
	req *messages.ASReq,
	authPack *AuthPack,
	options *AcceptorOptions,
) ([]byte, types.EncryptionKey, error) {
	var replyKey types.EncryptionKey
	minimumBits := options.MinimumDHBits
	if minimumBits == 0 {
		minimumBits = defaultMinimumDHBits
	}
	serverKey, err := GenerateDHKeyForPeer(*authPack.ClientPublicValue, minimumBits, options.Random)
	if err != nil {
		return nil, replyKey, err
	}
	secret, err := serverKey.SharedSecret(*authPack.ClientPublicValue)
	if err != nil {
		return nil, replyKey, err
	}
	replyEType, err := selectPKINITReplyEType(req.ReqBody.EType)
	if err != nil {
		return nil, replyKey, err
	}
	kdf, err := selectPKINITKDF(authPack.SupportedKDFs)
	if err != nil {
		return nil, replyKey, err
	}
	replyPAData, err := marshalPKINITDHReply(serverKey, int64(req.ReqBody.Nonce), &kdf, options.Identity)
	if err != nil {
		return nil, replyKey, err
	}
	requestDER, err := req.Marshal()
	if err != nil {
		return nil, replyKey, fmt.Errorf("marshal PKINIT AS request: %w", err)
	}
	replyKey, err = DeriveReplyKey(
		kdf,
		secret,
		KRB5PrincipalName{Realm: req.ReqBody.Realm, PrincipalName: req.ReqBody.CName},
		KRB5PrincipalName{Realm: req.ReqBody.Realm, PrincipalName: req.ReqBody.SName},
		requestDER,
		replyPAData,
		replyEType,
	)
	if err != nil {
		return nil, replyKey, err
	}
	return replyPAData, replyKey, nil
}

func marshalPKINITDHReply(serverKey *DHKey, nonce int64, kdf *KDFAlgorithmID, identity *Identity) ([]byte, error) {
	serverPublic, err := serverKey.PublicKey()
	if err != nil {
		return nil, err
	}
	keyInfoDER, err := (KDCDHKeyInfo{
		SubjectPublicKey: serverPublic.SubjectPublicKey,
		Nonce:            nonce,
		DHKeyExpiration:  time.Time{},
	}).Marshal()
	if err != nil {
		return nil, err
	}
	signedKeyInfo, err := SignSignedData(OIDPKINITDHKeyData, keyInfoDER, identity.CertificateChain(), identity.Signer)
	if err != nil {
		return nil, err
	}
	return (PAPKAsRep{
		DHInfo:     &DHRepInfo{DHSignedData: signedKeyInfo, ServerDHNonce: nil, KDF: kdf},
		EncKeyPack: nil,
	}).Marshal()
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
	return 0, errors.New("PKINIT request offers no supported AES encryption type")
}

func selectPKINITKDF(offered []KDFAlgorithmID) (KDFAlgorithmID, error) {
	for _, preferred := range []asn1.ObjectIdentifier{OIDKDFSHA512, OIDKDFSHA384, OIDKDFSHA256, OIDKDFSHA1} {
		for _, candidate := range offered {
			if candidate.ID.Equal(preferred) {
				return KDFAlgorithmID{ID: append(asn1.ObjectIdentifier(nil), preferred...)}, nil
			}
		}
	}
	return KDFAlgorithmID{}, errors.New("PKINIT request offers no supported KDF")
}

func (exchange *Exchange) processDHReply(reply *DHRepInfo, paValue []byte, replyEType int32) (*ExchangeResult, error) {
	if exchange.dhKey == nil {
		return nil, errors.New("KDC returned a DH reply to an RSA PKINIT request")
	}
	signed, err := VerifySignedData(reply.DHSignedData, OIDPKINITDHKeyData)
	if err != nil {
		return nil, err
	}
	if err = exchange.validateDHKDCSigner(signed); err != nil {
		return nil, err
	}
	var keyInfo KDCDHKeyInfo
	if ierr := keyInfo.Unmarshal(signed.Content); ierr != nil {
		return nil, fmt.Errorf("decode PKINIT KDC DH key info: %w", ierr)
	}
	if err = exchange.validateDHKeyInfo(&keyInfo, reply.ServerDHNonce, replyEType); err != nil {
		return nil, err
	}
	clientPublic, err := exchange.dhKey.PublicKey()
	if err != nil {
		return nil, err
	}
	secret, err := exchange.dhKey.SharedSecret(SubjectPublicKeyInfo{
		Algorithm:        clientPublic.Algorithm,
		SubjectPublicKey: keyInfo.SubjectPublicKey,
	})
	if err != nil {
		return nil, err
	}
	var replyKey types.EncryptionKey
	if reply.KDF == nil {
		replyKey, err = DeriveLegacyReplyKey(secret, exchange.clientNonce, reply.ServerDHNonce, replyEType)
	} else {
		replyKey, err = DeriveReplyKey(
			*reply.KDF,
			secret,
			exchange.client,
			exchange.server,
			exchange.request,
			paValue,
			replyEType,
		)
	}
	if err != nil {
		return nil, err
	}
	return &ExchangeResult{ReplyKey: replyKey, KDCSigner: signed.Signer, DHKeyExpiration: keyInfo.DHKeyExpiration}, nil
}

func (exchange *Exchange) validateDHKDCSigner(signed *VerifiedSignedData) error {
	if exchange.options.ValidateKDCSigner != nil {
		return exchange.options.ValidateKDCSigner(signed)
	}
	_, err := ValidateKDCCertificate(signed, exchange.options.KDCCertificate)
	return err
}

func (exchange *Exchange) validateDHKeyInfo(keyInfo *KDCDHKeyInfo, serverNonce []byte, replyEType int32) error {
	if keyInfo.DHKeyExpiration.IsZero() {
		if keyInfo.Nonce != exchange.nonce || len(serverNonce) != 0 {
			return errors.New("PKINIT ephemeral KDC DH key has inconsistent nonce or expiration fields")
		}
		return nil
	}
	if keyInfo.Nonce != 0 || !keyInfo.DHKeyExpiration.After(exchange.options.CurrentTime) {
		return errors.New("PKINIT reused KDC DH key has an invalid nonce or expiration")
	}
	et, err := krbcrypto.GetEtype(replyEType)
	if err != nil || len(serverNonce) < et.GetKeyByteSize() {
		return errors.New("PKINIT reused KDC DH key has an insufficient server nonce")
	}
	return nil
}

func (exchange *Exchange) processRSAReply(encrypted []byte) (*ExchangeResult, error) {
	if exchange.dhKey != nil {
		return nil, errors.New("KDC returned an RSA reply to a DH PKINIT request")
	}
	decrypter, ok := exchange.options.Identity.Signer.(crypto.Decrypter)
	if !ok {
		return nil, errors.New("PKINIT RSA identity does not support decryption")
	}
	plaintext, err := DecryptEnvelopedData(encrypted, exchange.options.Identity.Certificate, decrypter)
	if err != nil {
		return nil, err
	}
	signed, err := VerifySignedData(plaintext, OIDPKINITRKeyData)
	if err != nil {
		return nil, err
	}
	if _, ierr := ValidateKDCCertificate(signed, exchange.options.KDCCertificate); ierr != nil {
		return nil, ierr
	}
	var pack ReplyKeyPack
	if ierr := pack.Unmarshal(signed.Content); ierr != nil {
		return nil, fmt.Errorf("decode PKINIT ReplyKeyPack: %w", ierr)
	}
	checksumType, err := krbcrypto.GetChksumEtype(pack.ASChecksum.CksumType)
	if err != nil || checksumType.GetETypeID() != pack.ReplyKey.KeyType {
		return nil, errors.New("PKINIT ReplyKeyPack checksum type does not match reply key")
	}
	if !checksumType.VerifyChecksum(
		pack.ReplyKey.KeyValue,
		exchange.request,
		pack.ASChecksum.Checksum,
		keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR_CHKSUM,
	) {
		return nil, errors.New("PKINIT ReplyKeyPack request checksum is invalid")
	}
	return &ExchangeResult{ReplyKey: pack.ReplyKey, KDCSigner: signed.Signer, DHKeyExpiration: time.Time{}}, nil
}
