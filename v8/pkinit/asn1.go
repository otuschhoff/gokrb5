package pkinit

import (
	"bytes"
	"fmt"
	"math"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/types"
)

var (
	OIDPKINITAuthData   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 1}
	OIDPKINITDHKeyData  = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 2}
	OIDPKINITRKeyData   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 3}
	OIDPKINITClientAuth = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 4}
	OIDPKINITKDC        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 5}
	OIDPKINITSAN        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 2}
	OIDKDFSHA1          = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 6, 1}
	OIDKDFSHA256        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 6, 2}
	OIDKDFSHA512        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 6, 3}
	OIDKDFSHA384        = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 3, 6, 4}
)

// AlgorithmIdentifier identifies a PKIX or CMS algorithm and its parameters.
type AlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

// SubjectPublicKeyInfo carries a public key and its algorithm parameters.
type SubjectPublicKeyInfo struct {
	Algorithm        AlgorithmIdentifier
	SubjectPublicKey asn1.BitString
}

// ExternalPrincipalIdentifier identifies a certificate or principal key.
type ExternalPrincipalIdentifier struct {
	SubjectName          []byte `asn1:"optional,tag:0"`
	IssuerAndSerial      []byte `asn1:"optional,tag:1"`
	SubjectKeyIdentifier []byte `asn1:"optional,tag:2"`
}

// PAPKAsReq is the PA-PK-AS-REQ value from RFC 4556.
type PAPKAsReq struct {
	SignedAuthPack    []byte                        `asn1:"tag:0"`
	TrustedCertifiers []ExternalPrincipalIdentifier `asn1:"optional,explicit,tag:1"`
	KDCPkID           []byte                        `asn1:"optional,tag:2"`
}

// KDFAlgorithmID identifies an RFC 8636 PKINIT KDF.
type KDFAlgorithmID struct {
	ID asn1.ObjectIdentifier `asn1:"explicit,tag:0"`
}

// AuthPack is signed by the client in PA-PK-AS-REQ.
type AuthPack struct {
	PKAuthenticator   PKAuthenticator       `asn1:"explicit,tag:0"`
	ClientPublicValue *SubjectPublicKeyInfo `asn1:"optional,explicit,tag:1"`
	SupportedCMSTypes []AlgorithmIdentifier `asn1:"optional,explicit,tag:2"`
	ClientDHNonce     []byte                `asn1:"optional,explicit,tag:3"`
	SupportedKDFs     []KDFAlgorithmID      `asn1:"optional,explicit,tag:4"`
}

// PKAuthenticator binds a signed PKINIT request to its KDC request body.
type PKAuthenticator struct {
	CUSec          int       `asn1:"explicit,tag:0"`
	CTime          time.Time `asn1:"generalized,explicit,tag:1"`
	Nonce          int64     `asn1:"explicit,tag:2"`
	PAChecksum     []byte    `asn1:"optional,explicit,tag:3"`
	FreshnessToken []byte    `asn1:"optional,explicit,tag:4"`
}

// DHRepInfo carries the KDC's signed DH public value and negotiated KDF.
type DHRepInfo struct {
	DHSignedData  []byte          `asn1:"tag:0"`
	ServerDHNonce []byte          `asn1:"optional,explicit,tag:1"`
	KDF           *KDFAlgorithmID `asn1:"optional,explicit,tag:2"`
}

// PAPKAsRep is the PA-PK-AS-REP CHOICE. Exactly one field must be set.
type PAPKAsRep struct {
	DHInfo     *DHRepInfo
	EncKeyPack []byte
}

// KDCDHKeyInfo is the signed KDC DH contribution.
type KDCDHKeyInfo struct {
	SubjectPublicKey asn1.BitString `asn1:"explicit,tag:0"`
	Nonce            int64          `asn1:"explicit,tag:1"`
	DHKeyExpiration  time.Time      `asn1:"optional,generalized,explicit,tag:2"`
}

// ReplyKeyPack carries an RSA-delivered AS reply key and request checksum.
type ReplyKeyPack struct {
	ReplyKey   types.EncryptionKey `asn1:"explicit,tag:0"`
	ASChecksum types.Checksum      `asn1:"explicit,tag:1"`
}

// KRB5PrincipalName is the id-pkinit-san principal representation.
type KRB5PrincipalName struct {
	Realm         string              `asn1:"generalstring,explicit,tag:0"`
	PrincipalName types.PrincipalName `asn1:"explicit,tag:1"`
}

type TDDHParameters []AlgorithmIdentifier
type TDTrustedCertifiers []ExternalPrincipalIdentifier
type TDInvalidCertificates []ExternalPrincipalIdentifier
type TDCMSDigestAlgorithms []AlgorithmIdentifier

// TDCertDigestAlgorithms carries acceptable and rejected certificate digests.
type TDCertDigestAlgorithms struct {
	AllowedAlgorithms []AlgorithmIdentifier `asn1:"explicit,tag:0"`
	RejectedAlgorithm *AlgorithmIdentifier  `asn1:"optional,explicit,tag:1"`
}

// OtherInfo is the RFC 8636 structured KDF context.
type OtherInfo struct {
	AlgorithmID  AlgorithmIdentifier
	PartyUInfo   []byte `asn1:"explicit,tag:0"`
	PartyVInfo   []byte `asn1:"explicit,tag:1"`
	SuppPubInfo  []byte `asn1:"optional,explicit,tag:2"`
	SuppPrivInfo []byte `asn1:"optional,explicit,tag:3"`
}

// PKINITSuppPubInfo binds an RFC 8636 KDF result to the exchange.
type PKINITSuppPubInfo struct {
	EType   int32  `asn1:"explicit,tag:0"`
	ASReq   []byte `asn1:"explicit,tag:1"`
	PKASRep []byte `asn1:"explicit,tag:2"`
}

func strictUnmarshal(b []byte, value interface{}) error {
	rest, err := asn1.Unmarshal(b, value)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("PKINIT value contains %d trailing bytes", len(rest))
	}
	return nil
}

func (m PAPKAsReq) Marshal() ([]byte, error)  { return asn1.Marshal(m) }
func (m *PAPKAsReq) Unmarshal(b []byte) error { return strictUnmarshal(b, m) }
func marshalExplicit(tag int, value interface{}) ([]byte, error) {
	inner, err := asn1.Marshal(value)
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: tag, IsCompound: true, Bytes: inner})
}

func marshalSequence(fields ...[]byte) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class: asn1.ClassUniversal, Tag: asn1.TagSequence, IsCompound: true,
		Bytes: bytes.Join(fields, nil),
	})
}

func sequenceFields(b []byte) ([]asn1.RawValue, error) {
	var sequence asn1.RawValue
	if err := strictUnmarshal(b, &sequence); err != nil {
		return nil, err
	}
	if sequence.Class != asn1.ClassUniversal || sequence.Tag != asn1.TagSequence || !sequence.IsCompound {
		return nil, fmt.Errorf("PKINIT value is not a DER SEQUENCE")
	}
	var fields []asn1.RawValue
	rest := sequence.Bytes
	lastTag := -1
	for len(rest) > 0 {
		var field asn1.RawValue
		var err error
		rest, err = asn1.Unmarshal(rest, &field)
		if err != nil {
			return nil, err
		}
		if field.Class != asn1.ClassContextSpecific {
			return nil, fmt.Errorf("PKINIT field has class %d, want context-specific", field.Class)
		}
		if field.Tag <= lastTag {
			return nil, fmt.Errorf("PKINIT field tag %d is duplicated or out of order", field.Tag)
		}
		lastTag = field.Tag
		fields = append(fields, field)
	}
	return fields, nil
}

func unmarshalExplicit(field asn1.RawValue, value interface{}) error {
	if !field.IsCompound {
		return fmt.Errorf("PKINIT field [%d] is not explicit", field.Tag)
	}
	return strictUnmarshal(field.Bytes, value)
}

func (m AuthPack) Marshal() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	fields := make([][]byte, 0, 5)
	field, err := marshalExplicit(0, m.PKAuthenticator)
	if err != nil {
		return nil, err
	}
	fields = append(fields, field)
	if m.ClientPublicValue != nil {
		field, err = marshalExplicit(1, *m.ClientPublicValue)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	if len(m.SupportedCMSTypes) > 0 {
		field, err = marshalExplicit(2, m.SupportedCMSTypes)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	if len(m.ClientDHNonce) > 0 {
		field, err = marshalExplicit(3, m.ClientDHNonce)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	if len(m.SupportedKDFs) > 0 {
		field, err = marshalExplicit(4, m.SupportedKDFs)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	return marshalSequence(fields...)
}

func (m *AuthPack) Unmarshal(b []byte) error {
	fields, err := sequenceFields(b)
	if err != nil {
		return err
	}
	*m = AuthPack{}
	for _, field := range fields {
		switch field.Tag {
		case 0:
			if err := unmarshalExplicit(field, &m.PKAuthenticator); err != nil {
				return err
			}
		case 1:
			var value SubjectPublicKeyInfo
			if err := unmarshalExplicit(field, &value); err != nil {
				return err
			}
			m.ClientPublicValue = &value
		case 2:
			if err := unmarshalExplicit(field, &m.SupportedCMSTypes); err != nil {
				return err
			}
		case 3:
			if err := unmarshalExplicit(field, &m.ClientDHNonce); err != nil {
				return err
			}
		case 4:
			if err := unmarshalExplicit(field, &m.SupportedKDFs); err != nil {
				return err
			}
		default:
			return fmt.Errorf("unsupported AuthPack field tag %d", field.Tag)
		}
	}
	return m.Validate()
}

// Validate checks PKAuthenticator constraints which ASN.1 tags cannot express.
func (m AuthPack) Validate() error {
	if m.PKAuthenticator.CUSec < 0 || m.PKAuthenticator.CUSec > 999999 {
		return fmt.Errorf("PKINIT cusec %d is outside 0..999999", m.PKAuthenticator.CUSec)
	}
	if m.PKAuthenticator.Nonce < 0 || uint64(m.PKAuthenticator.Nonce) > math.MaxUint32 {
		return fmt.Errorf("PKINIT nonce %d is outside uint32", m.PKAuthenticator.Nonce)
	}
	if len(m.PKAuthenticator.PAChecksum) == 0 {
		return fmt.Errorf("PKINIT paChecksum is required")
	}
	return nil
}

// Marshal encodes the PA-PK-AS-REP CHOICE.
func (m PAPKAsRep) Marshal() ([]byte, error) {
	if (m.DHInfo == nil) == (m.EncKeyPack == nil) {
		return nil, fmt.Errorf("PA-PK-AS-REP must contain exactly one reply choice")
	}
	if m.DHInfo != nil {
		inner, err := m.DHInfo.Marshal()
		if err != nil {
			return nil, err
		}
		return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, IsCompound: true, Bytes: inner})
	}
	return asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: m.EncKeyPack})
}

// Unmarshal decodes one supported PA-PK-AS-REP CHOICE arm.
func (m *PAPKAsRep) Unmarshal(b []byte) error {
	var raw asn1.RawValue
	if err := strictUnmarshal(b, &raw); err != nil {
		return err
	}
	if raw.Class != asn1.ClassContextSpecific {
		return fmt.Errorf("PA-PK-AS-REP has class %d, want context-specific", raw.Class)
	}
	m.DHInfo = nil
	m.EncKeyPack = nil
	switch raw.Tag {
	case 0:
		if !raw.IsCompound {
			return fmt.Errorf("PA-PK-AS-REP dhInfo is not constructed")
		}
		var info DHRepInfo
		if err := info.Unmarshal(raw.Bytes); err != nil {
			return fmt.Errorf("decode PA-PK-AS-REP dhInfo: %w", err)
		}
		m.DHInfo = &info
	case 1:
		if raw.IsCompound {
			return fmt.Errorf("PA-PK-AS-REP encKeyPack is constructed")
		}
		m.EncKeyPack = append([]byte(nil), raw.Bytes...)
	default:
		return fmt.Errorf("unsupported PA-PK-AS-REP choice tag %d", raw.Tag)
	}
	return nil
}

// Marshal encodes DHRepInfo with its RFC 8636 optional KDF extension.
func (m DHRepInfo) Marshal() ([]byte, error) {
	if len(m.DHSignedData) == 0 {
		return nil, fmt.Errorf("PKINIT dhSignedData is required")
	}
	field, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: m.DHSignedData})
	if err != nil {
		return nil, err
	}
	fields := [][]byte{field}
	if len(m.ServerDHNonce) > 0 {
		field, err = marshalExplicit(1, m.ServerDHNonce)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	if m.KDF != nil {
		field, err = marshalExplicit(2, *m.KDF)
		if err != nil {
			return nil, err
		}
		fields = append(fields, field)
	}
	return marshalSequence(fields...)
}

// Unmarshal decodes DHRepInfo and rejects unknown or malformed extensions.
func (m *DHRepInfo) Unmarshal(b []byte) error {
	fields, err := sequenceFields(b)
	if err != nil {
		return err
	}
	*m = DHRepInfo{}
	for _, field := range fields {
		switch field.Tag {
		case 0:
			if field.IsCompound {
				return fmt.Errorf("PKINIT dhSignedData is constructed")
			}
			m.DHSignedData = append([]byte(nil), field.Bytes...)
		case 1:
			if err := unmarshalExplicit(field, &m.ServerDHNonce); err != nil {
				return err
			}
		case 2:
			var kdf KDFAlgorithmID
			if err := unmarshalExplicit(field, &kdf); err != nil {
				return err
			}
			m.KDF = &kdf
		default:
			return fmt.Errorf("unsupported DHRepInfo field tag %d", field.Tag)
		}
	}
	if len(m.DHSignedData) == 0 {
		return fmt.Errorf("PKINIT dhSignedData is required")
	}
	return nil
}

func (m KDCDHKeyInfo) Marshal() ([]byte, error) {
	if m.Nonce < 0 || uint64(m.Nonce) > math.MaxUint32 {
		return nil, fmt.Errorf("PKINIT nonce %d is outside uint32", m.Nonce)
	}
	return asn1.Marshal(m)
}

func (m *KDCDHKeyInfo) Unmarshal(b []byte) error {
	if err := strictUnmarshal(b, m); err != nil {
		return err
	}
	if m.Nonce < 0 || uint64(m.Nonce) > math.MaxUint32 {
		return fmt.Errorf("PKINIT nonce %d is outside uint32", m.Nonce)
	}
	return nil
}

func (m ReplyKeyPack) Marshal() ([]byte, error)  { return asn1.Marshal(m) }
func (m *ReplyKeyPack) Unmarshal(b []byte) error { return strictUnmarshal(b, m) }
