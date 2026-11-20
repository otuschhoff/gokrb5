package types

import (
	"errors"
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/iana/asnAppTag"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
)

const fastReqBodyTag = 2

// KrbFastArmor identifies and carries a FAST armor value.
type KrbFastArmor struct {
	ArmorType  int32  `asn1:"explicit,tag:0"`
	ArmorValue []byte `asn1:"explicit,tag:1"`
}

// KrbFastArmoredReq carries an encrypted FAST request and its outer-body checksum.
type KrbFastArmoredReq struct {
	Armor       KrbFastArmor  `asn1:"explicit,optional,tag:0"`
	ReqChecksum Checksum      `asn1:"explicit,tag:1"`
	EncFastReq  EncryptedData `asn1:"explicit,tag:2"`
}

// KrbFastReq is the plaintext protected by KrbFastArmoredReq.
// ReqBody is a context-specific [2] RawValue containing a DER KDC-REQ-BODY.
type KrbFastReq struct {
	FastOptions asn1.BitString `asn1:"explicit,tag:0"`
	PAData      PADataSequence `asn1:"explicit,tag:1"`
	ReqBody     asn1.RawValue
}

// PAFXFastRequest is the armored-data alternative of PA-FX-FAST-REQUEST.
type PAFXFastRequest struct {
	ArmoredData KrbFastArmoredReq
}

// KrbFastArmoredRep carries an encrypted KrbFastResponse.
type KrbFastArmoredRep struct {
	EncFastRep EncryptedData `asn1:"explicit,tag:0"`
}

// PAFXFastReply is the armored-data alternative of PA-FX-FAST-REPLY.
type PAFXFastReply struct {
	ArmoredData KrbFastArmoredRep
}

// KrbFastFinished binds the FAST response to the issued ticket.
type KrbFastFinished struct {
	Timestamp      time.Time     `asn1:"generalized,explicit,tag:0"`
	Usec           int           `asn1:"explicit,tag:1"`
	CRealm         string        `asn1:"generalstring,explicit,tag:2"`
	CName          PrincipalName `asn1:"explicit,tag:3"`
	TicketChecksum Checksum      `asn1:"explicit,tag:4"`
}

// KrbFastResponse is the plaintext protected by KrbFastArmoredRep.
type KrbFastResponse struct {
	PAData        PADataSequence
	StrengthenKey EncryptionKey
	Finished      KrbFastFinished
	Nonce         uint32
}

type krbFastResponseWire struct {
	PAData        PADataSequence  `asn1:"explicit,tag:0"`
	StrengthenKey EncryptionKey   `asn1:"explicit,optional,tag:1"`
	Finished      KrbFastFinished `asn1:"explicit,optional,tag:2"`
	Nonce         int64           `asn1:"explicit,tag:3"`
}

// PAEncryptedChallenge is the encrypted challenge pre-authentication value.
type PAEncryptedChallenge EncryptedData

// PAFXError is a complete DER-encoded KRB-ERROR carried inside FAST.
type PAFXError []byte

// Marshal marshals KrbFastArmor to its DER encoding.
func (v *KrbFastArmor) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KrbFastArmor.
func (v *KrbFastArmor) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KrbFastArmoredReq to its DER encoding.
func (v *KrbFastArmoredReq) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KrbFastArmoredReq.
func (v *KrbFastArmoredReq) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KrbFastArmoredRep to its DER encoding.
func (v *KrbFastArmoredRep) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KrbFastArmoredRep.
func (v *KrbFastArmoredRep) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// Marshal marshals KrbFastFinished to its DER encoding.
func (v *KrbFastFinished) Marshal() ([]byte, error) { return marshalMSKILE(*v) }

// Unmarshal unmarshals DER bytes into KrbFastFinished.
func (v *KrbFastFinished) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }

// NewKrbFastReq assembles a KRB-FAST-REQ from its components.
func NewKrbFastReq(options asn1.BitString, paData PADataSequence, reqBody []byte) KrbFastReq {
	return KrbFastReq{
		FastOptions: options,
		PAData:      paData,
		ReqBody: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Tag:        fastReqBodyTag,
			Bytes:      append([]byte(nil), reqBody...),
			FullBytes:  nil,
		},
	}
}

// Marshal marshals KrbFastReq to its DER encoding.
func (v *KrbFastReq) Marshal() ([]byte, error) {
	if v.FastOptions.BitLength < kerberosFlagBits {
		return nil, errors.New("KrbFastReq fast-options must contain at least 32 bits")
	}
	if v.ReqBody.Class != asn1.ClassContextSpecific || v.ReqBody.Tag != fastReqBodyTag || !v.ReqBody.IsCompound {
		return nil, errors.New("KrbFastReq req-body must be an explicit context-specific tag 2")
	}
	return marshalMSKILE(*v)
}

// Unmarshal unmarshals DER bytes into KrbFastReq.
func (v *KrbFastReq) Unmarshal(b []byte) error {
	if err := unmarshalMSKILE(b, v); err != nil {
		return err
	}
	if v.ReqBody.Class != asn1.ClassContextSpecific || v.ReqBody.Tag != fastReqBodyTag || !v.ReqBody.IsCompound {
		return errors.New("KrbFastReq req-body must be an explicit context-specific tag 2")
	}
	if v.FastOptions.BitLength < kerberosFlagBits {
		return errors.New("KrbFastReq fast-options must contain at least 32 bits")
	}
	return nil
}

// Marshal marshals PAFXFastRequest to its DER encoding.
func (v *PAFXFastRequest) Marshal() ([]byte, error) {
	b, err := v.ArmoredData.Marshal()
	if err != nil {
		return nil, err
	}
	wrapped, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        0,
		Bytes:      b,
		FullBytes:  nil,
	})
	if err != nil {
		return wrapped, fmt.Errorf("encode PA-FX-FAST-REQUEST wrapper: %w", err)
	}
	return wrapped, nil
}

// Unmarshal unmarshals DER bytes into PAFXFastRequest.
func (v *PAFXFastRequest) Unmarshal(b []byte) error {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return fmt.Errorf("decode PA-FX-FAST-REQUEST wrapper: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing ASN.1 data: %d bytes", len(rest))
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 || !raw.IsCompound {
		return errors.New("PA-FX-FAST-REQUEST must contain armored-data tag 0")
	}
	return v.ArmoredData.Unmarshal(raw.Bytes)
}

// Marshal marshals PAFXFastReply to its DER encoding.
func (v *PAFXFastReply) Marshal() ([]byte, error) {
	b, err := v.ArmoredData.Marshal()
	if err != nil {
		return nil, err
	}
	wrapped, err := asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        0,
		Bytes:      b,
		FullBytes:  nil,
	})
	if err != nil {
		return wrapped, fmt.Errorf("encode PA-FX-FAST-REPLY wrapper: %w", err)
	}
	return wrapped, nil
}

// Unmarshal unmarshals DER bytes into PAFXFastReply.
func (v *PAFXFastReply) Unmarshal(b []byte) error {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return fmt.Errorf("decode PA-FX-FAST-REPLY wrapper: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing ASN.1 data: %d bytes", len(rest))
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 || !raw.IsCompound {
		return errors.New("PA-FX-FAST-REPLY must contain armored-data tag 0")
	}
	return v.ArmoredData.Unmarshal(raw.Bytes)
}

// Marshal marshals KrbFastResponse to its DER encoding.
func (v *KrbFastResponse) Marshal() ([]byte, error) {
	w := krbFastResponseWire{
		PAData:        v.PAData,
		StrengthenKey: v.StrengthenKey,
		Finished:      v.Finished,
		Nonce:         int64(v.Nonce),
	}
	return marshalMSKILE(w)
}

// Unmarshal unmarshals DER bytes into KrbFastResponse.
func (v *KrbFastResponse) Unmarshal(b []byte) error {
	var w krbFastResponseWire
	if err := unmarshalMSKILE(b, &w); err != nil {
		return err
	}
	if w.Nonce < 0 || w.Nonce > int64(^uint32(0)) {
		return fmt.Errorf("KrbFastResponse nonce out of range: %d", w.Nonce)
	}
	v.PAData = w.PAData
	v.StrengthenKey = w.StrengthenKey
	v.Finished = w.Finished
	v.Nonce = uint32(w.Nonce)
	return nil
}

// Marshal marshals PAEncryptedChallenge to its DER encoding.
func (v *PAEncryptedChallenge) Marshal() ([]byte, error) {
	ed := EncryptedData(*v)
	return ed.Marshal()
}

// Unmarshal unmarshals DER bytes into PAEncryptedChallenge.
func (v *PAEncryptedChallenge) Unmarshal(b []byte) error {
	var ed EncryptedData
	if err := unmarshalMSKILE(b, &ed); err != nil {
		return err
	}
	*v = PAEncryptedChallenge(ed)
	return nil
}

// Marshal marshals PAFXError to its DER encoding.
func (v PAFXError) Marshal() ([]byte, error) {
	var decoded PAFXError
	if err := decoded.Unmarshal(v); err != nil {
		return nil, err
	}
	return append([]byte(nil), v...), nil
}

// Unmarshal unmarshals DER bytes into PAFXError.
func (v *PAFXError) Unmarshal(b []byte) error {
	if v == nil {
		return errors.New("cannot unmarshal PA-FX-ERROR into nil receiver")
	}
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return fmt.Errorf("decode PA-FX-ERROR wrapper: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing ASN.1 data: %d bytes", len(rest))
	}
	if raw.Class != asn1.ClassApplication || raw.Tag != asnAppTag.KRBError || !raw.IsCompound {
		return errors.New("PA-FX-ERROR must contain an application-tagged KRB-ERROR")
	}
	*v = append((*v)[:0], b...)
	return nil
}

// NewPAFXErrorPAData wraps PAFXError in a PA-DATA entry of its assigned type.
func NewPAFXErrorPAData(v PAFXError) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_FX_ERROR, PADataValue: b}, err
}

// GetPAFXError decodes the PAFXError carried by the value.
func (pa *PAData) GetPAFXError() (PAFXError, error) {
	var v PAFXError
	var err error
	if pa.PADataType != patype.PA_FX_ERROR {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_FX_ERROR, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return v, err
}

// NewPAFXFastRequestPAData wraps PAFXFastRequest in a PA-DATA entry of its assigned type.
func NewPAFXFastRequestPAData(v PAFXFastRequest) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_FX_FAST, PADataValue: b}, err
}

// GetPAFXFastRequest decodes the PAFXFastRequest carried by the value.
func (pa *PAData) GetPAFXFastRequest() (PAFXFastRequest, error) {
	var v PAFXFastRequest
	var err error
	if pa.PADataType != patype.PA_FX_FAST {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_FX_FAST, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return v, err
}

// NewPAFXFastReplyPAData wraps PAFXFastReply in a PA-DATA entry of its assigned type.
func NewPAFXFastReplyPAData(v PAFXFastReply) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_FX_FAST, PADataValue: b}, err
}

// GetPAFXFastReply decodes the PAFXFastReply carried by the value.
func (pa *PAData) GetPAFXFastReply() (PAFXFastReply, error) {
	var v PAFXFastReply
	var err error
	if pa.PADataType != patype.PA_FX_FAST {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_FX_FAST, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return v, err
}

// NewPAEncryptedChallengePAData wraps PAEncryptedChallenge in a PA-DATA entry of its assigned type.
func NewPAEncryptedChallengePAData(v PAEncryptedChallenge) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_ENCRYPTED_CHALLENGE, PADataValue: b}, err
}

// GetPAEncryptedChallenge decodes the PAEncryptedChallenge carried by the value.
func (pa *PAData) GetPAEncryptedChallenge() (PAEncryptedChallenge, error) {
	var v PAEncryptedChallenge
	var err error
	if pa.PADataType != patype.PA_ENCRYPTED_CHALLENGE {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_ENCRYPTED_CHALLENGE, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return v, err
}
