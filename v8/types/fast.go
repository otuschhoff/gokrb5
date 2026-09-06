package types

import (
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/asnAppTag"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
)

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

func (v *KrbFastArmor) Marshal() ([]byte, error)      { return marshalMSKILE(*v) }
func (v *KrbFastArmor) Unmarshal(b []byte) error      { return unmarshalMSKILE(b, v) }
func (v *KrbFastArmoredReq) Marshal() ([]byte, error) { return marshalMSKILE(*v) }
func (v *KrbFastArmoredReq) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }
func (v *KrbFastArmoredRep) Marshal() ([]byte, error) { return marshalMSKILE(*v) }
func (v *KrbFastArmoredRep) Unmarshal(b []byte) error { return unmarshalMSKILE(b, v) }
func (v *KrbFastFinished) Marshal() ([]byte, error)   { return marshalMSKILE(*v) }
func (v *KrbFastFinished) Unmarshal(b []byte) error   { return unmarshalMSKILE(b, v) }

func NewKrbFastReq(options asn1.BitString, paData PADataSequence, reqBody []byte) KrbFastReq {
	return KrbFastReq{
		FastOptions: options,
		PAData:      paData,
		ReqBody: asn1.RawValue{
			Class:      asn1.ClassContextSpecific,
			IsCompound: true,
			Tag:        2,
			Bytes:      append([]byte(nil), reqBody...),
		},
	}
}

func (v *KrbFastReq) Marshal() ([]byte, error) {
	if v.FastOptions.BitLength < 32 {
		return nil, fmt.Errorf("KrbFastReq fast-options must contain at least 32 bits")
	}
	if v.ReqBody.Class != asn1.ClassContextSpecific || v.ReqBody.Tag != 2 || !v.ReqBody.IsCompound {
		return nil, fmt.Errorf("KrbFastReq req-body must be an explicit context-specific tag 2")
	}
	return marshalMSKILE(*v)
}

func (v *KrbFastReq) Unmarshal(b []byte) error {
	if err := unmarshalMSKILE(b, v); err != nil {
		return err
	}
	if v.ReqBody.Class != asn1.ClassContextSpecific || v.ReqBody.Tag != 2 || !v.ReqBody.IsCompound {
		return fmt.Errorf("KrbFastReq req-body must be an explicit context-specific tag 2")
	}
	if v.FastOptions.BitLength < 32 {
		return fmt.Errorf("KrbFastReq fast-options must contain at least 32 bits")
	}
	return nil
}

func (v *PAFXFastRequest) Marshal() ([]byte, error) {
	b, err := v.ArmoredData.Marshal()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        0,
		Bytes:      b,
	})
}

func (v *PAFXFastRequest) Unmarshal(b []byte) error {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing ASN.1 data: %d bytes", len(rest))
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 || !raw.IsCompound {
		return fmt.Errorf("PA-FX-FAST-REQUEST must contain armored-data tag 0")
	}
	return v.ArmoredData.Unmarshal(raw.Bytes)
}

func (v *PAFXFastReply) Marshal() ([]byte, error) {
	b, err := v.ArmoredData.Marshal()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		IsCompound: true,
		Tag:        0,
		Bytes:      b,
	})
}

func (v *PAFXFastReply) Unmarshal(b []byte) error {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing ASN.1 data: %d bytes", len(rest))
	}
	if raw.Class != asn1.ClassContextSpecific || raw.Tag != 0 || !raw.IsCompound {
		return fmt.Errorf("PA-FX-FAST-REPLY must contain armored-data tag 0")
	}
	return v.ArmoredData.Unmarshal(raw.Bytes)
}

func (v *KrbFastResponse) Marshal() ([]byte, error) {
	w := krbFastResponseWire{
		PAData:        v.PAData,
		StrengthenKey: v.StrengthenKey,
		Finished:      v.Finished,
		Nonce:         int64(v.Nonce),
	}
	return marshalMSKILE(w)
}

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

func (v *PAEncryptedChallenge) Marshal() ([]byte, error) {
	ed := EncryptedData(*v)
	return ed.Marshal()
}

func (v *PAEncryptedChallenge) Unmarshal(b []byte) error {
	var ed EncryptedData
	if err := unmarshalMSKILE(b, &ed); err != nil {
		return err
	}
	*v = PAEncryptedChallenge(ed)
	return nil
}

func (v PAFXError) Marshal() ([]byte, error) {
	var decoded PAFXError
	if err := decoded.Unmarshal(v); err != nil {
		return nil, err
	}
	return append([]byte(nil), v...), nil
}

func (v *PAFXError) Unmarshal(b []byte) error {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(b, &raw)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("trailing ASN.1 data: %d bytes", len(rest))
	}
	if raw.Class != asn1.ClassApplication || raw.Tag != asnAppTag.KRBError || !raw.IsCompound {
		return fmt.Errorf("PA-FX-ERROR must contain an application-tagged KRB-ERROR")
	}
	*v = append((*v)[:0], b...)
	return nil
}

func NewPAFXErrorPAData(v PAFXError) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_FX_ERROR, PADataValue: b}, err
}

func (pa *PAData) GetPAFXError() (v PAFXError, err error) {
	if pa.PADataType != patype.PA_FX_ERROR {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_FX_ERROR, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return
}

func NewPAFXFastRequestPAData(v PAFXFastRequest) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_FX_FAST, PADataValue: b}, err
}

func (pa *PAData) GetPAFXFastRequest() (v PAFXFastRequest, err error) {
	if pa.PADataType != patype.PA_FX_FAST {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_FX_FAST, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return
}

func NewPAFXFastReplyPAData(v PAFXFastReply) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_FX_FAST, PADataValue: b}, err
}

func (pa *PAData) GetPAFXFastReply() (v PAFXFastReply, err error) {
	if pa.PADataType != patype.PA_FX_FAST {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_FX_FAST, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return
}

func NewPAEncryptedChallengePAData(v PAEncryptedChallenge) (PAData, error) {
	b, err := v.Marshal()
	return PAData{PADataType: patype.PA_ENCRYPTED_CHALLENGE, PADataValue: b}, err
}

func (pa *PAData) GetPAEncryptedChallenge() (v PAEncryptedChallenge, err error) {
	if pa.PADataType != patype.PA_ENCRYPTED_CHALLENGE {
		return v, fmt.Errorf("PAData type mismatch: expected %d, got %d", patype.PA_ENCRYPTED_CHALLENGE, pa.PADataType)
	}
	err = v.Unmarshal(pa.PADataValue)
	return
}
