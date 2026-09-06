package messages

import (
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/asn1tools"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/asnAppTag"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// APRep implements RFC 4120 KRB_AP_REP: https://tools.ietf.org/html/rfc4120#section-5.5.2.
type APRep struct {
	PVNO             int                 `asn1:"explicit,tag:0"`
	MsgType          int                 `asn1:"explicit,tag:1"`
	EncPart          types.EncryptedData `asn1:"explicit,tag:2"`
	DecryptedEncPart EncAPRepPart        `asn1:"optional,omitempty"`
}

// EncAPRepPart is the encrypted part of KRB_AP_REP.
type EncAPRepPart struct {
	CTime          time.Time           `asn1:"generalized,explicit,tag:0"`
	Cusec          int                 `asn1:"explicit,tag:1"`
	Subkey         types.EncryptionKey `asn1:"optional,explicit,tag:2"`
	SequenceNumber int64               `asn1:"optional,explicit,tag:3"`
}

// NewAPRep creates and encrypts a KRB_AP_REP from its encrypted part.
func NewAPRep(part EncAPRepPart, key types.EncryptionKey) (APRep, error) {
	a := APRep{
		PVNO:             iana.PVNO,
		MsgType:          msgtype.KRB_AP_REP,
		DecryptedEncPart: part,
	}
	if err := a.EncryptEncPart(key); err != nil {
		return APRep{}, err
	}
	return a, nil
}

// NewAPRepFromAuthenticator creates the normal acceptor reply to an AP_REQ.
func NewAPRepFromAuthenticator(auth types.Authenticator, key, subkey types.EncryptionKey, sequenceNumber int64) (APRep, error) {
	return NewAPRep(EncAPRepPart{
		CTime:          auth.CTime,
		Cusec:          auth.Cusec,
		Subkey:         subkey,
		SequenceNumber: sequenceNumber,
	}, key)
}

// Unmarshal bytes b into the APRep struct.
func (a *APRep) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.APREP))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}
	expectedMsgType := msgtype.KRB_AP_REP
	if a.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_AP_REP. Expected: %v; Actual: %v", expectedMsgType, a.MsgType)
	}
	return nil
}

// Marshal the APRep.
func (a *APRep) Marshal() ([]byte, error) {
	wire := APRep{
		PVNO:    a.PVNO,
		MsgType: a.MsgType,
		EncPart: a.EncPart,
	}
	b, err := asn1.Marshal(wire)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "AP_REP marshal error")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.APREP), nil
}

// Unmarshal bytes b into the APRep encrypted part struct.
func (a *EncAPRepPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, a, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncAPRepPart))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "AP_REP unmarshal error")
	}
	return nil
}

// Marshal the EncAPRepPart.
func (a *EncAPRepPart) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*a)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "AP_REP encrypted part marshal error")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.EncAPRepPart), nil
}

// EncryptEncPart encrypts DecryptedEncPart using the AP-REP key usage.
func (a *APRep) EncryptEncPart(key types.EncryptionKey) error {
	b, err := a.DecryptedEncPart.Marshal()
	if err != nil {
		return err
	}
	a.EncPart, err = crypto.GetEncryptedData(b, key, keyusage.AP_REP_ENCPART, 0)
	if err != nil {
		return krberror.Errorf(err, krberror.EncryptingError, "error encrypting AP_REP encrypted part")
	}
	return nil
}

// DecryptEncPart decrypts and unmarshals the encrypted part of the AP_REP.
func (a *APRep) DecryptEncPart(key types.EncryptionKey) error {
	b, err := crypto.DecryptEncPart(a.EncPart, key, keyusage.AP_REP_ENCPART)
	if err != nil {
		return krberror.Errorf(err, krberror.DecryptingError, "error decrypting AP_REP encrypted part")
	}
	if err := a.DecryptedEncPart.Unmarshal(b); err != nil {
		return err
	}
	return nil
}

// Verify decrypts an AP_REP and verifies that it proves receipt of auth.
func (a *APRep) Verify(auth types.Authenticator, key types.EncryptionKey) error {
	if err := a.DecryptEncPart(key); err != nil {
		return err
	}
	if !a.DecryptedEncPart.CTime.Equal(auth.CTime.Truncate(time.Second)) || a.DecryptedEncPart.Cusec != auth.Cusec {
		return krberror.NewErrorf(krberror.KRBMsgError, "AP_REP timestamp does not match authenticator")
	}
	return nil
}

// VerifyDCE decrypts and verifies a DCE-style AP-REP. A negative expected
// sequence accepts the peer-selected sequence. The final initiator reply must
// set requireNoSubkey.
func (a *APRep) VerifyDCE(key types.EncryptionKey, expectedSequence int64, requireNoSubkey bool, maxClockSkew time.Duration) error {
	if err := a.DecryptEncPart(key); err != nil {
		return err
	}
	part := a.DecryptedEncPart
	if expectedSequence >= 0 && part.SequenceNumber != expectedSequence {
		return krberror.NewErrorf(krberror.KRBMsgError, "DCE AP_REP sequence number does not match")
	}
	if requireNoSubkey && (part.Subkey.KeyType != 0 || len(part.Subkey.KeyValue) != 0) {
		return krberror.NewErrorf(krberror.KRBMsgError, "DCE final AP_REP must not contain a subkey")
	}
	timestamp := part.CTime.Add(time.Duration(part.Cusec) * time.Microsecond)
	now := time.Now().UTC()
	if now.Sub(timestamp) > maxClockSkew || timestamp.Sub(now) > maxClockSkew {
		return krberror.NewErrorf(krberror.KRBMsgError, "DCE AP_REP timestamp exceeds clock skew")
	}
	return nil
}
