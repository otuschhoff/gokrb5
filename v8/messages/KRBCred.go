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

type marshalKRBCred struct {
	PVNO    int                 `asn1:"explicit,tag:0"`
	MsgType int                 `asn1:"explicit,tag:1"`
	Tickets asn1.RawValue       `asn1:"explicit,tag:2"`
	EncPart types.EncryptedData `asn1:"explicit,tag:3"`
}

// KRBCred implements RFC 4120 KRB_CRED: https://tools.ietf.org/html/rfc4120#section-5.8.1.
type KRBCred struct {
	PVNO             int
	MsgType          int
	Tickets          []Ticket
	EncPart          types.EncryptedData
	DecryptedEncPart EncKrbCredPart
}

// EncKrbCredPart is the encrypted part of KRB_CRED.
type EncKrbCredPart struct {
	TicketInfo []KrbCredInfo     `asn1:"explicit,tag:0"`
	Nouce      int               `asn1:"optional,explicit,tag:1"`
	Timestamp  time.Time         `asn1:"generalized,optional,explicit,tag:2"`
	Usec       int               `asn1:"optional,explicit,tag:3"`
	SAddress   types.HostAddress `asn1:"optional,explicit,tag:4"`
	RAddress   types.HostAddress `asn1:"optional,explicit,tag:5"`
}

// KrbCredInfo is the KRB_CRED_INFO part of KRB_CRED.
type KrbCredInfo struct {
	Key       types.EncryptionKey `asn1:"explicit,tag:0"`
	PRealm    string              `asn1:"generalstring,optional,explicit,tag:1"`
	PName     types.PrincipalName `asn1:"optional,explicit,tag:2"`
	Flags     asn1.BitString      `asn1:"optional,explicit,tag:3"`
	AuthTime  time.Time           `asn1:"generalized,optional,explicit,tag:4"`
	StartTime time.Time           `asn1:"generalized,optional,explicit,tag:5"`
	EndTime   time.Time           `asn1:"generalized,optional,explicit,tag:6"`
	RenewTill time.Time           `asn1:"generalized,optional,explicit,tag:7"`
	SRealm    string              `asn1:"optional,explicit,ia5,tag:8"`
	SName     types.PrincipalName `asn1:"optional,explicit,tag:9"`
	CAddr     types.HostAddresses `asn1:"optional,explicit,tag:10"`
}

// NewKRBCred creates and encrypts a KRB_CRED message.
func NewKRBCred(tickets []Ticket, ticketInfo []KrbCredInfo, key types.EncryptionKey) (KRBCred, error) {
	if len(tickets) == 0 || len(tickets) != len(ticketInfo) {
		return KRBCred{}, fmt.Errorf("KRB_CRED requires one ticket-info entry per ticket")
	}
	k := KRBCred{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_CRED,
		Tickets: append([]Ticket(nil), tickets...),
		DecryptedEncPart: EncKrbCredPart{
			TicketInfo: append([]KrbCredInfo(nil), ticketInfo...),
		},
	}
	if err := k.EncryptEncPart(key); err != nil {
		return KRBCred{}, err
	}
	return k, nil
}

// Unmarshal bytes b into the KRBCred struct.
func (k *KRBCred) Unmarshal(b []byte) error {
	var m marshalKRBCred
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.KRBCred))
	if err != nil {
		return processUnmarshalReplyError(b, err)
	}
	expectedMsgType := msgtype.KRB_CRED
	if m.MsgType != expectedMsgType {
		return krberror.NewErrorf(krberror.KRBMsgError, "message ID does not indicate a KRB_CRED. Expected: %v; Actual: %v", expectedMsgType, m.MsgType)
	}
	k.PVNO = m.PVNO
	k.MsgType = m.MsgType
	k.EncPart = m.EncPart
	if len(m.Tickets.Bytes) > 0 {
		k.Tickets, err = unmarshalTicketsSequence(m.Tickets)
		if err != nil {
			return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling tickets within KRB_CRED")
		}
	}
	return nil
}

// Marshal the KRB_CRED message.
func (k *KRBCred) Marshal() ([]byte, error) {
	tickets, err := MarshalTicketSequence(k.Tickets)
	if err != nil {
		return nil, err
	}
	tickets.Tag = 2
	wire := marshalKRBCred{
		PVNO:    k.PVNO,
		MsgType: k.MsgType,
		Tickets: tickets,
		EncPart: k.EncPart,
	}
	b, err := asn1.Marshal(wire)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "KRB_CRED marshal error")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.KRBCred), nil
}

// EncryptEncPart encrypts DecryptedEncPart using the KRB-CRED key usage.
func (k *KRBCred) EncryptEncPart(key types.EncryptionKey) error {
	b, err := k.DecryptedEncPart.Marshal()
	if err != nil {
		return err
	}
	k.EncPart, err = crypto.GetEncryptedData(b, key, keyusage.KRB_CRED_ENCPART, 0)
	if err != nil {
		return krberror.Errorf(err, krberror.EncryptingError, "error encrypting KRB_CRED EncPart")
	}
	return nil
}

// DecryptEncPart decrypts the encrypted part of a KRB_CRED.
func (k *KRBCred) DecryptEncPart(key types.EncryptionKey) error {
	var b []byte
	if k.EncPart.EType == 0 {
		b = k.EncPart.Cipher
	} else {
		var err error
		b, err = crypto.DecryptEncPart(k.EncPart, key, keyusage.KRB_CRED_ENCPART)
		if err != nil {
			return krberror.Errorf(err, krberror.DecryptingError, "error decrypting KRB_CRED EncPart")
		}
	}
	var denc EncKrbCredPart
	err := denc.Unmarshal(b)
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling encrypted part of KRB_CRED")
	}
	k.DecryptedEncPart = denc
	return nil
}

// Unmarshal bytes b into the encrypted part of KRB_CRED.
func (k *EncKrbCredPart) Unmarshal(b []byte) error {
	_, err := asn1.UnmarshalWithParams(b, k, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.EncKrbCredPart))
	if err != nil {
		return krberror.Errorf(err, krberror.EncodingError, "error unmarshaling EncKrbCredPart")
	}
	return nil
}

// Marshal the encrypted part of a KRB_CRED.
func (k *EncKrbCredPart) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*k)
	if err != nil {
		return nil, krberror.Errorf(err, krberror.EncodingError, "EncKrbCredPart marshal error")
	}
	return asn1tools.AddASNAppTag(b, asnAppTag.EncKrbCredPart), nil
}
