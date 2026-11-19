package messages

import (
	"fmt"
	"log"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/asn1tools"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/asnAppTag"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.3

// Ticket implements the Kerberos ticket.
type Ticket struct {
	TktVNO           int                 `asn1:"explicit,tag:0"`
	Realm            string              `asn1:"generalstring,explicit,tag:1"`
	SName            types.PrincipalName `asn1:"explicit,tag:2"`
	EncPart          types.EncryptedData `asn1:"explicit,tag:3"`
	DecryptedEncPart EncTicketPart       `asn1:"optional"` // Not part of ASN1 bytes so marked as optional so unmarshalling works
}

// EncTicketPart is the encrypted part of the Ticket.
type EncTicketPart struct {
	Flags             asn1.BitString          `asn1:"explicit,tag:0"`
	Key               types.EncryptionKey     `asn1:"explicit,tag:1"`
	CRealm            string                  `asn1:"generalstring,explicit,tag:2"`
	CName             types.PrincipalName     `asn1:"explicit,tag:3"`
	Transited         TransitedEncoding       `asn1:"explicit,tag:4"`
	AuthTime          time.Time               `asn1:"generalized,explicit,tag:5"`
	StartTime         time.Time               `asn1:"generalized,explicit,optional,tag:6"`
	EndTime           time.Time               `asn1:"generalized,explicit,tag:7"`
	RenewTill         time.Time               `asn1:"generalized,explicit,optional,tag:8"`
	CAddr             types.HostAddresses     `asn1:"explicit,optional,tag:9"`
	AuthorizationData types.AuthorizationData `asn1:"explicit,optional,tag:10"`
}

// TransitedEncoding part of the ticket's encrypted part.
type TransitedEncoding struct {
	TRType   int32  `asn1:"explicit,tag:0"`
	Contents []byte `asn1:"explicit,tag:1"`
}

// NewTicket creates a new Ticket instance.
func NewTicket(cname types.PrincipalName, crealm string, sname types.PrincipalName, srealm string, flags asn1.BitString, sktab *keytab.Keytab, eTypeID int32, kvno int, authTime, startTime, endTime, renewTill time.Time) (Ticket, types.EncryptionKey, error) {
	skey, _, err := sktab.GetEncryptionKey(sname, srealm, kvno, eTypeID)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "error getting encryption key for new ticket")
	}
	return NewTicketWithKey(cname, crealm, sname, srealm, flags, skey, kvno, authTime, startTime, endTime, renewTill)
}

// NewTicketWithKey creates a ticket encrypted by an explicitly supplied
// service key. It is used by KDC-less protocols that retain an ephemeral
// service key for the lifetime of a conversation.
func NewTicketWithKey(cname types.PrincipalName, crealm string, sname types.PrincipalName, srealm string, flags asn1.BitString, serviceKey types.EncryptionKey, kvno int, authTime, startTime, endTime, renewTill time.Time) (Ticket, types.EncryptionKey, error) {
	eTypeID := serviceKey.KeyType
	etype, err := crypto.GetEtype(eTypeID)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "error getting etype for new ticket")
	}
	sessionKey, err := types.GenerateEncryptionKey(etype)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "error generating session key")
	}

	etp := EncTicketPart{
		Flags:     flags,
		Key:       sessionKey,
		CRealm:    crealm,
		CName:     cname,
		Transited: TransitedEncoding{},
		AuthTime:  authTime,
		StartTime: startTime,
		EndTime:   endTime,
		RenewTill: renewTill,
	}
	b, err := asn1.Marshal(etp)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncodingError, "error marshalling ticket encpart")
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.EncTicketPart)
	ed, err := crypto.GetEncryptedData(b, serviceKey, keyusage.KDC_REP_TICKET, kvno)
	if err != nil {
		return Ticket{}, types.EncryptionKey{}, krberror.Errorf(err, krberror.EncryptingError, "error encrypting ticket encpart")
	}
	tkt := Ticket{
		TktVNO:  iana.PVNO,
		Realm:   srealm,
		SName:   sname,
		EncPart: ed,
	}
	return tkt, sessionKey, nil
}

// Unmarshal bytes b into a Ticket struct.
func (t *Ticket) Unmarshal(b []byte) error {
	params := fmt.Sprintf("application,explicit,tag:%d", asnAppTag.Ticket)
	if _, err := asn1.UnmarshalWithParams(b, t, params); err != nil {
		return fmt.Errorf("decode ticket: %w", err)
	}
	return nil
}

// Marshal the Ticket.
func (t *Ticket) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*t)
	if err != nil {
		return nil, fmt.Errorf("encode ticket: %w", err)
	}
	b = asn1tools.AddASNAppTag(b, asnAppTag.Ticket)
	return b, nil
}

// Unmarshal bytes b into the EncTicketPart struct.
func (t *EncTicketPart) Unmarshal(b []byte) error {
	params := fmt.Sprintf("application,explicit,tag:%d", asnAppTag.EncTicketPart)
	if _, err := asn1.UnmarshalWithParams(b, t, params); err != nil {
		return fmt.Errorf("decode encrypted ticket part: %w", err)
	}
	return nil
}

// unmarshalTicket returns any decoded fields along with the decode error.
func unmarshalTicket(b []byte) (Ticket, error) {
	var t Ticket
	err := t.Unmarshal(b)
	return t, err
}

// unmarshalTicketsSequence decodes each application-tagged ticket in the sequence.
func unmarshalTicketsSequence(in asn1.RawValue) ([]Ticket, error) {
	// Decode members individually to work around https://github.com/golang/go/issues/17321.
	b := in.Bytes
	// Skip the SEQUENCE identifier and its encoded length.
	p := 1 + asn1tools.GetNumberBytesInLengthHeader(b)
	var tkts []Ticket
	var raw asn1.RawValue
	for p < len(b) {
		_, err := asn1.UnmarshalWithParams(b[p:], &raw, fmt.Sprintf("application,tag:%d", asnAppTag.Ticket))
		if err != nil {
			return nil, fmt.Errorf("unmarshaling sequence of tickets failed getting length of ticket: %w", err)
		}
		t, err := unmarshalTicket(b[p:])
		if err != nil {
			return nil, fmt.Errorf("unmarshaling sequence of tickets failed: %w", err)
		}
		p += len(raw.FullBytes)
		tkts = append(tkts, t)
	}
	return tkts, nil
}

// MarshalTicketSequence wraps the ticket sequence for an explicit ASN.1 field.
// The caller sets the field's context-specific tag.
func MarshalTicketSequence(tkts []Ticket) (asn1.RawValue, error) {
	raw := asn1.RawValue{
		Class:      asn1.ClassContextSpecific,
		Tag:        0,
		IsCompound: true,
		Bytes:      nil,
		FullBytes:  nil,
	}
	if len(tkts) < 1 {
		return raw, nil
	}
	var btkts []byte
	for i, t := range tkts {
		b, err := t.Marshal()
		if err != nil {
			return raw, fmt.Errorf("error marshaling ticket number %d in sequence of tickets: %w", i+1, err)
		}
		btkts = append(btkts, b...)
	}
	// The explicit field contains a universal, constructed SEQUENCE.
	const constructedBit = 0x20
	btkts = append(asn1tools.MarshalLengthBytes(len(btkts)), btkts...)
	raw.Bytes = append([]byte{constructedBit | asn1.TagSequence}, btkts...)
	return raw, nil
}

// DecryptEncPart decrypts the ticket using the key for sname.
// If sname is nil, it uses the service principal named in the ticket.
func (t *Ticket) DecryptEncPart(kt *keytab.Keytab, sname *types.PrincipalName) error {
	key, err := t.lookupServiceKey(kt, sname)
	if err != nil {
		return err
	}
	return t.Decrypt(key)
}

// Decrypt decrypts the encrypted part of the ticket using the key provided.
func (t *Ticket) Decrypt(key types.EncryptionKey) error {
	b, err := crypto.DecryptEncPart(t.EncPart, key, keyusage.KDC_REP_TICKET)
	if err != nil {
		return fmt.Errorf("error decrypting Ticket EncPart: %w", err)
	}
	var denc EncTicketPart
	err = denc.Unmarshal(b)
	if err != nil {
		return fmt.Errorf("error unmarshaling encrypted part: %w", err)
	}
	t.DecryptedEncPart = denc
	return nil
}

// GetPACType extracts and verifies the ticket's Microsoft PAC using the ticket context.
func (t *Ticket) GetPACType(kt *keytab.Keytab, sname *types.PrincipalName, l *log.Logger) (bool, pac.PACType, error) {
	var options pac.VerifyOptions
	return t.GetPACTypeWithOptions(kt, sname, l, options)
}

// GetPACTypeWithOptions returns a processed PAC with additional verification context.
// A true result indicates a PAC was found; callers must check the error before using it.
func (t *Ticket) GetPACTypeWithOptions(
	kt *keytab.Keytab,
	sname *types.PrincipalName,
	l *log.Logger,
	options pac.VerifyOptions,
) (bool, pac.PACType, error) {
	var p pac.PACType
	entries, err := t.DecryptedEncPart.AuthorizationData.EntriesOfType(adtype.ADWin2KPAC)
	if err != nil {
		return false, p, fmt.Errorf("PAC authorization data could not be traversed: %w", err)
	}
	if len(entries) == 0 {
		return false, p, nil
	}
	if decodeErr := p.Unmarshal(entries[0].ADData); decodeErr != nil {
		return true, p, fmt.Errorf("error unmarshaling PAC: %w", decodeErr)
	}
	key, err := t.lookupServiceKey(kt, sname)
	if err != nil {
		return true, p, err
	}
	if err := p.ProcessPACInfoBuffers(key, l); err != nil {
		return true, p, fmt.Errorf("process ticket PAC buffers: %w", err)
	}
	if options.ExpectedClientName == "" {
		options.ExpectedClientName = t.DecryptedEncPart.CName.PrincipalNameString()
	}
	if options.ExpectedAuthTime == nil && !t.DecryptedEncPart.AuthTime.IsZero() {
		options.ExpectedAuthTime = &t.DecryptedEncPart.AuthTime
	}
	if err := p.Verify(key, options); err != nil {
		return true, p, fmt.Errorf("verify ticket PAC: %w", err)
	}
	return true, p, nil
}

// Valid checks it the ticket is currently valid. Max duration passed endtime passed in as argument.
func (t *Ticket) Valid(d time.Duration) (bool, error) {
	return t.ValidAt(time.Now().UTC(), d)
}

// ValidAt checks whether the ticket is valid at the supplied time, allowing d
// of clock skew.
func (t *Ticket) ValidAt(now time.Time, d time.Duration) (bool, error) {
	// Check for future tickets or invalid tickets
	if t.DecryptedEncPart.StartTime.Sub(now) > d || types.IsFlagSet(&t.DecryptedEncPart.Flags, flags.Invalid) {
		return false, NewKRBError(t.SName, t.Realm, errorcode.KRB_AP_ERR_TKT_NYV, "service ticket provided is not yet valid")
	}

	// Check for expired ticket
	if now.Sub(t.DecryptedEncPart.EndTime) > d {
		return false, NewKRBError(t.SName, t.Realm, errorcode.KRB_AP_ERR_TKT_EXPIRED, "service ticket provided has expired")
	}

	return true, nil
}

func (t *Ticket) lookupServiceKey(kt *keytab.Keytab, sname *types.PrincipalName) (types.EncryptionKey, error) {
	if sname == nil {
		sname = &t.SName
	}
	key, _, err := kt.GetEncryptionKey(*sname, t.Realm, t.EncPart.KVNO, t.EncPart.EType)
	if err != nil {
		text := fmt.Sprintf("Could not get key from keytab: %v", err)
		return key, NewKRBError(t.SName, t.Realm, errorcode.KRB_AP_ERR_NOKEY, text)
	}
	return key, nil
}
