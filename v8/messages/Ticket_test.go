package messages

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/addrtype"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/trtype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalTicket(t *testing.T) {
	t.Parallel()
	var a Ticket
	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	assert.Equal(t, iana.PVNO, a.TktVNO, "Ticket version number not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString), "SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName name strings not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of Ticket EncPart not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "KNVO of Ticket EncPart not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncPart.Cipher, "Cipher of Ticket EncPart not as expected")
}

func TestUnmarshalEncTicketPart(t *testing.T) {
	t.Parallel()
	var a EncTicketPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_tkt_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, int32(1), a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName string entries not as expected")
	assert.Equal(t, trtype.DOMAIN_X500_COMPRESS, a.Transited.TRType, "Transisted type not as expected")
	assert.Equal(t, []byte("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."), a.Transited.Contents, "Transisted content not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.StartTime, "Start time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, tt, a.RenewTill, "Renew Till time not as expected")
	assert.Equal(t, 2, len(a.CAddr), "Number of client addresses not as expected")
	for i, addr := range a.CAddr {
		assert.Equal(t, addrtype.IPv4, addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	for i, ele := range a.AuthorizationData {
		assert.Equal(t, adtype.ADIfRelevant, ele.ADType, fmt.Sprintf("Authorization data type of element %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), ele.ADData, fmt.Sprintf("Authorization data of element %d not as expected", i+1))
	}
}

func TestUnmarshalEncTicketPart_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a EncTicketPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_tkt_partOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, int32(1), a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName string entries not as expected")
	assert.Equal(t, trtype.DOMAIN_X500_COMPRESS, a.Transited.TRType, "Transisted type not as expected")
	assert.Equal(t, []byte("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."), a.Transited.Contents, "Transisted content not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
}

func TestMarshalTicket(t *testing.T) {
	t.Parallel()
	var a Ticket
	b, err := hex.DecodeString(testdata.MarshaledKRB5ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal of ticket errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshalled bytes not as expected")
}

func TestNewTicketWithKeyAndValidity(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	serviceKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: bytes.Repeat([]byte{1}, 32)}
	ticket, sessionKey, err := NewTicketWithKey(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG", types.NewKrbFlags(), serviceKey, 4, now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Realm != "EXAMPLE.ORG" || !ticket.SName.Equal(sname) || len(sessionKey.KeyValue) != 32 {
		t.Fatalf("ticket/session key = %+v/%x", ticket, sessionKey.KeyValue)
	}
	if err := ticket.Decrypt(serviceKey); err != nil {
		t.Fatal(err)
	}
	if !ticket.DecryptedEncPart.CName.Equal(cname) || ticket.DecryptedEncPart.Key.KeyType != sessionKey.KeyType || !bytes.Equal(ticket.DecryptedEncPart.Key.KeyValue, sessionKey.KeyValue) {
		t.Fatalf("decrypted ticket = %+v", ticket.DecryptedEncPart)
	}
	if valid, err := ticket.ValidAt(now.Add(time.Minute), 0); !valid || err != nil {
		t.Fatalf("current ticket validity = %v, %v", valid, err)
	}
	if valid, err := ticket.Valid(time.Hour); !valid || err != nil {
		t.Fatalf("ticket validity with skew = %v, %v", valid, err)
	}

	future := ticket
	future.DecryptedEncPart.StartTime = now.Add(2 * time.Hour)
	if valid, err := future.ValidAt(now, time.Minute); valid || err == nil {
		t.Fatalf("future ticket validity = %v, %v", valid, err)
	}
	invalid := ticket
	types.SetFlag(&invalid.DecryptedEncPart.Flags, flags.Invalid)
	if valid, err := invalid.ValidAt(now, 0); valid || err == nil {
		t.Fatalf("invalid ticket validity = %v, %v", valid, err)
	}
	expired := ticket
	expired.DecryptedEncPart.EndTime = now.Add(-2 * time.Hour)
	if valid, err := expired.ValidAt(now, time.Minute); valid || err == nil {
		t.Fatalf("expired ticket validity = %v, %v", valid, err)
	}

	tampered := ticket
	tampered.EncPart.Cipher[0] ^= 0xff
	if err := tampered.Decrypt(serviceKey); err == nil {
		t.Fatal("tampered ticket decrypted")
	}
	if _, _, err := NewTicketWithKey(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG", types.NewKrbFlags(), types.EncryptionKey{KeyType: -1}, 1, now, now, now, now); err == nil {
		t.Fatal("unsupported service key etype accepted")
	}
}

func TestNewTicketAndKeytabDecryption(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	kt := keytab.New()
	if err := kt.AddEntry("HTTP/server.example.org", "EXAMPLE.ORG", "password", now, 2, etypeID.AES256_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	ticket, _, err := NewTicket(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG", types.NewKrbFlags(), kt, etypeID.AES256_CTS_HMAC_SHA1_96, 2, now, now, now.Add(time.Hour), now.Add(2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := ticket.DecryptEncPart(kt, nil); err != nil {
		t.Fatal(err)
	}
	if err := ticket.DecryptEncPart(keytab.New(), &sname); err == nil {
		t.Fatal("missing keytab entry returned no error")
	}
	if _, _, err := NewTicket(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG", types.NewKrbFlags(), keytab.New(), etypeID.AES256_CTS_HMAC_SHA1_96, 2, now, now, now, now); err == nil {
		t.Fatal("NewTicket accepted an empty keytab")
	}
}

func TestAuthorizationData_GetPACType_GOKRB5TestData(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_AuthorizationData_GOKRB5)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	var a types.AuthorizationData
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	tkt := Ticket{
		Realm: "TEST.GOKRB5",
		EncPart: types.EncryptedData{
			EType: 18,
			KVNO:  2,
		},
		DecryptedEncPart: EncTicketPart{
			AuthorizationData: a,
		},
	}
	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	sname := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"sysHTTP"}}
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	isPAC, pac, err := tkt.GetPACType(kt, &sname, l)
	if err != nil {
		t.Log(w.String())
		t.Errorf("error getting PAC: %v", err)
	}
	assert.True(t, isPAC, "PAC should be present")
	assert.Equal(t, 5, len(pac.Buffers), "Number of buffers not as expected")
	assert.Equal(t, uint32(5), pac.CBuffers, "Count of buffers not as expected")
	assert.Equal(t, uint32(0), pac.Version, "PAC version not as expected")
	assert.NotNil(t, pac.KerbValidationInfo, "PAC Kerb Validation info is nil")
	assert.NotNil(t, pac.ClientInfo, "PAC Client Info info is nil")
	assert.NotNil(t, pac.UPNDNSInfo, "PAC UPN DNS Info info is nil")
	assert.NotNil(t, pac.KDCChecksum, "PAC KDC Checksum info is nil")
	assert.NotNil(t, pac.ServerChecksum, "PAC Server checksum info is nil")
}
