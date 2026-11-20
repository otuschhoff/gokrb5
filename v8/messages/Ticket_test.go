package messages

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/addrtype"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/trtype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const ticketTestRealm = "EXAMPLE.ORG"

func TestTicketDecodeErrorContext(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		context string
		decode  func([]byte) error
	}{
		{name: "ticket", context: "decode ticket:", decode: new(Ticket).Unmarshal},
		{name: "encrypted part", context: "decode encrypted ticket part:", decode: new(EncTicketPart).Unmarshal},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.decode(nil)
			if _, ok := errors.AsType[asn1.SyntaxError](err); !ok || !strings.HasPrefix(err.Error(), tt.context) {
				t.Fatalf("Unmarshal() = %v; want %q and ASN.1 syntax cause", err, tt.context)
			}
		})
	}
}

func TestUnmarshalTicketRetainsDecodedFieldsOnError(t *testing.T) {
	t.Parallel()

	// The version and realm are valid, but the explicit service name is empty.
	data := mustDecodeHex(t, "6111300fa003020105a1061b0454455354a200")
	ticket, err := unmarshalTicket(data)
	var structure asn1.StructuralError
	require.ErrorAs(t, err, &structure)
	assert.ErrorContains(t, err, "decode ticket:")
	assert.Equal(t, iana.PVNO, ticket.TktVNO)
	assert.Equal(t, "TEST", ticket.Realm)
}

func TestTicketSequenceFraming(t *testing.T) {
	t.Parallel()

	firstWire := mustDecodeHex(t, testdata.MarshaledKRB5ticket)
	first := mustUnmarshalTicket(t, firstWire)
	second := first
	second.Realm = "SECOND.EXAMPLE"
	secondWire, err := second.Marshal()
	require.NoError(t, err)

	for _, tt := range []struct {
		name        string
		tickets     []Ticket
		expectBytes []byte
	}{
		{name: "empty", tickets: nil, expectBytes: nil},
		{
			name:        "short length",
			tickets:     []Ticket{first},
			expectBytes: slices.Concat([]byte{0x30, 0x5e}, firstWire),
		},
		{
			name:        "long length in ticket order",
			tickets:     []Ticket{first, second},
			expectBytes: slices.Concat([]byte{0x30, 0x81, 0xbc}, firstWire, secondWire),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			raw, err := MarshalTicketSequence(tt.tickets)
			require.NoError(t, err)
			assert.Equal(t, asn1.ClassContextSpecific, raw.Class)
			assert.True(t, raw.IsCompound)
			assert.Zero(t, raw.Tag, "the caller supplies the field tag")
			assert.Nil(t, raw.FullBytes)
			assert.Equal(t, tt.expectBytes, raw.Bytes)

			tickets, err := unmarshalTicketsSequence(raw)
			require.NoError(t, err)
			assert.Equal(t, tt.tickets, tickets)
		})
	}
}

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
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString),
		"SName does not have the expected number of NameStrings")
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
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, int32(1), a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName string entries not as expected")
	assert.Equal(t, trtype.DOMAIN_X500_COMPRESS, a.Transited.TRType, "Transisted type not as expected")
	assert.Equal(t, []byte("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."), a.Transited.Contents,
		"Transisted content not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.StartTime, "Start time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, tt, a.RenewTill, "Renew Till time not as expected")
	assert.Equal(t, 2, len(a.CAddr), "Number of client addresses not as expected")
	for i, addr := range a.CAddr {
		assert.Equal(t, addrtype.IPv4, addr.AddrType,
			fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address),
			fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	for i, ele := range a.AuthorizationData {
		assert.Equal(t, adtype.ADIfRelevant, ele.ADType,
			fmt.Sprintf("Authorization data type of element %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_AUTHORIZATION_DATA_VALUE), ele.ADData,
			fmt.Sprintf("Authorization data of element %d not as expected", i+1))
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
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, int32(1), a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "CRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName string entries not as expected")
	assert.Equal(t, trtype.DOMAIN_X500_COMPRESS, a.Transited.TRType, "Transisted type not as expected")
	assert.Equal(t, []byte("EDU,MIT.,ATHENA.,WASHINGTON.EDU,CS."), a.Transited.Contents,
		"Transisted content not as expected")
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
	ticket, sessionKey, err := NewTicketWithKey(
		cname, ticketTestRealm, sname, ticketTestRealm, types.NewKrbFlags(), serviceKey,
		4, now, now, now.Add(time.Hour), now.Add(2*time.Hour),
	)
	if err != nil {
		t.Fatal(err)
	}
	if ticket.Realm != ticketTestRealm || !ticket.SName.Equal(sname) || len(sessionKey.KeyValue) != 32 {
		t.Fatalf("ticket/session key = %+v/%x", ticket, sessionKey.KeyValue)
	}
	checkTicketDecryption(t, &ticket, serviceKey, sessionKey, cname)
	checkTicketValidity(t, ticket, now)
	checkTicketRejectedAtInvalidTimes(t, ticket, now)

	tampered := ticket
	tampered.EncPart.Cipher[0] ^= 0xff
	if err := tampered.Decrypt(serviceKey); err == nil {
		t.Fatal("tampered ticket decrypted")
	}
	unsupportedKey := types.EncryptionKey{KeyType: -1, KeyValue: nil}
	if _, _, err := NewTicketWithKey(
		cname, ticketTestRealm, sname, ticketTestRealm, types.NewKrbFlags(), unsupportedKey, 1, now, now, now, now,
	); err == nil {
		t.Fatal("unsupported service key etype accepted")
	}
}

func checkTicketDecryption(
	t *testing.T,
	ticket *Ticket,
	serviceKey, sessionKey types.EncryptionKey,
	cname types.PrincipalName,
) {
	t.Helper()
	if err := ticket.Decrypt(serviceKey); err != nil {
		t.Fatal(err)
	}
	decrypted := ticket.DecryptedEncPart
	if !decrypted.CName.Equal(cname) ||
		decrypted.Key.KeyType != sessionKey.KeyType ||
		!bytes.Equal(decrypted.Key.KeyValue, sessionKey.KeyValue) {
		t.Fatalf("decrypted ticket = %+v", decrypted)
	}
}

func checkTicketValidity(t *testing.T, ticket Ticket, now time.Time) {
	t.Helper()
	if valid, err := ticket.ValidAt(now.Add(time.Minute), 0); !valid || err != nil {
		t.Fatalf("current ticket validity = %v, %v", valid, err)
	}
	if valid, err := ticket.Valid(time.Hour); !valid || err != nil {
		t.Fatalf("ticket validity with skew = %v, %v", valid, err)
	}
}

func checkTicketRejectedAtInvalidTimes(t *testing.T, ticket Ticket, now time.Time) {
	t.Helper()
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
}

func TestNewTicketAndKeytabDecryption(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	kt := keytab.New()
	require.NoError(t, kt.AddEntry(
		"HTTP/server.example.org", ticketTestRealm, "password", now, 2, etypeID.AES256_CTS_HMAC_SHA1_96,
	))
	ticket, _, err := NewTicket(
		cname, ticketTestRealm, sname, ticketTestRealm, types.NewKrbFlags(), kt,
		etypeID.AES256_CTS_HMAC_SHA1_96, 2, now, now, now.Add(time.Hour), now.Add(2*time.Hour),
	)
	require.NoError(t, err)
	require.NoError(t, ticket.DecryptEncPart(kt, nil))
	assert.Equal(t, cname, ticket.DecryptedEncPart.CName)

	t.Run("a missing override does not fall back to the ticket principal", func(t *testing.T) {
		override := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/missing.example.org")
		lookupErr := ticket.DecryptEncPart(kt, &override)
		var missingKey KRBError
		require.ErrorAs(t, lookupErr, &missingKey)
		assert.IsType(t, missingKey, lookupErr)
		assert.Equal(t, errorcode.KRB_AP_ERR_NOKEY, missingKey.ErrorCode)
		assert.Equal(t, ticket.SName, missingKey.SName)
	})

	ticket.SName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/alias.example.org")
	require.NoError(t, ticket.DecryptEncPart(kt, &sname))
	assert.Equal(t, cname, ticket.DecryptedEncPart.CName)
	err = ticket.DecryptEncPart(kt, nil)
	var missingKey KRBError
	require.ErrorAs(t, err, &missingKey)
	assert.IsType(t, missingKey, err)
	assert.Equal(t, errorcode.KRB_AP_ERR_NOKEY, missingKey.ErrorCode)
	assert.Equal(t, ticket.SName, missingKey.SName)

	_, _, err = NewTicket(
		cname, ticketTestRealm, sname, ticketTestRealm, types.NewKrbFlags(), keytab.New(),
		etypeID.AES256_CTS_HMAC_SHA1_96, 2, now, now, now, now,
	)
	require.Error(t, err, "NewTicket must reject an empty keytab")
}

func ticketPACFixture(t *testing.T) (Ticket, *keytab.Keytab, types.PrincipalName) {
	t.Helper()
	var ticket Ticket
	ticket.Realm = "TEST.GOKRB5"
	ticket.EncPart.EType = etypeID.AES256_CTS_HMAC_SHA1_96
	ticket.EncPart.KVNO = 2
	data := mustDecodeHex(t, testdata.MarshaledPAC_AuthorizationData_GOKRB5)
	require.NoError(t, ticket.DecryptedEncPart.AuthorizationData.Unmarshal(data))
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(mustDecodeHex(t, testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)))
	return ticket, kt, types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "sysHTTP")
}

func TestAuthorizationData_GetPACType_GOKRB5TestData(t *testing.T) {
	t.Parallel()

	tkt, kt, sname := ticketPACFixture(t)
	var logs bytes.Buffer
	logger := log.New(&logs, "", 0)
	isPAC, parsedPAC, err := tkt.GetPACType(kt, &sname, logger)
	require.NoError(t, err, "PAC logs: %s", logs.String())
	assert.True(t, isPAC, "PAC should be present")
	assert.Len(t, parsedPAC.Buffers, 5, "Number of buffers not as expected")
	assert.Equal(t, uint32(5), parsedPAC.CBuffers, "Count of buffers not as expected")
	assert.Equal(t, uint32(0), parsedPAC.Version, "PAC version not as expected")
	assert.NotNil(t, parsedPAC.KerbValidationInfo, "PAC Kerb Validation info is nil")
	assert.NotNil(t, parsedPAC.ClientInfo, "PAC Client Info info is nil")
	assert.NotNil(t, parsedPAC.UPNDNSInfo, "PAC UPN DNS Info info is nil")
	assert.NotNil(t, parsedPAC.KDCChecksum, "PAC KDC Checksum info is nil")
	assert.NotNil(t, parsedPAC.ServerChecksum, "PAC Server checksum info is nil")

	t.Run("option verification retains its cause", func(t *testing.T) {
		var options pac.VerifyOptions
		options.ExpectedClientName = "different-client"
		found, parsed, verifyErr := tkt.GetPACTypeWithOptions(kt, &sname, nil, options)
		assert.True(t, found)
		assert.NotNil(t, parsed.ClientInfo)
		assert.ErrorContains(t, verifyErr, "verify ticket PAC:")
		assert.ErrorContains(t, errors.Unwrap(verifyErr), "PAC client name")
	})
}

func TestTicketPACVerificationContext(t *testing.T) {
	t.Parallel()

	ticket, kt, sname := ticketPACFixture(t)
	ticket.SName = sname
	found, baseline, err := ticket.GetPACType(kt, nil, nil)
	require.NoError(t, err)
	require.True(t, found)
	require.NotNil(t, baseline.ClientInfo)

	client := baseline.ClientInfo.Name
	authTime := baseline.ClientInfo.ClientID.Time()
	ticket.DecryptedEncPart.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "other-client")
	ticket.DecryptedEncPart.AuthTime = authTime.Add(time.Second)
	for _, tt := range []struct {
		name        string
		override    func(*pac.VerifyOptions)
		wantContext string
	}{
		{
			name:        "ticket client name is checked by default",
			override:    func(o *pac.VerifyOptions) { o.ExpectedAuthTime = &authTime },
			wantContext: "PAC client name",
		},
		{
			name:        "ticket auth time is checked by default",
			override:    func(o *pac.VerifyOptions) { o.ExpectedClientName = client },
			wantContext: "PAC client authentication time",
		},
		{
			name: "explicit verification context takes precedence",
			override: func(o *pac.VerifyOptions) {
				o.ExpectedClientName = client
				o.ExpectedAuthTime = &authTime
			},
			wantContext: "",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var options pac.VerifyOptions
			tt.override(&options)
			found, parsed, err := ticket.GetPACTypeWithOptions(kt, nil, nil, options)
			assert.True(t, found)
			assert.Equal(t, baseline.ClientInfo, parsed.ClientInfo)
			if tt.wantContext == "" {
				require.NoError(t, err)
				return
			}
			require.ErrorContains(t, err, "verify ticket PAC:")
			assert.ErrorContains(t, errors.Unwrap(err), tt.wantContext)
		})
	}
}
