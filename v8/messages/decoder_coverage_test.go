package messages

import (
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/asn1tools"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/addrtype"
	"github.com/otuschhoff/gokrb5/v8/iana/adtype"
	"github.com/otuschhoff/gokrb5/v8/iana/asnAppTag"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	decoderExampleRealm          = "EXAMPLE.COM"
	decoderOtherRealm            = "EXAMPLE.ORG"
	decoderTicketGrantingService = "krbtgt"
)

type decoderVector struct {
	hex       string
	unmarshal func([]byte) error
}

func decoderVectorFor[T any, P interface {
	*T
	Unmarshal([]byte) error
}](fixtureHex string) decoderVector {
	return decoderVector{
		hex:       fixtureHex,
		unmarshal: func(b []byte) error { return P(new(T)).Unmarshal(b) },
	}
}

func messageUnmarshalVectors(tb testing.TB) map[string]decoderVector {
	tb.Helper()
	return map[string]decoderVector{
		"AS_REQ": decoderVectorFor[ASReq](testdata.MarshaledKRB5as_req),
		"AS_REQ optionals null except 2nd tkt": decoderVectorFor[ASReq](
			testdata.MarshaledKRB5as_reqOptionalsNULLexceptsecond_ticket,
		),
		"AS_REQ optionals null except server": decoderVectorFor[ASReq](
			testdata.MarshaledKRB5as_reqOptionalsNULLexceptserver,
		),
		"TGS_REQ": decoderVectorFor[TGSReq](testdata.MarshaledKRB5tgs_req),
		"TGS_REQ optionals null except 2nd tkt": decoderVectorFor[TGSReq](
			testdata.MarshaledKRB5tgs_reqOptionalsNULLexceptsecond_ticket,
		),
		"TGS_REQ optionals null except server": decoderVectorFor[TGSReq](
			testdata.MarshaledKRB5tgs_reqOptionalsNULLexceptserver,
		),
		"KDC_REQ_BODY":           decoderVectorFor[KDCReqBody](testdata.MarshaledKRB5kdc_req_body),
		"AS_REP":                 decoderVectorFor[ASRep](testdata.MarshaledKRB5as_rep),
		"AS_REP optionals null":  decoderVectorFor[ASRep](testdata.MarshaledKRB5as_repOptionalsNULL),
		"TGS_REP":                decoderVectorFor[TGSRep](testdata.MarshaledKRB5tgs_rep),
		"TGS_REP optionals null": decoderVectorFor[TGSRep](testdata.MarshaledKRB5tgs_repOptionalsNULL),
		"AP_REQ":                 decoderVectorFor[APReq](testdata.MarshaledKRB5ap_req),
		"AP_REP":                 decoderVectorFor[APRep](testdata.MarshaledKRB5ap_rep),
		"AP_REP enc part":        decoderVectorFor[EncAPRepPart](testdata.MarshaledKRB5ap_rep_enc_part),
		"AP_REP enc part optionals null": decoderVectorFor[EncAPRepPart](
			testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL,
		),
		"KRB_CRED":          decoderVectorFor[KRBCred](testdata.MarshaledKRB5cred),
		"KRB_CRED enc part": decoderVectorFor[EncKrbCredPart](testdata.MarshaledKRB5enc_cred_part),
		"KRB_CRED enc part optionals null": decoderVectorFor[EncKrbCredPart](
			testdata.MarshaledKRB5enc_cred_partOptionalsNULL,
		),
		"KRB_PRIV":          decoderVectorFor[KRBPriv](testdata.MarshaledKRB5priv),
		"KRB_PRIV enc part": decoderVectorFor[EncKrbPrivPart](testdata.MarshaledKRB5enc_priv_part),
		"KRB_PRIV enc part optionals null": decoderVectorFor[EncKrbPrivPart](
			testdata.MarshaledKRB5enc_priv_partOptionalsNULL,
		),
		"KRB_SAFE":                 decoderVectorFor[KRBSafe](testdata.MarshaledKRB5safe),
		"KRB_SAFE optionals null":  decoderVectorFor[KRBSafe](testdata.MarshaledKRB5safeOptionalsNULL),
		"KRB_ERROR":                decoderVectorFor[KRBError](testdata.MarshaledKRB5error),
		"KRB_ERROR optionals null": decoderVectorFor[KRBError](testdata.MarshaledKRB5errorOptionalsNULL),
		"Ticket":                   decoderVectorFor[Ticket](testdata.MarshaledKRB5ticket),
		"EncTicketPart":            decoderVectorFor[EncTicketPart](testdata.MarshaledKRB5enc_tkt_part),
		"EncTicketPart optionals null": decoderVectorFor[EncTicketPart](
			testdata.MarshaledKRB5enc_tkt_partOptionalsNULL,
		),
		"EncKDCRepPart": decoderVectorFor[EncKDCRepPart](testdata.MarshaledKRB5enc_kdc_rep_part),
		"EncKDCRepPart optionals null": decoderVectorFor[EncKDCRepPart](
			testdata.MarshaledKRB5enc_kdc_rep_partOptionalsNULL,
		),
	}
}

// TestMessageUnmarshalTruncationSweep unmarshals every strict prefix of every
// valid message vector: DER length framing must reject every truncation.
func TestMessageUnmarshalTruncationSweep(t *testing.T) {
	for name, vector := range messageUnmarshalVectors(t) {
		t.Run(name, func(t *testing.T) {
			b := mustDecodeHex(t, vector.hex)
			require.NoError(t, vector.unmarshal(b), "valid vector must parse")
			for length := range len(b) {
				if err := vector.unmarshal(b[:length]); err == nil {
					t.Fatalf("truncated prefix of length %d was accepted", length)
				}
			}
		})
	}
}

// TestMessageUnmarshalByteFlipRobustness flips every byte of representative
// vectors in turn; corrupted messages must never panic the decoders.
func TestMessageUnmarshalByteFlipRobustness(t *testing.T) {
	for _, name := range []string{
		"KDC_REQ_BODY",
		"AS_REQ",
		"TGS_REQ",
		"AS_REP",
		"TGS_REP",
		"AP_REQ",
		"KRB_CRED",
		"Ticket",
		"KRB_ERROR",
		"KRB_SAFE",
	} {
		t.Run(name, func(t *testing.T) {
			vector := messageUnmarshalVectors(t)[name]
			b := mustDecodeHex(t, vector.hex)
			for offset := range b {
				mutated := make([]byte, len(b))
				copy(mutated, b)
				mutated[offset] ^= 0xFF
				_ = vector.unmarshal(mutated)
			}
		})
	}
}

// TestKDCReqMsgTypeMismatch covers the message type validation branches with
// bytes that carry the correct application tag but the wrong inner msg-type.
func TestKDCReqMsgTypeMismatch(t *testing.T) {
	b := mustDecodeHex(t, testdata.MarshaledKRB5as_req)
	var m marshalKDCReq
	_, err := asn1.UnmarshalWithParams(b, &m, fmt.Sprintf("application,explicit,tag:%v", asnAppTag.ASREQ))
	require.NoError(t, err)

	m.MsgType = msgtype.KRB_TGS_REQ
	raw, err := asn1.Marshal(m)
	require.NoError(t, err)
	err = new(ASReq).Unmarshal(asn1tools.AddASNAppTag(raw, asnAppTag.ASREQ))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message ID does not indicate a AS_REQ")

	m.MsgType = msgtype.KRB_AS_REQ
	raw, err = asn1.Marshal(m)
	require.NoError(t, err)
	err = new(TGSReq).Unmarshal(asn1tools.AddASNAppTag(raw, asnAppTag.TGSREQ))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "message ID does not indicate a TGS_REQ")
}

// TestKDCReqBodyShortKDCOptionsPadded covers the short flag padding branch.
func TestKDCReqBodyShortKDCOptionsPadded(t *testing.T) {
	b := mustDecodeHex(t, testdata.MarshaledKRB5kdc_req_body)
	var m marshalKDCReqBody
	_, err := asn1.Unmarshal(b, &m)
	require.NoError(t, err)
	m.KDCOptions = asn1.BitString{Bytes: []byte{0x40, 0x00}, BitLength: 16}
	short, err := asn1.Marshal(m)
	require.NoError(t, err)
	var body KDCReqBody
	require.NoError(t, body.Unmarshal(short))
	assert.Len(t, body.KDCOptions.Bytes, 4, "short KDC options must be padded to 4 bytes")
	assert.Equal(t, byte(0), body.KDCOptions.Bytes[0])
	assert.Equal(t, byte(0x40), body.KDCOptions.Bytes[2])
}

// TestKDCReqBodyAdditionalTicketsError covers the additional-tickets rejection.
func TestKDCReqBodyAdditionalTicketsError(t *testing.T) {
	b := mustDecodeHex(t, testdata.MarshaledKRB5kdc_req_body)
	var m marshalKDCReqBody
	_, err := asn1.Unmarshal(b, &m)
	require.NoError(t, err)
	m.AdditionalTickets = asn1.RawValue{
		FullBytes:  nil,
		Class:      2,
		IsCompound: true,
		Tag:        11,
		Bytes:      []byte{0x61, 0x03, 0x1b, 0x01, 0x01},
	}
	crafted, err := asn1.Marshal(m)
	require.NoError(t, err)
	err = new(KDCReqBody).Unmarshal(crafted)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error unmarshaling additional tickets")
}

// TestUnmarshalTicketsSequenceErrors covers the ticket sequence rejections.
func TestUnmarshalTicketsSequenceErrors(t *testing.T) {
	// An application-tagged value whose content is not a valid ticket.
	var invalid asn1.RawValue
	invalid.Bytes = []byte{0x30, 0x05, 0x61, 0x03, 0x1b, 0x01, 0x01}
	tickets, err := unmarshalTicketsSequence(invalid)
	var structure asn1.StructuralError
	require.ErrorAs(t, err, &structure)
	assert.ErrorContains(t, err, "unmarshaling sequence of tickets failed: decode ticket:")
	assert.Nil(t, tickets)

	valid := mustDecodeHex(t, testdata.MarshaledKRB5ticket)
	ticket := mustUnmarshalTicket(t, valid)
	raw, err := MarshalTicketSequence([]Ticket{ticket, ticket})
	require.NoError(t, err)
	// A truncated second member must not publish the first one.
	raw.Bytes = raw.Bytes[:len(raw.Bytes)-1]
	tickets, err = unmarshalTicketsSequence(raw)
	var syntax asn1.SyntaxError
	require.ErrorAs(t, err, &syntax)
	assert.ErrorContains(t, err, "unmarshaling sequence of tickets failed getting length of ticket:")
	assert.Nil(t, tickets)
}

func mustUnmarshalTicket(t *testing.T, b []byte) Ticket {
	t.Helper()
	var tkt Ticket
	require.NoError(t, tkt.Unmarshal(b))
	return tkt
}

// TestNewTicketWithKeyEncryptError covers encryption rejection with a key
// whose size does not match a valid enctype.
func TestNewTicketWithKeyEncryptError(t *testing.T) {
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service")
	now := time.Now().UTC()
	shortKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}
	_, _, err := NewTicketWithKey(
		cname,
		decoderOtherRealm,
		sname,
		decoderOtherRealm,
		types.NewKrbFlags(),
		shortKey,
		1,
		now,
		now,
		now,
		now,
	)
	require.Error(t, err, "16-byte key must be rejected for AES256")
}

// TestTicketDecryptFailures covers decryption and plaintext rejection.
func TestTicketDecryptFailures(t *testing.T) {
	var zeroEncTicketPart EncTicketPart

	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	otherKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}

	ed, err := crypto.GetEncryptedData([]byte("plaintext that is not an EncTicketPart"), key, keyusage.KDC_REP_TICKET, 1)
	require.NoError(t, err)
	ticket := Ticket{
		DecryptedEncPart: zeroEncTicketPart,
		TktVNO:           5,
		Realm:            decoderOtherRealm,
		SName:            types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service"),
		EncPart:          ed,
	}

	err = ticket.Decrypt(otherKey)
	require.Error(t, err, "decryption with the wrong key must fail")

	err = ticket.Decrypt(key)
	require.Error(t, err, "non-EncTicketPart plaintext must fail")
	assert.Contains(t, err.Error(), "error unmarshaling encrypted part")
}

// TestTicketGetPACTypeWithOptions covers PAC extraction and validation states.
func TestTicketGetPACTypeWithOptions(t *testing.T) {
	logger := log.New(log.Writer(), "", 0)
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM")

	checkTicketMissingOrMalformedPAC(t, logger, sname)
	checkTicketPACVerification(t, logger, sname)
}

func checkTicketMissingOrMalformedPAC(t *testing.T, logger *log.Logger, sname types.PrincipalName) {
	t.Helper()

	t.Run("no PAC present", func(t *testing.T) {
		var zeroEncTicketPart EncTicketPart
		var zeroEncryptedData types.EncryptedData

		ticket := Ticket{
			TktVNO:           0,
			EncPart:          zeroEncryptedData,
			DecryptedEncPart: zeroEncTicketPart,
			SName:            sname,
			Realm:            decoderExampleRealm,
		}
		ok, _, err := ticket.GetPACTypeWithOptions(keytab.New(), nil, logger, pacVerifyOptions())
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("authorization data traversal failure", func(t *testing.T) {
		var zeroEncTicketPart EncTicketPart
		var zeroEncryptedData types.EncryptedData

		ticket := Ticket{
			TktVNO:           0,
			EncPart:          zeroEncryptedData,
			DecryptedEncPart: zeroEncTicketPart,
			SName:            sname,
			Realm:            decoderExampleRealm,
		}
		ticket.DecryptedEncPart.AuthorizationData = types.AuthorizationData{
			{ADType: adtype.ADIfRelevant, ADData: []byte{0xFF, 0xFF}},
		}
		_, _, err := ticket.GetPACTypeWithOptions(keytab.New(), nil, logger, pacVerifyOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PAC authorization data could not be traversed")
	})
	t.Run("malformed PAC", func(t *testing.T) {
		var zeroEncTicketPart EncTicketPart
		var zeroEncryptedData types.EncryptedData

		ticket := Ticket{
			TktVNO:           0,
			EncPart:          zeroEncryptedData,
			DecryptedEncPart: zeroEncTicketPart,
			SName:            sname,
			Realm:            decoderExampleRealm,
		}
		ticket.DecryptedEncPart.AuthorizationData = types.AuthorizationData{
			{ADType: adtype.ADWin2KPAC, ADData: []byte{0xFF, 0xFF, 0xFF}},
		}
		ok, _, err := ticket.GetPACTypeWithOptions(keytab.New(), nil, logger, pacVerifyOptions())
		require.Error(t, err)
		assert.True(t, ok)
		assert.Contains(t, err.Error(), "error unmarshaling PAC")
	})
}

func checkTicketPACVerification(t *testing.T, logger *log.Logger, sname types.PrincipalName) {
	t.Helper()

	t.Run("valid PAC without key", func(t *testing.T) {
		ticket := ticketWithPAC(t, sname)
		ok, _, err := ticket.GetPACTypeWithOptions(keytab.New(), nil, logger, pacVerifyOptions())
		require.Error(t, err)
		assert.True(t, ok)
		var krbErr KRBError
		require.ErrorAs(t, err, &krbErr)
		assert.IsType(t, krbErr, err, "missing key must return a concrete KRB-ERROR")
		assert.Equal(t, errorcode.KRB_AP_ERR_NOKEY, krbErr.ErrorCode)
	})
	t.Run("valid PAC with wrong key", func(t *testing.T) {
		ticket := ticketWithPAC(t, sname)
		kt := keytab.New()
		require.NoError(t, kt.AddKey(keytab.Principal{
			Realm:      decoderExampleRealm,
			Components: []string{decoderTicketGrantingService, decoderExampleRealm},
			NameType:   nametype.KRB_NT_SRV_INST,
		}, 1, types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}, time.Now()))
		found, _, err := ticket.GetPACTypeWithOptions(kt, nil, logger, pacVerifyOptions())
		require.Error(t, err, "PAC verification with the wrong key must fail")
		if !found || !strings.HasPrefix(err.Error(), "process ticket PAC buffers:") || errors.Unwrap(err) == nil {
			t.Fatalf("expected a wrapped PAC processing failure, got %v", err)
		}
	})
}

func ticketWithPAC(t *testing.T, sname types.PrincipalName) Ticket {
	t.Helper()
	var zeroEncTicketPart EncTicketPart

	ticket := Ticket{
		TktVNO:           0,
		DecryptedEncPart: zeroEncTicketPart,

		SName: sname,
		Realm: decoderExampleRealm,
		EncPart: types.EncryptedData{
			Cipher: nil,
			EType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KVNO:   1,
		},
	}
	ticket.DecryptedEncPart.AuthorizationData = types.AuthorizationData{
		{ADType: adtype.ADWin2KPAC, ADData: mustDecodeHex(t, testdata.MarshaledPAC_AD_WIN2K_PAC)},
	}
	return ticket
}

// pacVerifyOptions returns zero-value PAC verify options without exporting pac.
func pacVerifyOptions() pac.VerifyOptions {
	return pac.VerifyOptions{
		KDCKey:                nil,
		TicketData:            nil,
		ExpectedClientName:    "",
		ExpectedAuthTime:      nil,
		RequireFullChecksum:   false,
		RequireTicketChecksum: false,
	}
}

// TestKRBCredCrypto covers construction, encryption, and decryption failures.
func TestKRBCredCrypto(t *testing.T) {
	var zeroBitString asn1.BitString
	var zeroPrincipalName types.PrincipalName
	var zeroTime time.Time

	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	badKey := types.EncryptionKey{KeyType: -1, KeyValue: make([]byte, 32)}
	info := KrbCredInfo{
		PRealm:    "",
		PName:     zeroPrincipalName,
		Flags:     zeroBitString,
		AuthTime:  zeroTime,
		StartTime: zeroTime,
		EndTime:   zeroTime,
		RenewTill: zeroTime,
		SName:     zeroPrincipalName,
		CAddr:     nil,
		Key:       key,
		SRealm:    decoderExampleRealm,
	}
	tickets := []Ticket{mustUnmarshalTicket(t, mustDecodeHex(t, testdata.MarshaledKRB5ticket))}

	checkKRBCredConstruction(t, key, badKey, info, tickets)
	checkKRBCredCryptoFailures(t, key, badKey)
}

func checkKRBCredConstruction(t *testing.T, key, badKey types.EncryptionKey, info KrbCredInfo, tickets []Ticket) {
	t.Helper()

	t.Run("constructor rejects ticket-info count mismatch", func(t *testing.T) {
		_, err := NewKRBCred(nil, []KrbCredInfo{info}, key)
		require.Error(t, err)
	})
	t.Run("constructor rejects unknown enctype", func(t *testing.T) {
		_, err := NewKRBCred(tickets, []KrbCredInfo{info}, badKey)
		require.Error(t, err)
	})
	t.Run("round trip and wrong key", func(t *testing.T) {
		cred, err := NewKRBCred(tickets, []KrbCredInfo{info}, key)
		require.NoError(t, err)
		other := types.EncryptionKey{
			KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KeyValue: append([]byte{1}, make([]byte, 31)...),
		}
		require.Error(t, cred.DecryptEncPart(other))
		require.NoError(t, cred.DecryptEncPart(key))
		require.Len(t, cred.DecryptedEncPart.TicketInfo, 1)
	})
}

func checkKRBCredCryptoFailures(t *testing.T, key, badKey types.EncryptionKey) {
	t.Helper()

	t.Run("encrypt rejects unknown enctype", func(t *testing.T) {
		cred := krbCredWithEmptyTicketInfo()
		require.Error(t, cred.EncryptEncPart(badKey))
	})
	t.Run("decrypt rejects wrong key", func(t *testing.T) {
		cred := krbCredWithEmptyTicketInfo()
		require.NoError(t, cred.EncryptEncPart(key))
		other := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}
		require.Error(t, cred.DecryptEncPart(other))
	})
}

func krbCredWithEmptyTicketInfo() KRBCred {
	var cred KRBCred
	var info KrbCredInfo
	cred.DecryptedEncPart.TicketInfo = []KrbCredInfo{info}
	return cred
}

// TestKRBPrivCrypto covers KRBPriv encryption and decryption.
func TestKRBPrivCrypto(t *testing.T) {
	var zeroHostAddress types.HostAddress
	var zeroTime time.Time

	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	badKey := types.EncryptionKey{
		KeyValue: nil,
		KeyType:  -1,
	}
	priv := NewKRBPriv(EncKrbPrivPart{
		Timestamp:      zeroTime,
		Usec:           0,
		SequenceNumber: 0,
		SAddress:       zeroHostAddress,
		RAddress:       zeroHostAddress,
		UserData:       []byte("confidential"),
	})

	encryptErr := priv.EncryptEncPart(badKey)
	assert.ErrorContains(t, encryptErr, "encrypt KRB-PRIV encrypted part:")
	assert.ErrorContains(t, errors.Unwrap(encryptErr), "error getting etype:")
	require.NoError(t, priv.EncryptEncPart(key))
	other := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}
	require.Error(t, priv.DecryptEncPart(other))
	require.NoError(t, priv.DecryptEncPart(key))
	assert.Equal(t, []byte("confidential"), priv.DecryptedEncPart.UserData)
}

// TestAPRepCryptoErrors covers AP_REP encryption and decryption failures.
func TestAPRepCryptoErrors(t *testing.T) {
	var zeroChecksum types.Checksum
	var zeroEncryptedData types.EncryptedData
	var zeroEncryptionKey types.EncryptionKey

	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	badKey := types.EncryptionKey{
		KeyValue: nil,
		KeyType:  -1,
	}
	part := EncAPRepPart{
		Subkey:         zeroEncryptionKey,
		SequenceNumber: 0,
		CTime:          time.Now().UTC(),
		Cusec:          123,
	}

	_, err := NewAPRep(part, badKey)
	require.Error(t, err)

	auth := types.Authenticator{
		Cksum:             zeroChecksum,
		Cusec:             0,
		SubKey:            zeroEncryptionKey,
		SeqNumber:         0,
		AuthorizationData: nil,
		AVNO:              5,
		CRealm:            decoderExampleRealm,
		CName:             types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"),
		CTime:             time.Now().UTC(),
	}
	_, err = NewAPRepFromAuthenticator(auth, badKey, key, 1)
	require.Error(t, err)

	rep, err := NewAPRep(part, key)
	require.NoError(t, err)
	other := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}
	require.Error(t, rep.DecryptEncPart(other))
	require.NoError(t, rep.DecryptEncPart(key))
	assert.Equal(t, 123, rep.DecryptedEncPart.Cusec)

	rep2 := APRep{
		PVNO:             0,
		MsgType:          0,
		EncPart:          zeroEncryptedData,
		DecryptedEncPart: part,
	}
	require.Error(t, rep2.EncryptEncPart(badKey))
}

// TestAPReqCryptoErrors covers AP_REQ authenticator encryption failures.
func TestAPReqCryptoErrors(t *testing.T) {
	var zeroChecksum types.Checksum
	var zeroEncryptionKey types.EncryptionKey

	badKey := types.EncryptionKey{
		KeyValue: nil,
		KeyType:  -1,
	}
	auth := types.Authenticator{
		Cksum:             zeroChecksum,
		Cusec:             0,
		SubKey:            zeroEncryptionKey,
		SeqNumber:         0,
		AuthorizationData: nil,
		AVNO:              5,
		CRealm:            decoderExampleRealm,
		CName:             types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"),
		CTime:             time.Now().UTC(),
	}
	_, err := NewAPReq(s4uTestTicket(), badKey, auth)
	require.Error(t, err)
	_, err = NewAPReqWithKeyUsage(s4uTestTicket(), badKey, auth, keyusage.AP_REQ_AUTHENTICATOR)
	require.Error(t, err)

	reqBytes := mustDecodeHex(t, testdata.MarshaledKRB5ap_req)
	var req APReq
	require.NoError(t, req.Unmarshal(reqBytes))
	wrongKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	require.Error(t, req.DecryptAuthenticator(wrongKey))
}

// TestKDCRepDecryptFailures covers reply decryption with wrong keys.
func TestKDCRepDecryptFailures(t *testing.T) {
	wrongKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}

	var asRep ASRep
	require.NoError(t, asRep.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5as_rep)))
	require.Error(t, asRep.DecryptEncPartWithKey(wrongKey))

	var tgsRep TGSRep
	require.NoError(t, tgsRep.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5tgs_rep)))
	require.Error(t, tgsRep.DecryptEncPart(wrongKey))
	require.Error(t, tgsRep.DecryptEncPartWithKeyUsage(wrongKey, keyusage.TGS_REP_ENCPART_SESSION_KEY))
}

// TestS4UErrorPaths covers the S4U PA-DATA construction and reply rejection
// branches.
func TestS4UErrorPaths(t *testing.T) {
	cfg := s4uTestConfig()
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	key := types.EncryptionKey{
		KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
		KeyValue: []byte("0123456789abcdeffedcba9876543210"),
	}

	checkS4UPAData(t, user)
	checkS4UReplyPresence(t, cfg, service, user, key)
	checkS4UReplyNonceAndChecksumType(t, cfg, service, user, key)
	checkS4UReplyChecksum(t, cfg, service, user, key)
}

func checkS4UPAData(t *testing.T, user types.PrincipalName) {
	t.Helper()

	t.Run("X509 PA data rejects unknown enctype", func(t *testing.T) {
		var zeroBitString asn1.BitString

		_, err := NewPAS4UX509UserPAData(types.S4UUserID{
			Nonce:              0,
			SubjectCertificate: nil,
			Options:            zeroBitString,
			CName:              user,
			CRealm:             decoderExampleRealm,
		}, types.EncryptionKey{
			KeyValue: nil,
			KeyType:  -1,
		})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get S4U session key etype")
	})
	t.Run("find requires the PA type", func(t *testing.T) {
		_, err := findS4UX509User(types.PADataSequence{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PA-S4U-X509-USER is missing")
	})
}

func checkS4UReplyPresence(
	t *testing.T,
	cfg *config.Config,
	service, user types.PrincipalName,
	key types.EncryptionKey,
) {
	t.Helper()

	t.Run("reply verification requires request PA", func(t *testing.T) {
		var zeroKDCReqFields KDCReqFields

		_, err := new(TGSRep).VerifyS4UX509UserReply(TGSReq{
			KDCReqFields: zeroKDCReqFields,
		}, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "S4U request")
	})
	t.Run("reply verification requires reply PA", func(t *testing.T) {
		var zeroTGSReqOptions TGSReqOptions

		req, err := NewS4U2SelfTGSReq(
			service,
			decoderExampleRealm,
			cfg,
			s4uTestTicket(),
			key,
			service,
			user,
			decoderExampleRealm,
			S4U2SelfReqOptions{
				TGSReqOptions:      zeroTGSReqOptions,
				SubjectCertificate: nil,
				PAForUserOnly:      false,
			},
		)
		require.NoError(t, err)
		_, err = new(TGSRep).VerifyS4UX509UserReply(req, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "S4U reply")
	})
}

func checkS4UReplyNonceAndChecksumType(
	t *testing.T,
	cfg *config.Config,
	service, user types.PrincipalName,
	key types.EncryptionKey,
) {
	t.Helper()

	t.Run("nonce mismatch", func(t *testing.T) {
		var zeroTGSReqOptions TGSReqOptions

		req, err := NewS4U2SelfTGSReq(
			service,
			decoderExampleRealm,
			cfg,
			s4uTestTicket(),
			key,
			service,
			user,
			decoderExampleRealm,
			S4U2SelfReqOptions{
				TGSReqOptions:      zeroTGSReqOptions,
				SubjectCertificate: nil,
				PAForUserOnly:      false,
			},
		)
		require.NoError(t, err)
		reply := s4uReply(t, mustNonceUint32(t, req.ReqBody.Nonce)+1, key, user, false)
		_, err = reply.VerifyS4UX509UserReply(req, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce")
	})
	t.Run("checksum type mismatch", func(t *testing.T) {
		var zeroTGSReqOptions TGSReqOptions

		req, err := NewS4U2SelfTGSReq(
			service,
			decoderExampleRealm,
			cfg,
			s4uTestTicket(),
			key,
			service,
			user,
			decoderExampleRealm,
			S4U2SelfReqOptions{
				TGSReqOptions:      zeroTGSReqOptions,
				SubjectCertificate: nil,
				PAForUserOnly:      false,
			},
		)
		require.NoError(t, err)
		reply := s4uReply(t, mustNonceUint32(t, req.ReqBody.Nonce), key, user, true)
		_, err = reply.VerifyS4UX509UserReply(req, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum type")
	})
}

func checkS4UReplyChecksum(
	t *testing.T,
	cfg *config.Config,
	service, user types.PrincipalName,
	key types.EncryptionKey,
) {
	t.Helper()

	t.Run("checksum invalid", func(t *testing.T) {
		var zeroTGSReqOptions TGSReqOptions

		req, err := NewS4U2SelfTGSReq(
			service,
			decoderExampleRealm,
			cfg,
			s4uTestTicket(),
			key,
			service,
			user,
			decoderExampleRealm,
			S4U2SelfReqOptions{
				TGSReqOptions:      zeroTGSReqOptions,
				SubjectCertificate: nil,
				PAForUserOnly:      false,
			},
		)
		require.NoError(t, err)
		other := types.EncryptionKey{KeyType: key.KeyType, KeyValue: append([]byte{0xFF}, key.KeyValue[1:]...)}
		reply := s4uReply(t, mustNonceUint32(t, req.ReqBody.Nonce), other, user, false)
		_, err = reply.VerifyS4UX509UserReply(req, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum invalid")
	})
	t.Run("valid reply accepted", func(t *testing.T) {
		var zeroTGSReqOptions TGSReqOptions

		req, err := NewS4U2SelfTGSReq(
			service,
			decoderExampleRealm,
			cfg,
			s4uTestTicket(),
			key,
			service,
			user,
			decoderExampleRealm,
			S4U2SelfReqOptions{
				TGSReqOptions:      zeroTGSReqOptions,
				SubjectCertificate: nil,
				PAForUserOnly:      false,
			},
		)
		require.NoError(t, err)
		reply := s4uReply(t, mustNonceUint32(t, req.ReqBody.Nonce), key, user, false)
		userID, err := reply.VerifyS4UX509UserReply(req, key)
		require.NoError(t, err)
		assert.Equal(t, user.PrincipalNameString(), userID.CName.PrincipalNameString())
	})
}

// s4uReply builds a TGS reply carrying a PA-S4U-X509-USER answer computed with
// the reply key usage and the reply-usage flag acknowledged; wrongCksumType
// corrupts the checksum type.
func s4uReply(
	t *testing.T,
	nonce uint32,
	key types.EncryptionKey,
	user types.PrincipalName,
	wrongCksumType bool,
) TGSRep {
	t.Helper()
	var zeroEncKDCRepPart EncKDCRepPart
	var zeroEncryptedData types.EncryptedData
	var zeroPrincipalName types.PrincipalName
	var zeroTicket Ticket

	options := types.NewKrbFlags()
	types.SetFlag(&options, flags.S4UOptionUseReplyKeyUsage)
	userID := types.S4UUserID{
		SubjectCertificate: nil,
		Nonce:              nonce,
		CName:              user,
		CRealm:             decoderExampleRealm,
		Options:            options,
	}
	userIDBytes, err := userID.Marshal()
	require.NoError(t, err)
	etype, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)
	checksum, err := etype.GetChecksumHash(key.KeyValue, userIDBytes, keyusage.PA_S4U_X509_USER_REPLY)
	require.NoError(t, err)
	cksumType := etype.GetHashID()
	if wrongCksumType {
		cksumType = -1
	}
	value, err := types.NewPAS4UX509User(userID, types.Checksum{CksumType: cksumType, Checksum: checksum})
	require.NoError(t, err)
	pa, err := types.NewPAS4UX509UserPAData(value)
	require.NoError(t, err)
	return TGSRep{KDCRepFields: KDCRepFields{
		PVNO:             0,
		MsgType:          0,
		CRealm:           "",
		CName:            zeroPrincipalName,
		Ticket:           zeroTicket,
		EncPart:          zeroEncryptedData,
		DecryptedEncPart: zeroEncKDCRepPart,
		PAData:           types.PADataSequence{pa},
	}}
}

// TestKRBErrorTypedData covers METHOD-DATA, KERB-ERROR-DATA, and NTSTATUS
// extraction branches.
func TestKRBErrorTypedData(t *testing.T) {
	checkKRBErrorMethodData(t)
	checkKRBErrorMalformedData(t)
	checkKRBErrorNTStatus(t)
}

func checkKRBErrorMethodData(t *testing.T) {
	t.Helper()

	t.Run("method data requires preauth codes", func(t *testing.T) {
		e := NewKRBError(
			types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, decoderTicketGrantingService),
			decoderExampleRealm,
			errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
			"x",
		)
		_, err := e.MethodData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not carry METHOD-DATA")
	})
	t.Run("method data rejects corrupt edata", func(t *testing.T) {
		e := NewKRBError(
			types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, decoderTicketGrantingService),
			decoderExampleRealm,
			errorcode.KDC_ERR_PREAUTH_REQUIRED,
			"x",
		)
		e.EData = []byte{0xFF, 0xFF}
		_, err := e.MethodData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode KRB-ERROR METHOD-DATA")
	})
	t.Run("method data rejects trailing bytes", func(t *testing.T) {
		e := NewKRBError(
			types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, decoderTicketGrantingService),
			decoderExampleRealm,
			errorcode.KDC_ERR_PREAUTH_REQUIRED,
			"x",
		)
		e.EData = append(mustDecodeHex(t, testdata.MarshaledKRB5padata_sequence), 0x05, 0x00)
		_, err := e.MethodData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trailing bytes")
	})
	t.Run("method data decodes", func(t *testing.T) {
		e := NewKRBError(
			types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, decoderTicketGrantingService),
			decoderExampleRealm,
			errorcode.KDC_ERR_PREAUTH_REQUIRED,
			"x",
		)
		e.EData = mustDecodeHex(t, testdata.MarshaledKRB5padata_sequence)
		pa, err := e.MethodData()
		require.NoError(t, err)
		assert.NotEmpty(t, pa)
	})
}

func checkKRBErrorMalformedData(t *testing.T) {
	t.Helper()

	t.Run("kerb error data rejects corrupt edata", func(t *testing.T) {
		var zeroPrincipalName types.PrincipalName
		var zeroTime time.Time

		e := KRBError{
			PVNO:      0,
			MsgType:   0,
			CTime:     zeroTime,
			Cusec:     0,
			STime:     zeroTime,
			Susec:     0,
			ErrorCode: 0,
			CRealm:    "",
			CName:     zeroPrincipalName,
			Realm:     "",
			SName:     zeroPrincipalName,
			EText:     "",
			EData:     []byte{0xFF},
		}
		_, err := e.KerbErrorData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode KRB-ERROR-DATA")
	})
	t.Run("ntstatus absent without valid edata", func(t *testing.T) {
		var zeroPrincipalName types.PrincipalName
		var zeroTime time.Time

		_, ok := KRBError{
			PVNO:      0,
			MsgType:   0,
			CTime:     zeroTime,
			Cusec:     0,
			STime:     zeroTime,
			Susec:     0,
			ErrorCode: 0,
			CRealm:    "",
			CName:     zeroPrincipalName,
			Realm:     "",
			SName:     zeroPrincipalName,
			EText:     "",
			EData:     []byte{0xFF},
		}.NTStatus()
		assert.False(t, ok)
	})
}

func checkKRBErrorNTStatus(t *testing.T) {
	t.Helper()

	t.Run("ntstatus from extended error", func(t *testing.T) {
		var zeroPrincipalName types.PrincipalName
		var zeroTime time.Time

		errorData, err := types.NewKerbExtErrorData(types.KerbExtError{
			Reserved: 0,
			Flags:    0,
			Status:   ntstatus.STATUS_ACCOUNT_DISABLED,
		})
		require.NoError(t, err)
		status, ok := KRBError{
			PVNO:      0,
			MsgType:   0,
			CTime:     zeroTime,
			Cusec:     0,
			STime:     zeroTime,
			Susec:     0,
			ErrorCode: 0,
			CRealm:    "",
			CName:     zeroPrincipalName,
			Realm:     "",
			SName:     zeroPrincipalName,
			EText:     "",
			EData:     errorDataBytes(t, errorData),
		}.NTStatus()
		require.True(t, ok)
		assert.Equal(t, ntstatus.STATUS_ACCOUNT_DISABLED, status)
	})
	t.Run("ntstatus absent for other data types", func(t *testing.T) {
		var zeroPrincipalName types.PrincipalName
		var zeroTime time.Time

		errorData, err := types.NewKerbExtErrorData(types.KerbExtError{
			Reserved: 0,
			Flags:    0,
			Status:   ntstatus.STATUS_ACCOUNT_DISABLED,
		})
		require.NoError(t, err)
		errorData.DataType = int32(msflags.KERB_AP_ERR_TYPE_SKEW_RECOVERY)
		_, ok := KRBError{
			PVNO:      0,
			MsgType:   0,
			CTime:     zeroTime,
			Cusec:     0,
			STime:     zeroTime,
			Susec:     0,
			ErrorCode: 0,
			CRealm:    "",
			CName:     zeroPrincipalName,
			Realm:     "",
			SName:     zeroPrincipalName,
			EText:     "",
			EData:     errorDataBytes(t, errorData),
		}.NTStatus()
		assert.False(t, ok)
	})
}

func errorDataBytes(t *testing.T, data types.KerbErrorData) []byte {
	t.Helper()
	b, err := data.Marshal()
	require.NoError(t, err)
	return b
}

// TestMessageMarshalRoundTrips marshals every parsed message vector back to
// DER and parses it again, covering the marshal success paths.
func TestMessageMarshalRoundTrips(t *testing.T) {
	t.Run("AS_REQ", func(t *testing.T) {
		checkMessageRoundTrip[ASReq](t, testdata.MarshaledKRB5as_req)
	})
	t.Run("TGS_REQ", func(t *testing.T) {
		checkMessageRoundTrip[TGSReq](t, testdata.MarshaledKRB5tgs_req)
	})
	t.Run("KDC_REQ_BODY", func(t *testing.T) {
		checkMessageRoundTrip[KDCReqBody](t, testdata.MarshaledKRB5kdc_req_body)
	})
	t.Run("AS_REP", func(t *testing.T) {
		checkMessageRoundTrip[ASRep](t, testdata.MarshaledKRB5as_rep)
	})
	t.Run("TGS_REP", func(t *testing.T) {
		checkMessageRoundTrip[TGSRep](t, testdata.MarshaledKRB5tgs_rep)
	})
	t.Run("EncKDCRepPart", func(t *testing.T) {
		checkMessageRoundTrip[EncKDCRepPart](t, testdata.MarshaledKRB5enc_kdc_rep_part)
	})
	t.Run("AP_REQ", func(t *testing.T) {
		checkMessageRoundTrip[APReq](t, testdata.MarshaledKRB5ap_req)
	})
	t.Run("AP_REP", func(t *testing.T) {
		checkMessageRoundTrip[APRep](t, testdata.MarshaledKRB5ap_rep)
	})
	t.Run("AP_REP enc part", func(t *testing.T) {
		checkMessageRoundTrip[EncAPRepPart](t, testdata.MarshaledKRB5ap_rep_enc_part)
	})
	t.Run("KRB_CRED", func(t *testing.T) {
		checkMessageRoundTrip[KRBCred](t, testdata.MarshaledKRB5cred)
	})
	t.Run("KRB_CRED enc part", func(t *testing.T) {
		checkMessageRoundTrip[EncKrbCredPart](t, testdata.MarshaledKRB5enc_cred_part)
	})
	t.Run("KRB_PRIV", func(t *testing.T) {
		checkMessageRoundTrip[KRBPriv](t, testdata.MarshaledKRB5priv)
	})
	t.Run("KRB_ERROR", func(t *testing.T) {
		checkMessageRoundTrip[KRBError](t, testdata.MarshaledKRB5error)
	})
	t.Run("Ticket", func(t *testing.T) {
		checkMessageRoundTrip[Ticket](t, testdata.MarshaledKRB5ticket)
	})
}

func checkMessageRoundTrip[T any, P interface {
	*T
	Marshal() ([]byte, error)
	Unmarshal([]byte) error
}](t *testing.T, fixtureHex string) {
	t.Helper()
	var m T
	require.NoError(t, P(&m).Unmarshal(mustDecodeHex(t, fixtureHex)))
	b, err := P(&m).Marshal()
	require.NoError(t, err)
	require.NoError(t, P(new(T)).Unmarshal(b))
}

// TestTGSReqConstructorsRejectBadSessionKey covers the PA-TGS-REQ construction
// failure branches of every TGS request constructor.
func TestTGSReqConstructorsRejectBadSessionKey(t *testing.T) {
	var zeroS4U2SelfReqOptions S4U2SelfReqOptions
	var zeroTGSReqOptions TGSReqOptions

	cfg := s4uTestConfig()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service")
	badKey := types.EncryptionKey{KeyType: -1, KeyValue: nil}
	tgt := s4uTestTicket()

	if _, err := NewTGSReqWithOptions(
		cname,
		decoderExampleRealm,
		cfg,
		tgt,
		badKey,
		sname,
		false,
		zeroTGSReqOptions,
	); err == nil {
		t.Fatal("NewTGSReqWithOptions accepted an unknown enctype session key")
	}
	if _, err := NewS4U2SelfTGSReq(
		cname,
		decoderExampleRealm,
		cfg,
		tgt,
		badKey,
		sname,
		cname,
		decoderExampleRealm,
		zeroS4U2SelfReqOptions,
	); err == nil {
		t.Fatal("NewS4U2SelfTGSReq accepted an unknown enctype session key")
	}
	if _, err := NewS4U2ProxyTGSReq(
		cname,
		decoderExampleRealm,
		cfg,
		tgt,
		badKey,
		sname,
		tgt,
		zeroTGSReqOptions,
	); err == nil {
		t.Fatal("NewS4U2ProxyTGSReq accepted an unknown enctype session key")
	}
	if _, err := NewUser2UserTGSReqWithOptions(
		cname,
		decoderExampleRealm,
		cfg,
		tgt,
		badKey,
		sname,
		false,
		tgt,
		zeroTGSReqOptions,
	); err == nil {
		t.Fatal("NewUser2UserTGSReqWithOptions accepted an unknown enctype session key")
	}
}

// TestTGSRepDecryptEncPartWithKeyUsage covers both reply key usages.
func TestTGSRepDecryptEncPartWithKeyUsage(t *testing.T) {
	var zeroTime time.Time

	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	part := EncKDCRepPart{
		KeyExpiration: zeroTime,
		StartTime:     zeroTime,
		EndTime:       zeroTime,
		RenewTill:     zeroTime,
		CAddr:         nil,
		EncPAData:     nil,

		Key:      key,
		LastReqs: []LastReq{{LRType: 0, LRValue: time.Now().UTC()}},
		Nonce:    42,
		Flags:    types.NewKrbFlags(),
		AuthTime: time.Now().UTC(),
		SName:    types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service"),
		SRealm:   decoderExampleRealm,
	}
	for name, usage := range map[string]uint32{
		"session key":          keyusage.TGS_REP_ENCPART_SESSION_KEY,
		"authenticator subkey": keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY,
	} {
		t.Run(name, func(t *testing.T) {
			var zeroKDCRepFields KDCRepFields

			raw, err := part.Marshal()
			require.NoError(t, err)
			ed, err := crypto.GetEncryptedData(raw, key, usage, 1)
			require.NoError(t, err)
			rep := TGSRep{
				KDCRepFields: zeroKDCRepFields,
			}
			rep.EncPart = ed
			require.NoError(t, rep.DecryptEncPartWithKeyUsage(key, usage))
			assert.Equal(t, 42, rep.DecryptedEncPart.Nonce)
		})
	}
}

// TestTicketValidAt covers ticket validity windows and the invalid flag.
func TestTicketValidAt(t *testing.T) {
	now := time.Now().UTC()
	validTicket := func() Ticket {
		var zeroEncTicketPart EncTicketPart
		var zeroEncryptedData types.EncryptedData

		tkt := Ticket{
			TktVNO:           0,
			EncPart:          zeroEncryptedData,
			DecryptedEncPart: zeroEncTicketPart,
			SName:            types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service"),
			Realm:            decoderExampleRealm,
		}
		tkt.DecryptedEncPart.StartTime = now.Add(-time.Hour)
		tkt.DecryptedEncPart.EndTime = now.Add(time.Hour)
		return tkt
	}
	t.Run("valid", func(t *testing.T) {
		tkt := validTicket()
		ok, err := tkt.ValidAt(now, 5*time.Minute)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("not yet valid", func(t *testing.T) {
		tkt := validTicket()
		tkt.DecryptedEncPart.StartTime = now.Add(time.Hour)
		ok, err := tkt.ValidAt(now, 5*time.Minute)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "not yet valid")
	})
	t.Run("invalid flag", func(t *testing.T) {
		tkt := validTicket()
		types.SetFlag(&tkt.DecryptedEncPart.Flags, flags.Invalid)
		ok, err := tkt.ValidAt(now, 5*time.Minute)
		require.Error(t, err)
		assert.False(t, ok)
	})
	t.Run("expired", func(t *testing.T) {
		tkt := validTicket()
		tkt.DecryptedEncPart.EndTime = now.Add(-time.Hour)
		ok, err := tkt.ValidAt(now, 5*time.Minute)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "has expired")
	})
	t.Run("expired within skew", func(t *testing.T) {
		tkt := validTicket()
		tkt.DecryptedEncPart.EndTime = now.Add(-time.Minute)
		ok, err := tkt.ValidAt(now, 5*time.Minute)
		require.NoError(t, err)
		assert.True(t, ok)
	})
}

// TestKRBErrorErrorString covers the extended text branches of Error.
func TestKRBErrorErrorString(t *testing.T) {
	plain := NewKRBError(
		types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM"),
		decoderExampleRealm,
		errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
		"",
	)
	assert.NotContains(t, plain.Error(), " - ")

	withText := NewKRBError(
		types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM"),
		decoderExampleRealm,
		errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
		"detail text",
	)
	assert.Contains(t, withText.Error(), "detail text")

	errorData, err := types.NewKerbExtErrorData(types.KerbExtError{
		Reserved: 0,
		Flags:    0,
		Status:   ntstatus.STATUS_ACCOUNT_DISABLED,
	})
	require.NoError(t, err)
	withStatus := NewKRBError(
		types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM"),
		decoderExampleRealm,
		errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
		"detail text",
	)
	withStatus.EData = errorDataBytes(t, errorData)
	assert.Contains(t, withStatus.Error(), ntstatus.STATUS_ACCOUNT_DISABLED.String())
}

// TestAPRepVerifyDCETransitions covers DCE-style AP-REP verification transitions.
func TestAPRepVerifyDCETransitions(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	now := time.Now().UTC()
	withSubkey := EncAPRepPart{
		CTime:          now,
		Cusec:          42,
		Subkey:         types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)},
		SequenceNumber: 7,
	}

	t.Run("success", func(t *testing.T) {
		rep, err := NewAPRep(withSubkey, key)
		require.NoError(t, err)
		require.NoError(t, rep.VerifyDCE(key, 7, false, 5*time.Minute))
	})
	t.Run("peer-selected sequence accepted", func(t *testing.T) {
		rep, err := NewAPRep(withSubkey, key)
		require.NoError(t, err)
		require.NoError(t, rep.VerifyDCE(key, -1, false, 5*time.Minute))
	})
	t.Run("sequence mismatch", func(t *testing.T) {
		rep, err := NewAPRep(withSubkey, key)
		require.NoError(t, err)
		err = rep.VerifyDCE(key, 8, false, 5*time.Minute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "sequence number does not match")
	})
	t.Run("final reply with subkey rejected", func(t *testing.T) {
		rep, err := NewAPRep(withSubkey, key)
		require.NoError(t, err)
		err = rep.VerifyDCE(key, 7, true, 5*time.Minute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "must not contain a subkey")
	})
	t.Run("final reply without subkey", func(t *testing.T) {
		part := withSubkey
		part.Subkey = types.EncryptionKey{
			KeyType:  0,
			KeyValue: nil,
		}
		rep, err := NewAPRep(part, key)
		require.NoError(t, err)
		require.NoError(t, rep.VerifyDCE(key, 7, true, 5*time.Minute))
	})
	t.Run("timestamp beyond skew", func(t *testing.T) {
		part := withSubkey
		part.CTime = now.Add(-2 * time.Hour)
		rep, err := NewAPRep(part, key)
		require.NoError(t, err)
		err = rep.VerifyDCE(key, 7, false, 5*time.Minute)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "exceeds clock skew")
	})
	t.Run("wrong key", func(t *testing.T) {
		rep, err := NewAPRep(withSubkey, key)
		require.NoError(t, err)
		other := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}
		require.Error(t, rep.VerifyDCE(other, 7, false, 5*time.Minute))
	})
}

// TestAPRepVerify covers the authenticator timestamp comparison.
func TestAPRepVerify(t *testing.T) {
	var zeroChecksum types.Checksum
	var zeroEncryptionKey types.EncryptionKey

	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	authTime := time.Now().UTC()
	auth := types.Authenticator{
		Cksum:             zeroChecksum,
		SubKey:            zeroEncryptionKey,
		SeqNumber:         0,
		AuthorizationData: nil,
		AVNO:              5,
		CRealm:            decoderExampleRealm,
		CName:             types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"),
		CTime:             authTime,
		Cusec:             4242,
	}

	rep, err := NewAPRepFromAuthenticator(auth, key, types.EncryptionKey{
		KeyType:  0,
		KeyValue: nil,
	}, 1)
	require.NoError(t, err)
	require.NoError(t, rep.Verify(auth, key))

	rep2, err := NewAPRepFromAuthenticator(auth, key, types.EncryptionKey{
		KeyType:  0,
		KeyValue: nil,
	}, 1)
	require.NoError(t, err)
	mismatched := auth
	mismatched.Cusec = 999
	err = rep2.Verify(mismatched, key)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not match authenticator")
}

// TestASRepVerifyTransitions covers the RFC 4120 3.1.5 reply verification
// branches and the PA-REQ-ENC-PA-REP acknowledgment checks.
func TestASRepVerifyTransitions(t *testing.T) {
	cfg := config.New()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM")
	now := time.Now().UTC()
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}

	newReq := func() ASReq {
		var zeroEncryptedData types.EncryptedData
		var zeroTime time.Time

		return ASReq{KDCReqFields: KDCReqFields{
			PVNO:    0,
			MsgType: 0,
			PAData:  nil,
			Renewal: false,
			ReqBody: KDCReqBody{
				From:              zeroTime,
				RTime:             zeroTime,
				Addresses:         nil,
				EncAuthData:       zeroEncryptedData,
				AdditionalTickets: nil,

				KDCOptions: types.NewKrbFlags(),
				CName:      cname,
				Realm:      decoderExampleRealm,
				SName:      sname,
				Nonce:      4242,
				Till:       now.Add(time.Hour),
				EType:      []int32{etypeID.AES256_CTS_HMAC_SHA1_96},
			},
		}}
	}
	newRep := func() *ASRep { return newDecoderASRep(cname, sname, now) }
	creds := credentials.New("user", decoderExampleRealm)

	checkASRepIdentity(t, cfg, creds, newReq, newRep, key)
	checkASRepRealmAddressAndTime(t, cfg, creds, newReq, newRep, key, now)
	checkASRepEncPARepPresence(t, cfg, creds, newReq, newRep, key)
	checkASRepEncPARepInvalidChecksum(t, cfg, creds, newReq, newRep, key)
	checkASRepEncPARepChecksumInputs(t, cfg, creds, newReq, newRep, key)
	checkASRepWrongPassword(t, cfg, newReq)
}

func newDecoderASRep(cname, sname types.PrincipalName, now time.Time) *ASRep {
	var zeroBitString asn1.BitString
	var zeroEncKDCRepPart EncKDCRepPart
	var zeroEncryptedData types.EncryptedData
	var zeroEncryptionKey types.EncryptionKey
	var zeroTicket Ticket
	var zeroTime time.Time

	rep := &ASRep{KDCRepFields: KDCRepFields{
		PVNO:             0,
		MsgType:          0,
		PAData:           nil,
		Ticket:           zeroTicket,
		EncPart:          zeroEncryptedData,
		DecryptedEncPart: zeroEncKDCRepPart,
		CName:            cname,
		CRealm:           decoderExampleRealm,
	}}
	rep.DecryptedEncPart = EncKDCRepPart{
		Key:           zeroEncryptionKey,
		LastReqs:      nil,
		KeyExpiration: zeroTime,
		Flags:         zeroBitString,
		StartTime:     zeroTime,
		EndTime:       zeroTime,
		RenewTill:     zeroTime,
		CAddr:         nil,
		EncPAData:     nil,

		Nonce:    4242,
		SName:    sname,
		SRealm:   decoderExampleRealm,
		AuthTime: now,
	}
	return rep
}

func checkASRepIdentity(
	t *testing.T,
	cfg *config.Config,
	creds *credentials.Credentials,
	newReq func() ASReq,
	newRep func() *ASRep,
	key types.EncryptionKey,
) {
	t.Helper()

	t.Run("success", func(t *testing.T) {
		ok, err := newRep().verifyWithReplyKey(cfg, creds, newReq(), key, nil)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("cname mismatch", func(t *testing.T) {
		rep := newRep()
		rep.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "other")
		_, err := rep.verifyWithReplyKey(cfg, creds, newReq(), key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CName in response does not match")
	})
	t.Run("cname mismatch allowed when canonicalize", func(t *testing.T) {
		rep := newRep()
		rep.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "other")
		req := newReq()
		types.SetFlag(&req.ReqBody.KDCOptions, flags.Canonicalize)
		ok, err := rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("crealm mismatch", func(t *testing.T) {
		rep := newRep()
		rep.CRealm = "OTHER.COM"
		_, err := rep.verifyWithReplyKey(cfg, creds, newReq(), key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "CRealm in response does not match")
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		rep := newRep()
		rep.DecryptedEncPart.Nonce = 1
		_, err := rep.verifyWithReplyKey(cfg, creds, newReq(), key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "possible replay attack")
	})
	t.Run("sname mismatch", func(t *testing.T) {
		rep := newRep()
		rep.DecryptedEncPart.SName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "other/EXAMPLE.COM")
		_, err := rep.verifyWithReplyKey(cfg, creds, newReq(), key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SName in response does not match")
	})
}

func checkASRepRealmAddressAndTime(
	t *testing.T,
	cfg *config.Config,
	creds *credentials.Credentials,
	newReq func() ASReq,
	newRep func() *ASRep,
	key types.EncryptionKey,
	now time.Time,
) {
	t.Helper()

	t.Run("srealm mismatch", func(t *testing.T) {
		rep := newRep()
		rep.DecryptedEncPart.SRealm = "OTHER.COM"
		_, err := rep.verifyWithReplyKey(cfg, creds, newReq(), key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "SRealm in response does not match")
	})
	t.Run("address mismatch", func(t *testing.T) {
		req := newReq()
		req.ReqBody.Addresses = types.HostAddresses{{AddrType: addrtype.IPv4, Address: []byte{127, 0, 0, 1}}}
		_, err := newRep().verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "addresses listed in the AS_REP does not match")
	})
	t.Run("clock skew", func(t *testing.T) {
		rep := newRep()
		rep.DecryptedEncPart.AuthTime = now.Add(-2 * time.Hour)
		_, err := rep.verifyWithReplyKey(cfg, creds, newReq(), key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "clock skew with KDC too large")
	})
}

func checkASRepEncPARepPresence(
	t *testing.T,
	cfg *config.Config,
	creds *credentials.Credentials,
	newReq func() ASReq,
	newRep func() *ASRep,
	key types.EncryptionKey,
) {
	t.Helper()

	t.Run("enc-pa-rep not acknowledged", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{
			PADataValue: nil,
			PADataType:  patype.PA_REQ_ENC_PA_REP,
		}}
		_, err := newRep().verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KDC did not acknowledge PA-REQ-ENC-PA-REP")
	})
	t.Run("enc-pa-rep omitted", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{
			PADataValue: nil,
			PADataType:  patype.PA_REQ_ENC_PA_REP,
		}}
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		_, err := rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KDC omitted PA-REQ-ENC-PA-REP")
	})
	t.Run("enc-pa-rep corrupt value", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{
			PADataValue: nil,
			PADataType:  patype.PA_REQ_ENC_PA_REP,
		}}
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		rep.DecryptedEncPart.EncPAData = types.PADataSequence{
			{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: []byte{0xFF}},
		}
		_, err := rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not unmarshal PA-REQ-ENC-PA-REP response")
	})
}

func checkASRepEncPARepInvalidChecksum(
	t *testing.T,
	cfg *config.Config,
	creds *credentials.Credentials,
	newReq func() ASReq,
	newRep func() *ASRep,
	key types.EncryptionKey,
) {
	t.Helper()

	t.Run("enc-pa-rep unsupported checksum type", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{
			PADataValue: nil,
			PADataType:  patype.PA_REQ_ENC_PA_REP,
		}}
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		value, err := asn1.Marshal(types.PAReqEncPARep{ChksumType: -1, Chksum: []byte{1}})
		require.NoError(t, err)
		rep.DecryptedEncPart.EncPAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: value}}
		_, err = rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unsupported PA-REQ-ENC-PA-REP checksum type")
	})
	t.Run("enc-pa-rep checksum invalid", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{
			PADataValue: nil,
			PADataType:  patype.PA_REQ_ENC_PA_REP,
		}}
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		value, err := asn1.Marshal(types.PAReqEncPARep{ChksumType: chksumtype.HMAC_SHA1_96_AES256, Chksum: make([]byte, 32)})
		require.NoError(t, err)
		rep.DecryptedEncPart.EncPAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: value}}
		_, err = rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PA-REQ-ENC-PA-REP checksum invalid")
	})
}

func checkASRepEncPARepChecksumInputs(
	t *testing.T,
	cfg *config.Config,
	creds *credentials.Credentials,
	newReq func() ASReq,
	newRep func() *ASRep,
	key types.EncryptionKey,
) {
	t.Helper()

	t.Run("enc-pa-rep checksum valid", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{
			PADataValue: nil,
			PADataType:  patype.PA_REQ_ENC_PA_REP,
		}}
		reqBytes, err := req.Marshal()
		require.NoError(t, err)
		ckEtype, err := crypto.GetChksumEtype(chksumtype.HMAC_SHA1_96_AES256)
		require.NoError(t, err)
		checksum, err := ckEtype.GetChecksumHash(key.KeyValue, reqBytes, keyusage.KEY_USAGE_AS_REQ)
		require.NoError(t, err)
		value, err := asn1.Marshal(types.PAReqEncPARep{ChksumType: chksumtype.HMAC_SHA1_96_AES256, Chksum: checksum})
		require.NoError(t, err)
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		rep.DecryptedEncPart.EncPAData = types.PADataSequence{
			{
				PADataValue: nil,
				PADataType:  patype.PA_PAC_REQUEST,
			}, // non-matching entries are skipped
			{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: value},
		}
		ok, err := rep.verifyWithReplyKey(cfg, creds, req, key, reqBytes)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("enc-pa-rep checksum computed over marshaled request", func(t *testing.T) {
		// requestBytes is nil, so verifyEncPARep marshals the request itself;
		// the checksum must match that deterministic encoding.
		req := newReq()
		req.PAData = types.PADataSequence{{
			PADataValue: nil,
			PADataType:  patype.PA_REQ_ENC_PA_REP,
		}}
		reqBytes, err := req.Marshal()
		require.NoError(t, err)
		ckEtype, err := crypto.GetChksumEtype(chksumtype.HMAC_SHA1_96_AES256)
		require.NoError(t, err)
		checksum, err := ckEtype.GetChecksumHash(key.KeyValue, reqBytes, keyusage.KEY_USAGE_AS_REQ)
		require.NoError(t, err)
		value, err := asn1.Marshal(types.PAReqEncPARep{ChksumType: chksumtype.HMAC_SHA1_96_AES256, Chksum: checksum})
		require.NoError(t, err)
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		rep.DecryptedEncPart.EncPAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: value}}
		_, err = rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.NoError(t, err)
	})
}

func checkASRepWrongPassword(t *testing.T, cfg *config.Config, newReq func() ASReq) {
	t.Helper()

	t.Run("verify decrypts with wrong password", func(t *testing.T) {
		var rep ASRep
		require.NoError(t, rep.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5as_rep)))
		pwCreds := credentials.New("user", decoderExampleRealm)
		pwCreds.WithPassword("wrongpassword")
		_, err := rep.Verify(cfg, pwCreds, newReq())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decrypting EncPart of AS_REP")
	})
}

// TestTGSReqOptionBranches covers tgsReq flag and address option handling.
func TestTGSReqOptionBranches(t *testing.T) {
	cfg := s4uTestConfig()
	cfg.LibDefaults.Canonicalize = true
	cfg.LibDefaults.Proxiable = true
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.RenewLifetime = time.Hour
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service")
	addresses := types.HostAddresses{{AddrType: addrtype.IPv4, Address: []byte{127, 0, 0, 1}}}
	no, yes := false, true
	options := TGSReqOptions{
		PACOptions: nil,
		IncludePAC: nil,

		Forwardable:       &no,
		Forwarded:         &yes,
		Addresses:         &addresses,
		SupportedEncTypes: msflags.SupportedEncTypeClaims | msflags.SupportedEncTypeAES256CTSHMACSHA196SK,
	}

	req, err := tgsReq(cname, sname, decoderExampleRealm, true, cfg, options)
	require.NoError(t, err)
	assert.False(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwardable), "explicit false overrides config")
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwarded))
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Canonicalize))
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Proxiable))
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renew))
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renewable))
	assert.False(t, req.ReqBody.RTime.IsZero())
	assert.Equal(t, []types.HostAddress(addresses), req.ReqBody.Addresses)
	require.NoError(t, req.addMSKILEPAData(cfg, options))
	pa := findTestPAData(t, req.PAData, patype.PA_PAC_OPTIONS)
	pacOptions, err := pa.GetPAPACOptions()
	require.NoError(t, err)
	assert.True(t, types.IsFlagSet(&pacOptions.Options, flags.PACOptionClaims))
}

// TestTGSReqSetPADataWithSubkey covers the authenticator subkey variant used
// for FAST armor.
func TestTGSReqSetPADataWithSubkey(t *testing.T) {
	cfg := s4uTestConfig()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM")
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}

	req, err := tgsReq(cname, sname, decoderExampleRealm, false, cfg, TGSReqOptions{
		PACOptions:        nil,
		IncludePAC:        nil,
		SupportedEncTypes: 0,
		Forwardable:       nil,
		Forwarded:         nil,
		Addresses:         nil,
	})
	require.NoError(t, err)
	subkey, apReqBytes, err := req.SetPADataWithSubkey(s4uTestTicket(), key)
	require.NoError(t, err)
	assert.Equal(t, key.KeyType, subkey.KeyType)
	assert.NotEmpty(t, subkey.KeyValue)
	assert.NotEmpty(t, apReqBytes)
	require.NotEmpty(t, req.PAData)
	var apReq APReq
	require.NoError(t, apReq.Unmarshal(apReqBytes), "PA-TGS-REQ must carry a parseable AP-REQ")
}

// TestNewASReqAllOptions covers the remaining per-request override branches.
func TestNewASReqAllOptions(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cfg.LibDefaults.TicketLifetime = time.Hour
	cfg.LibDefaults.RenewLifetime = 2 * time.Hour
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM")
	spn := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/host.example.com")
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	lifetime := 30 * time.Minute
	enterprise := true
	addresses := []types.HostAddress{{AddrType: addrtype.IPv4, Address: []byte{10, 0, 0, 1}}}

	req, err := NewASReqWithOptions(decoderExampleRealm, cfg, cname, sname, ASReqOptions{
		RenewLifetime: nil,
		Forwardable:   nil,
		Proxiable:     nil,
		Canonicalize:  nil,
		IncludePAC:    nil,

		Lifetime:         &lifetime,
		Enterprise:       &enterprise,
		ServicePrincipal: &spn,
		StartTime:        &start,
		Addresses:        addresses,
	})
	require.NoError(t, err)
	assert.Equal(t, nametype.KRB_NT_ENTERPRISE, req.ReqBody.CName.NameType)
	assert.Equal(t, spn.PrincipalNameString(), req.ReqBody.SName.PrincipalNameString())
	assert.Equal(t, start, req.ReqBody.From)
	assert.Equal(t, start.Add(lifetime), req.ReqBody.Till)
	assert.Equal(t, start.Add(2*time.Hour), req.ReqBody.RTime, "renew time follows the start time override")
	assert.Equal(t, addresses, req.ReqBody.Addresses)
	marshaled, err := req.Marshal()
	require.NoError(t, err)
	require.NoError(t, new(ASReq).Unmarshal(marshaled))
}

// TestAPReqVerifyTransitions covers the acceptor-side AP_REQ verification
// state machine: ticket decryption, validity, client addresses, authenticator
// integrity, name matching, and clock skew.
func TestAPReqVerifyTransitions(t *testing.T) {
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service/host.example.com")
	svcKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	now := time.Now().UTC()

	kt := keytab.New()
	require.NoError(t, kt.AddKey(keytab.Principal{
		Realm:      decoderExampleRealm,
		Components: sname.NameString,
		NameType:   sname.NameType,
	}, 1, svcKey, now))

	newTicket := func(t *testing.T) (Ticket, types.EncryptionKey) {
		t.Helper()
		tkt, sessionKey, err := NewTicketWithKey(
			cname,
			decoderExampleRealm,
			sname,
			decoderExampleRealm,
			types.NewKrbFlags(),
			svcKey,
			1,
			now,
			now.Add(-time.Hour),
			now.Add(time.Hour),
			now.Add(2*time.Hour),
		)
		require.NoError(t, err)
		return tkt, sessionKey
	}
	newAuthenticator := func() types.Authenticator {
		var zeroChecksum types.Checksum
		var zeroEncryptionKey types.EncryptionKey

		return types.Authenticator{
			Cksum:             zeroChecksum,
			SubKey:            zeroEncryptionKey,
			SeqNumber:         0,
			AuthorizationData: nil,
			AVNO:              5,
			CRealm:            decoderExampleRealm,
			CName:             cname,
			CTime:             now,
			Cusec:             123,
		}
	}

	checkAPReqKeySelection(t, kt, newTicket, newAuthenticator, sname)
	checkAPReqExpiredTicket(t, kt, newAuthenticator, cname, sname, svcKey, now)
	checkAPReqTicketAddress(t, kt, newTicket, newAuthenticator, cname, svcKey, now)
	checkAPReqAuthenticator(t, kt, newTicket, newAuthenticator, now)
}

func checkAPReqKeySelection(
	t *testing.T,
	kt *keytab.Keytab,
	newTicket func(*testing.T) (Ticket, types.EncryptionKey),
	newAuthenticator func() types.Authenticator,
	sname types.PrincipalName,
) {
	t.Helper()

	t.Run("success", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{
			AddrType: 0,
			Address:  nil,
		}, nil)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("success with sname override", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		override := sname
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{
			AddrType: 0,
			Address:  nil,
		}, &override)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("key not in keytab", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		_, err = apReq.Verify(keytab.New(), 5*time.Minute, types.HostAddress{
			AddrType: 0,
			Address:  nil,
		}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decrypting encpart of service ticket")
	})
}

func checkAPReqExpiredTicket(
	t *testing.T,
	kt *keytab.Keytab,
	newAuthenticator func() types.Authenticator,
	cname, sname types.PrincipalName,
	svcKey types.EncryptionKey,
	now time.Time,
) {
	t.Helper()

	t.Run("expired ticket", func(t *testing.T) {
		tkt, sessionKey, err := NewTicketWithKey(
			cname,
			decoderExampleRealm,
			sname,
			decoderExampleRealm,
			types.NewKrbFlags(),
			svcKey,
			1,
			now.Add(-4*time.Hour),
			now.Add(-4*time.Hour),
			now.Add(-3*time.Hour),
			now.Add(-2*time.Hour),
		)
		require.NoError(t, err)
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{
			AddrType: 0,
			Address:  nil,
		}, nil)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "has expired")
	})
}

func checkAPReqTicketAddress(
	t *testing.T,
	kt *keytab.Keytab,
	newTicket func(*testing.T) (Ticket, types.EncryptionKey),
	newAuthenticator func() types.Authenticator,
	cname types.PrincipalName,
	svcKey types.EncryptionKey,
	now time.Time,
) {
	t.Helper()

	t.Run("client address not in ticket", func(t *testing.T) {
		var zeroTime time.Time
		var zeroTransitedEncoding TransitedEncoding

		tkt, sessionKey := newTicket(t)
		etp := EncTicketPart{
			Transited:         zeroTransitedEncoding,
			RenewTill:         zeroTime,
			AuthorizationData: nil,

			Flags:     types.NewKrbFlags(),
			Key:       sessionKey,
			CRealm:    decoderExampleRealm,
			CName:     cname,
			AuthTime:  now,
			StartTime: now.Add(-time.Hour),
			EndTime:   now.Add(time.Hour),
			CAddr:     types.HostAddresses{{AddrType: addrtype.IPv4, Address: []byte{10, 0, 0, 1}}},
		}
		raw, err := asn1.Marshal(etp)
		require.NoError(t, err)
		raw = asn1tools.AddASNAppTag(raw, asnAppTag.EncTicketPart)
		ed, err := crypto.GetEncryptedData(raw, svcKey, keyusage.KDC_REP_TICKET, 1)
		require.NoError(t, err)
		tkt.EncPart = ed
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		ok, err := apReq.Verify(
			kt,
			5*time.Minute,
			types.HostAddress{AddrType: addrtype.IPv4, Address: []byte{127, 0, 0, 1}},
			nil,
		)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "client address not within the list")
	})
}

func checkAPReqAuthenticator(
	t *testing.T,
	kt *keytab.Keytab,
	newTicket func(*testing.T) (Ticket, types.EncryptionKey),
	newAuthenticator func() types.Authenticator,
	now time.Time,
) {
	t.Helper()

	t.Run("authenticator integrity failure", func(t *testing.T) {
		tkt, _ := newTicket(t)
		otherSession := types.EncryptionKey{
			KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KeyValue: append([]byte{0xFF}, make([]byte, 31)...),
		}
		apReq, err := NewAPReq(tkt, otherSession, newAuthenticator())
		require.NoError(t, err)
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{
			AddrType: 0,
			Address:  nil,
		}, nil)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "could not decrypt authenticator")
	})
	t.Run("cname mismatch", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		auth := newAuthenticator()
		auth.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "other")
		apReq, err := NewAPReq(tkt, sessionKey, auth)
		require.NoError(t, err)
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{
			AddrType: 0,
			Address:  nil,
		}, nil)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "CName in Authenticator does not match")
	})
	t.Run("clock skew", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		auth := newAuthenticator()
		auth.CTime = now.Add(-2 * time.Hour)
		apReq, err := NewAPReq(tkt, sessionKey, auth)
		require.NoError(t, err)
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{
			AddrType: 0,
			Address:  nil,
		}, nil)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "clock skew with client too large")
	})
}

// TestTGSReqRejectsOutOfRangePACOption covers the PA-PAC-OPTIONS marshal
// rejection propagated through addMSKILEPAData.
func TestTGSReqRejectsOutOfRangePACOption(t *testing.T) {
	cfg := s4uTestConfig()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM")
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}

	_, err := NewTGSReqWithOptions(cname, decoderExampleRealm, cfg, s4uTestTicket(), key, sname, false, TGSReqOptions{
		IncludePAC:        nil,
		SupportedEncTypes: 0,
		Forwardable:       nil,
		Forwarded:         nil,
		Addresses:         nil,
		PACOptions:        []int{999},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PA-PAC-OPTIONS")
}

// FuzzMessageUnmarshal fuzzes every wire-format decoder in the package with
// the valid message vectors as seeds. Malformed inputs must never panic.
func FuzzMessageUnmarshal(f *testing.F) {
	vectors := messageUnmarshalVectors(f)
	names := slices.Sorted(maps.Keys(vectors))
	for i, name := range names {
		b, err := hex.DecodeString(vectors[name].hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(i, b)
	}
	f.Fuzz(func(_ *testing.T, index int, b []byte) {
		i := index % len(names)
		if i < 0 {
			i += len(names)
		}
		_ = vectors[names[i]].unmarshal(b)
	})
}
