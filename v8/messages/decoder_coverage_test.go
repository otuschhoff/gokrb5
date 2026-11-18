package messages

import (
	"encoding/hex"
	"fmt"
	"log"
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

func messageUnmarshalVectors(tb testing.TB) map[string]struct {
	hex       string
	unmarshal func([]byte) error
} {
	tb.Helper()
	return map[string]struct {
		hex       string
		unmarshal func([]byte) error
	}{
		"AS_REQ":                                {testdata.MarshaledKRB5as_req, func(b []byte) error { return new(ASReq).Unmarshal(b) }},
		"AS_REQ optionals null except 2nd tkt":  {testdata.MarshaledKRB5as_reqOptionalsNULLexceptsecond_ticket, func(b []byte) error { return new(ASReq).Unmarshal(b) }},
		"AS_REQ optionals null except server":   {testdata.MarshaledKRB5as_reqOptionalsNULLexceptserver, func(b []byte) error { return new(ASReq).Unmarshal(b) }},
		"TGS_REQ":                               {testdata.MarshaledKRB5tgs_req, func(b []byte) error { return new(TGSReq).Unmarshal(b) }},
		"TGS_REQ optionals null except 2nd tkt": {testdata.MarshaledKRB5tgs_reqOptionalsNULLexceptsecond_ticket, func(b []byte) error { return new(TGSReq).Unmarshal(b) }},
		"TGS_REQ optionals null except server":  {testdata.MarshaledKRB5tgs_reqOptionalsNULLexceptserver, func(b []byte) error { return new(TGSReq).Unmarshal(b) }},
		"KDC_REQ_BODY":                          {testdata.MarshaledKRB5kdc_req_body, func(b []byte) error { return new(KDCReqBody).Unmarshal(b) }},
		"AS_REP":                                {testdata.MarshaledKRB5as_rep, func(b []byte) error { return new(ASRep).Unmarshal(b) }},
		"AS_REP optionals null":                 {testdata.MarshaledKRB5as_repOptionalsNULL, func(b []byte) error { return new(ASRep).Unmarshal(b) }},
		"TGS_REP":                               {testdata.MarshaledKRB5tgs_rep, func(b []byte) error { return new(TGSRep).Unmarshal(b) }},
		"TGS_REP optionals null":                {testdata.MarshaledKRB5tgs_repOptionalsNULL, func(b []byte) error { return new(TGSRep).Unmarshal(b) }},
		"AP_REQ":                                {testdata.MarshaledKRB5ap_req, func(b []byte) error { return new(APReq).Unmarshal(b) }},
		"AP_REP":                                {testdata.MarshaledKRB5ap_rep, func(b []byte) error { return new(APRep).Unmarshal(b) }},
		"AP_REP enc part":                       {testdata.MarshaledKRB5ap_rep_enc_part, func(b []byte) error { return new(EncAPRepPart).Unmarshal(b) }},
		"AP_REP enc part optionals null":        {testdata.MarshaledKRB5ap_rep_enc_partOptionalsNULL, func(b []byte) error { return new(EncAPRepPart).Unmarshal(b) }},
		"KRB_CRED":                              {testdata.MarshaledKRB5cred, func(b []byte) error { return new(KRBCred).Unmarshal(b) }},
		"KRB_CRED enc part":                     {testdata.MarshaledKRB5enc_cred_part, func(b []byte) error { return new(EncKrbCredPart).Unmarshal(b) }},
		"KRB_CRED enc part optionals null":      {testdata.MarshaledKRB5enc_cred_partOptionalsNULL, func(b []byte) error { return new(EncKrbCredPart).Unmarshal(b) }},
		"KRB_PRIV":                              {testdata.MarshaledKRB5priv, func(b []byte) error { return new(KRBPriv).Unmarshal(b) }},
		"KRB_PRIV enc part":                     {testdata.MarshaledKRB5enc_priv_part, func(b []byte) error { return new(EncKrbPrivPart).Unmarshal(b) }},
		"KRB_PRIV enc part optionals null":      {testdata.MarshaledKRB5enc_priv_partOptionalsNULL, func(b []byte) error { return new(EncKrbPrivPart).Unmarshal(b) }},
		"KRB_SAFE":                              {testdata.MarshaledKRB5safe, func(b []byte) error { return new(KRBSafe).Unmarshal(b) }},
		"KRB_SAFE optionals null":               {testdata.MarshaledKRB5safeOptionalsNULL, func(b []byte) error { return new(KRBSafe).Unmarshal(b) }},
		"KRB_ERROR":                             {testdata.MarshaledKRB5error, func(b []byte) error { return new(KRBError).Unmarshal(b) }},
		"KRB_ERROR optionals null":              {testdata.MarshaledKRB5errorOptionalsNULL, func(b []byte) error { return new(KRBError).Unmarshal(b) }},
		"Ticket":                                {testdata.MarshaledKRB5ticket, func(b []byte) error { return new(Ticket).Unmarshal(b) }},
		"EncTicketPart":                         {testdata.MarshaledKRB5enc_tkt_part, func(b []byte) error { return new(EncTicketPart).Unmarshal(b) }},
		"EncTicketPart optionals null":          {testdata.MarshaledKRB5enc_tkt_partOptionalsNULL, func(b []byte) error { return new(EncTicketPart).Unmarshal(b) }},
		"EncKDCRepPart":                         {testdata.MarshaledKRB5enc_kdc_rep_part, func(b []byte) error { return new(EncKDCRepPart).Unmarshal(b) }},
		"EncKDCRepPart optionals null":          {testdata.MarshaledKRB5enc_kdc_rep_partOptionalsNULL, func(b []byte) error { return new(EncKDCRepPart).Unmarshal(b) }},
	}
}

// TestMessageUnmarshalTruncationSweep unmarshals every strict prefix of every
// valid message vector: DER length framing must reject every truncation.
func TestMessageUnmarshalTruncationSweep(t *testing.T) {
	for name, vector := range messageUnmarshalVectors(t) {
		t.Run(name, func(t *testing.T) {
			b := mustDecodeHex(t, vector.hex)
			require.NoError(t, vector.unmarshal(b), "valid vector must parse")
			for length := 0; length < len(b); length++ {
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
	for _, name := range []string{"KDC_REQ_BODY", "AS_REQ", "TGS_REQ", "AS_REP", "TGS_REP", "AP_REQ", "KRB_CRED", "Ticket", "KRB_ERROR", "KRB_SAFE"} {
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
	m.AdditionalTickets = asn1.RawValue{Class: 2, IsCompound: true, Tag: 11, Bytes: []byte{0x61, 0x03, 0x1b, 0x01, 0x01}}
	crafted, err := asn1.Marshal(m)
	require.NoError(t, err)
	err = new(KDCReqBody).Unmarshal(crafted)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "error unmarshaling additional tickets")
}

// TestUnmarshalTicketsSequenceErrors covers the ticket sequence rejections.
func TestUnmarshalTicketsSequenceErrors(t *testing.T) {
	// An application-tagged value whose content is not a valid ticket.
	if _, err := unmarshalTicketsSequence(asn1.RawValue{Bytes: []byte{0x30, 0x05, 0x61, 0x03, 0x1b, 0x01, 0x01}}); err == nil {
		t.Fatal("garbage ticket sequence was accepted")
	}
	valid := mustDecodeHex(t, testdata.MarshaledKRB5ticket)
	raw, err := MarshalTicketSequence([]Ticket{mustUnmarshalTicket(t, valid)})
	require.NoError(t, err)
	tickets, err := unmarshalTicketsSequence(raw)
	require.NoError(t, err)
	assert.Len(t, tickets, 1)
	// Truncate the sequence content so the embedded ticket fails to parse.
	truncated := asn1.RawValue{Bytes: raw.Bytes[:len(raw.Bytes)-2]}
	if _, err := unmarshalTicketsSequence(truncated); err == nil {
		t.Fatal("truncated ticket sequence was accepted")
	}
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
	_, _, err := NewTicketWithKey(cname, "EXAMPLE.ORG", sname, "EXAMPLE.ORG", types.NewKrbFlags(), shortKey, 1, now, now, now, now)
	require.Error(t, err, "16-byte key must be rejected for AES256")
}

// TestTicketDecryptFailures covers decryption and plaintext rejection.
func TestTicketDecryptFailures(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	otherKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}

	ed, err := crypto.GetEncryptedData([]byte("plaintext that is not an EncTicketPart"), key, keyusage.KDC_REP_TICKET, 1)
	require.NoError(t, err)
	ticket := Ticket{TktVNO: 5, Realm: "EXAMPLE.ORG", SName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service"), EncPart: ed}

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

	t.Run("no PAC present", func(t *testing.T) {
		ticket := Ticket{SName: sname, Realm: "EXAMPLE.COM"}
		ok, _, err := ticket.GetPACTypeWithOptions(keytab.New(), nil, logger, pacVerifyOptions())
		require.NoError(t, err)
		assert.False(t, ok)
	})
	t.Run("authorization data traversal failure", func(t *testing.T) {
		ticket := Ticket{SName: sname, Realm: "EXAMPLE.COM"}
		ticket.DecryptedEncPart.AuthorizationData = types.AuthorizationData{
			{ADType: adtype.ADIfRelevant, ADData: []byte{0xFF, 0xFF}},
		}
		_, _, err := ticket.GetPACTypeWithOptions(keytab.New(), nil, logger, pacVerifyOptions())
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PAC authorization data could not be traversed")
	})
	t.Run("malformed PAC", func(t *testing.T) {
		ticket := Ticket{SName: sname, Realm: "EXAMPLE.COM"}
		ticket.DecryptedEncPart.AuthorizationData = types.AuthorizationData{
			{ADType: adtype.ADWin2KPAC, ADData: []byte{0xFF, 0xFF, 0xFF}},
		}
		ok, _, err := ticket.GetPACTypeWithOptions(keytab.New(), nil, logger, pacVerifyOptions())
		require.Error(t, err)
		assert.True(t, ok)
		assert.Contains(t, err.Error(), "error unmarshaling PAC")
	})
	t.Run("valid PAC without key", func(t *testing.T) {
		ticket := ticketWithPAC(t, sname)
		ok, _, err := ticket.GetPACTypeWithOptions(keytab.New(), nil, logger, pacVerifyOptions())
		require.Error(t, err)
		assert.True(t, ok)
		var krbErr KRBError
		require.ErrorAs(t, err, &krbErr)
		assert.Equal(t, errorcode.KRB_AP_ERR_NOKEY, krbErr.ErrorCode)
	})
	t.Run("valid PAC with wrong key", func(t *testing.T) {
		ticket := ticketWithPAC(t, sname)
		kt := keytab.New()
		require.NoError(t, kt.AddKey(keytab.Principal{
			Realm:      "EXAMPLE.COM",
			Components: []string{"krbtgt", "EXAMPLE.COM"},
			NameType:   nametype.KRB_NT_SRV_INST,
		}, 1, types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}, time.Now()))
		_, _, err := ticket.GetPACTypeWithOptions(kt, nil, logger, pacVerifyOptions())
		require.Error(t, err, "PAC verification with the wrong key must fail")
	})
}

func ticketWithPAC(t *testing.T, sname types.PrincipalName) Ticket {
	t.Helper()
	ticket := Ticket{
		SName:   sname,
		Realm:   "EXAMPLE.COM",
		EncPart: types.EncryptedData{EType: etypeID.AES256_CTS_HMAC_SHA1_96, KVNO: 1},
	}
	ticket.DecryptedEncPart.AuthorizationData = types.AuthorizationData{
		{ADType: adtype.ADWin2KPAC, ADData: mustDecodeHex(t, testdata.MarshaledPAC_AD_WIN2K_PAC)},
	}
	return ticket
}

// pacVerifyOptions returns zero-value PAC verify options without exporting pac.
func pacVerifyOptions() pac.VerifyOptions {
	return pac.VerifyOptions{}
}

// TestKRBCredCrypto covers construction, encryption, and decryption failures.
func TestKRBCredCrypto(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	badKey := types.EncryptionKey{KeyType: -1, KeyValue: make([]byte, 32)}
	info := KrbCredInfo{Key: key, SRealm: "EXAMPLE.COM"}
	tickets := []Ticket{mustUnmarshalTicket(t, mustDecodeHex(t, testdata.MarshaledKRB5ticket))}

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
		other := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: append([]byte{1}, make([]byte, 31)...)}
		require.Error(t, cred.DecryptEncPart(other))
		require.NoError(t, cred.DecryptEncPart(key))
		require.Len(t, cred.DecryptedEncPart.TicketInfo, 1)
	})
	t.Run("encrypt rejects unknown enctype", func(t *testing.T) {
		cred := KRBCred{DecryptedEncPart: EncKrbCredPart{TicketInfo: []KrbCredInfo{{}}}}
		require.Error(t, cred.EncryptEncPart(badKey))
	})
	t.Run("decrypt rejects wrong key", func(t *testing.T) {
		cred := KRBCred{DecryptedEncPart: EncKrbCredPart{TicketInfo: []KrbCredInfo{{}}}}
		require.NoError(t, cred.EncryptEncPart(key))
		other := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}
		require.Error(t, cred.DecryptEncPart(other))
	})
}

// TestKRBPrivCrypto covers KRBPriv encryption and decryption.
func TestKRBPrivCrypto(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	badKey := types.EncryptionKey{KeyType: -1}
	priv := NewKRBPriv(EncKrbPrivPart{UserData: []byte("confidential")})

	require.Error(t, priv.EncryptEncPart(badKey), "unknown enctype must be rejected")
	require.NoError(t, priv.EncryptEncPart(key))
	other := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}
	require.Error(t, priv.DecryptEncPart(other))
	require.NoError(t, priv.DecryptEncPart(key))
	assert.Equal(t, []byte("confidential"), priv.DecryptedEncPart.UserData)
}

// TestAPRepCryptoErrors covers AP_REP encryption and decryption failures.
func TestAPRepCryptoErrors(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	badKey := types.EncryptionKey{KeyType: -1}
	part := EncAPRepPart{CTime: time.Now().UTC(), Cusec: 123}

	_, err := NewAPRep(part, badKey)
	require.Error(t, err)

	auth := types.Authenticator{AVNO: 5, CRealm: "EXAMPLE.COM", CName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"), CTime: time.Now().UTC()}
	_, err = NewAPRepFromAuthenticator(auth, badKey, key, 1)
	require.Error(t, err)

	rep, err := NewAPRep(part, key)
	require.NoError(t, err)
	other := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 16)}
	require.Error(t, rep.DecryptEncPart(other))
	require.NoError(t, rep.DecryptEncPart(key))
	assert.Equal(t, 123, rep.DecryptedEncPart.Cusec)

	rep2 := APRep{DecryptedEncPart: part}
	require.Error(t, rep2.EncryptEncPart(badKey))
}

// TestAPReqCryptoErrors covers AP_REQ authenticator encryption failures.
func TestAPReqCryptoErrors(t *testing.T) {
	badKey := types.EncryptionKey{KeyType: -1}
	auth := types.Authenticator{AVNO: 5, CRealm: "EXAMPLE.COM", CName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"), CTime: time.Now().UTC()}
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
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdeffedcba9876543210")}

	t.Run("X509 PA data rejects unknown enctype", func(t *testing.T) {
		_, err := NewPAS4UX509UserPAData(types.S4UUserID{CName: user, CRealm: "EXAMPLE.COM"}, types.EncryptionKey{KeyType: -1})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "get S4U session key etype")
	})
	t.Run("find requires the PA type", func(t *testing.T) {
		_, err := findS4UX509User(types.PADataSequence{})
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PA-S4U-X509-USER is missing")
	})
	t.Run("find rejects corrupt value", func(t *testing.T) {
		_, err := findS4UX509User(types.PADataSequence{{PADataType: patype.PA_S4U_X509_USER, PADataValue: []byte{0xFF}}})
		require.Error(t, err)
	})
	t.Run("reply verification requires request PA", func(t *testing.T) {
		_, err := new(TGSRep).VerifyS4UX509UserReply(TGSReq{}, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "S4U request")
	})
	t.Run("reply verification requires reply PA", func(t *testing.T) {
		req, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", cfg, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{})
		require.NoError(t, err)
		_, err = new(TGSRep).VerifyS4UX509UserReply(req, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "S4U reply")
	})
	t.Run("nonce mismatch", func(t *testing.T) {
		req, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", cfg, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{})
		require.NoError(t, err)
		reply := s4uReply(t, mustNonceUint32(t, req.ReqBody.Nonce)+1, key, user, false)
		_, err = reply.VerifyS4UX509UserReply(req, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "nonce")
	})
	t.Run("checksum type mismatch", func(t *testing.T) {
		req, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", cfg, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{})
		require.NoError(t, err)
		reply := s4uReply(t, mustNonceUint32(t, req.ReqBody.Nonce), key, user, true)
		_, err = reply.VerifyS4UX509UserReply(req, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum type")
	})
	t.Run("checksum invalid", func(t *testing.T) {
		req, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", cfg, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{})
		require.NoError(t, err)
		other := types.EncryptionKey{KeyType: key.KeyType, KeyValue: append([]byte{0xFF}, key.KeyValue[1:]...)}
		reply := s4uReply(t, mustNonceUint32(t, req.ReqBody.Nonce), other, user, false)
		_, err = reply.VerifyS4UX509UserReply(req, key)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "checksum invalid")
	})
	t.Run("valid reply accepted", func(t *testing.T) {
		req, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", cfg, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{})
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
func s4uReply(t *testing.T, nonce uint32, key types.EncryptionKey, user types.PrincipalName, wrongCksumType bool) TGSRep {
	t.Helper()
	options := types.NewKrbFlags()
	types.SetFlag(&options, flags.S4UOptionUseReplyKeyUsage)
	userID := types.S4UUserID{Nonce: nonce, CName: user, CRealm: "EXAMPLE.COM", Options: options}
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
	return TGSRep{KDCRepFields: KDCRepFields{PAData: types.PADataSequence{pa}}}
}

// TestKRBErrorTypedData covers METHOD-DATA, KERB-ERROR-DATA, and NTSTATUS
// extraction branches.
func TestKRBErrorTypedData(t *testing.T) {
	t.Run("method data requires preauth codes", func(t *testing.T) {
		e := NewKRBError(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt"), "EXAMPLE.COM", errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, "x")
		_, err := e.MethodData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "does not carry METHOD-DATA")
	})
	t.Run("method data rejects corrupt edata", func(t *testing.T) {
		e := NewKRBError(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt"), "EXAMPLE.COM", errorcode.KDC_ERR_PREAUTH_REQUIRED, "x")
		e.EData = []byte{0xFF, 0xFF}
		_, err := e.MethodData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode KRB-ERROR METHOD-DATA")
	})
	t.Run("method data rejects trailing bytes", func(t *testing.T) {
		e := NewKRBError(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt"), "EXAMPLE.COM", errorcode.KDC_ERR_PREAUTH_REQUIRED, "x")
		e.EData = append(mustDecodeHex(t, testdata.MarshaledKRB5padata_sequence), 0x05, 0x00)
		_, err := e.MethodData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "trailing bytes")
	})
	t.Run("method data decodes", func(t *testing.T) {
		e := NewKRBError(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "krbtgt"), "EXAMPLE.COM", errorcode.KDC_ERR_PREAUTH_REQUIRED, "x")
		e.EData = mustDecodeHex(t, testdata.MarshaledKRB5padata_sequence)
		pa, err := e.MethodData()
		require.NoError(t, err)
		assert.NotEmpty(t, pa)
	})
	t.Run("kerb error data rejects corrupt edata", func(t *testing.T) {
		e := KRBError{EData: []byte{0xFF}}
		_, err := e.KerbErrorData()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "decode KRB-ERROR-DATA")
	})
	t.Run("ntstatus absent without valid edata", func(t *testing.T) {
		_, ok := KRBError{EData: []byte{0xFF}}.NTStatus()
		assert.False(t, ok)
	})
	t.Run("ntstatus from extended error", func(t *testing.T) {
		errorData, err := types.NewKerbExtErrorData(types.KerbExtError{Status: ntstatus.STATUS_ACCOUNT_DISABLED})
		require.NoError(t, err)
		status, ok := KRBError{EData: errorDataBytes(t, errorData)}.NTStatus()
		require.True(t, ok)
		assert.Equal(t, ntstatus.STATUS_ACCOUNT_DISABLED, status)
	})
	t.Run("ntstatus absent for other data types", func(t *testing.T) {
		errorData, err := types.NewKerbExtErrorData(types.KerbExtError{Status: ntstatus.STATUS_ACCOUNT_DISABLED})
		require.NoError(t, err)
		errorData.DataType = int32(msflags.KERB_AP_ERR_TYPE_SKEW_RECOVERY)
		_, ok := KRBError{EData: errorDataBytes(t, errorData)}.NTStatus()
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
		var m ASReq
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5as_req)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(ASReq).Unmarshal(b))
	})
	t.Run("TGS_REQ", func(t *testing.T) {
		var m TGSReq
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5tgs_req)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(TGSReq).Unmarshal(b))
	})
	t.Run("KDC_REQ_BODY", func(t *testing.T) {
		var m KDCReqBody
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5kdc_req_body)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(KDCReqBody).Unmarshal(b))
	})
	t.Run("AS_REP", func(t *testing.T) {
		var m ASRep
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5as_rep)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(ASRep).Unmarshal(b))
	})
	t.Run("TGS_REP", func(t *testing.T) {
		var m TGSRep
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5tgs_rep)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(TGSRep).Unmarshal(b))
	})
	t.Run("EncKDCRepPart", func(t *testing.T) {
		var m EncKDCRepPart
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5enc_kdc_rep_part)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(EncKDCRepPart).Unmarshal(b))
	})
	t.Run("AP_REQ", func(t *testing.T) {
		var m APReq
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5ap_req)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(APReq).Unmarshal(b))
	})
	t.Run("AP_REP", func(t *testing.T) {
		var m APRep
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5ap_rep)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(APRep).Unmarshal(b))
	})
	t.Run("AP_REP enc part", func(t *testing.T) {
		var m EncAPRepPart
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5ap_rep_enc_part)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(EncAPRepPart).Unmarshal(b))
	})
	t.Run("KRB_CRED", func(t *testing.T) {
		var m KRBCred
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5cred)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(KRBCred).Unmarshal(b))
	})
	t.Run("KRB_CRED enc part", func(t *testing.T) {
		var m EncKrbCredPart
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5enc_cred_part)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(EncKrbCredPart).Unmarshal(b))
	})
	t.Run("KRB_PRIV", func(t *testing.T) {
		var m KRBPriv
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5priv)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(KRBPriv).Unmarshal(b))
	})
	t.Run("KRB_ERROR", func(t *testing.T) {
		var m KRBError
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5error)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(KRBError).Unmarshal(b))
	})
	t.Run("Ticket", func(t *testing.T) {
		var m Ticket
		require.NoError(t, m.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5ticket)))
		b, err := m.Marshal()
		require.NoError(t, err)
		require.NoError(t, new(Ticket).Unmarshal(b))
	})
}

// TestTGSReqConstructorsRejectBadSessionKey covers the PA-TGS-REQ construction
// failure branches of every TGS request constructor.
func TestTGSReqConstructorsRejectBadSessionKey(t *testing.T) {
	cfg := s4uTestConfig()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service")
	badKey := types.EncryptionKey{KeyType: -1}
	tgt := s4uTestTicket()

	if _, err := NewTGSReqWithOptions(cname, "EXAMPLE.COM", cfg, tgt, badKey, sname, false, TGSReqOptions{}); err == nil {
		t.Fatal("NewTGSReqWithOptions accepted an unknown enctype session key")
	}
	if _, err := NewS4U2SelfTGSReq(cname, "EXAMPLE.COM", cfg, tgt, badKey, sname, cname, "EXAMPLE.COM", S4U2SelfReqOptions{}); err == nil {
		t.Fatal("NewS4U2SelfTGSReq accepted an unknown enctype session key")
	}
	if _, err := NewS4U2ProxyTGSReq(cname, "EXAMPLE.COM", cfg, tgt, badKey, sname, tgt, TGSReqOptions{}); err == nil {
		t.Fatal("NewS4U2ProxyTGSReq accepted an unknown enctype session key")
	}
	if _, err := NewUser2UserTGSReqWithOptions(cname, "EXAMPLE.COM", cfg, tgt, badKey, sname, false, tgt, TGSReqOptions{}); err == nil {
		t.Fatal("NewUser2UserTGSReqWithOptions accepted an unknown enctype session key")
	}
}

// TestTGSRepDecryptEncPartWithKeyUsage covers both reply key usages.
func TestTGSRepDecryptEncPartWithKeyUsage(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	part := EncKDCRepPart{
		Key:      key,
		LastReqs: []LastReq{{LRType: 0, LRValue: time.Now().UTC()}},
		Nonce:    42,
		Flags:    types.NewKrbFlags(),
		AuthTime: time.Now().UTC(),
		SName:    types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service"),
		SRealm:   "EXAMPLE.COM",
	}
	for name, usage := range map[string]uint32{
		"session key":          keyusage.TGS_REP_ENCPART_SESSION_KEY,
		"authenticator subkey": keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY,
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := part.Marshal()
			require.NoError(t, err)
			ed, err := crypto.GetEncryptedData(raw, key, usage, 1)
			require.NoError(t, err)
			rep := TGSRep{}
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
		tkt := Ticket{SName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service"), Realm: "EXAMPLE.COM"}
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
	plain := NewKRBError(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM"), "EXAMPLE.COM", errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, "")
	assert.NotContains(t, plain.Error(), " - ")

	withText := NewKRBError(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM"), "EXAMPLE.COM", errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, "detail text")
	assert.Contains(t, withText.Error(), "detail text")

	errorData, err := types.NewKerbExtErrorData(types.KerbExtError{Status: ntstatus.STATUS_ACCOUNT_DISABLED})
	require.NoError(t, err)
	withStatus := NewKRBError(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM"), "EXAMPLE.COM", errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, "detail text")
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
		part.Subkey = types.EncryptionKey{}
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
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 32)}
	authTime := time.Now().UTC()
	auth := types.Authenticator{AVNO: 5, CRealm: "EXAMPLE.COM", CName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"), CTime: authTime, Cusec: 4242}

	rep, err := NewAPRepFromAuthenticator(auth, key, types.EncryptionKey{}, 1)
	require.NoError(t, err)
	require.NoError(t, rep.Verify(auth, key))

	rep2, err := NewAPRepFromAuthenticator(auth, key, types.EncryptionKey{}, 1)
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
		return ASReq{KDCReqFields: KDCReqFields{ReqBody: KDCReqBody{
			KDCOptions: types.NewKrbFlags(),
			CName:      cname,
			Realm:      "EXAMPLE.COM",
			SName:      sname,
			Nonce:      4242,
			Till:       now.Add(time.Hour),
			EType:      []int32{etypeID.AES256_CTS_HMAC_SHA1_96},
		}}}
	}
	newRep := func() *ASRep {
		rep := &ASRep{KDCRepFields: KDCRepFields{CName: cname, CRealm: "EXAMPLE.COM"}}
		rep.DecryptedEncPart = EncKDCRepPart{
			Nonce:    4242,
			SName:    sname,
			SRealm:   "EXAMPLE.COM",
			AuthTime: now,
		}
		return rep
	}
	creds := credentials.New("user", "EXAMPLE.COM")

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
	t.Run("enc-pa-rep not acknowledged", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}
		_, err := newRep().verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KDC did not acknowledge PA-REQ-ENC-PA-REP")
	})
	t.Run("enc-pa-rep omitted", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		_, err := rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "KDC omitted PA-REQ-ENC-PA-REP")
	})
	t.Run("enc-pa-rep corrupt value", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		rep.DecryptedEncPart.EncPAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: []byte{0xFF}}}
		_, err := rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "could not unmarshal PA-REQ-ENC-PA-REP response")
	})
	t.Run("enc-pa-rep unsupported checksum type", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}
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
		req.PAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}
		rep := newRep()
		types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
		value, err := asn1.Marshal(types.PAReqEncPARep{ChksumType: chksumtype.HMAC_SHA1_96_AES256, Chksum: make([]byte, 32)})
		require.NoError(t, err)
		rep.DecryptedEncPart.EncPAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: value}}
		_, err = rep.verifyWithReplyKey(cfg, creds, req, key, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "PA-REQ-ENC-PA-REP checksum invalid")
	})
	t.Run("enc-pa-rep checksum valid", func(t *testing.T) {
		req := newReq()
		req.PAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}
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
			{PADataType: patype.PA_PAC_REQUEST}, // non-matching entries are skipped
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
		req.PAData = types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}
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
	t.Run("verify decrypts with wrong password", func(t *testing.T) {
		var rep ASRep
		require.NoError(t, rep.Unmarshal(mustDecodeHex(t, testdata.MarshaledKRB5as_rep)))
		pwCreds := credentials.New("user", "EXAMPLE.COM")
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
		Forwardable:       &no,
		Forwarded:         &yes,
		Addresses:         &addresses,
		SupportedEncTypes: msflags.SupportedEncTypeClaims | msflags.SupportedEncTypeAES256CTSHMACSHA196SK,
	}

	req, err := tgsReq(cname, sname, "EXAMPLE.COM", true, cfg, options)
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

	req, err := tgsReq(cname, sname, "EXAMPLE.COM", false, cfg, TGSReqOptions{})
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

	req, err := NewASReqWithOptions("EXAMPLE.COM", cfg, cname, sname, ASReqOptions{
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
		Realm:      "EXAMPLE.COM",
		Components: sname.NameString,
		NameType:   sname.NameType,
	}, 1, svcKey, now))

	newTicket := func(t *testing.T) (Ticket, types.EncryptionKey) {
		t.Helper()
		tkt, sessionKey, err := NewTicketWithKey(cname, "EXAMPLE.COM", sname, "EXAMPLE.COM", types.NewKrbFlags(), svcKey, 1, now, now.Add(-time.Hour), now.Add(time.Hour), now.Add(2*time.Hour))
		require.NoError(t, err)
		return tkt, sessionKey
	}
	newAuthenticator := func() types.Authenticator {
		return types.Authenticator{AVNO: 5, CRealm: "EXAMPLE.COM", CName: cname, CTime: now, Cusec: 123}
	}

	t.Run("success", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{}, nil)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("success with sname override", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		override := sname
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{}, &override)
		require.NoError(t, err)
		assert.True(t, ok)
	})
	t.Run("key not in keytab", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		_, err = apReq.Verify(keytab.New(), 5*time.Minute, types.HostAddress{}, nil)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "error decrypting encpart of service ticket")
	})
	t.Run("expired ticket", func(t *testing.T) {
		tkt, sessionKey, err := NewTicketWithKey(cname, "EXAMPLE.COM", sname, "EXAMPLE.COM", types.NewKrbFlags(), svcKey, 1, now.Add(-4*time.Hour), now.Add(-4*time.Hour), now.Add(-3*time.Hour), now.Add(-2*time.Hour))
		require.NoError(t, err)
		apReq, err := NewAPReq(tkt, sessionKey, newAuthenticator())
		require.NoError(t, err)
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{}, nil)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "has expired")
	})
	t.Run("client address not in ticket", func(t *testing.T) {
		tkt, sessionKey := newTicket(t)
		etp := EncTicketPart{
			Flags:     types.NewKrbFlags(),
			Key:       sessionKey,
			CRealm:    "EXAMPLE.COM",
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
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{AddrType: addrtype.IPv4, Address: []byte{127, 0, 0, 1}}, nil)
		require.Error(t, err)
		assert.False(t, ok)
		assert.Contains(t, err.Error(), "client address not within the list")
	})
	t.Run("authenticator integrity failure", func(t *testing.T) {
		tkt, _ := newTicket(t)
		otherSession := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: append([]byte{0xFF}, make([]byte, 31)...)}
		apReq, err := NewAPReq(tkt, otherSession, newAuthenticator())
		require.NoError(t, err)
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{}, nil)
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
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{}, nil)
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
		ok, err := apReq.Verify(kt, 5*time.Minute, types.HostAddress{}, nil)
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

	_, err := NewTGSReqWithOptions(cname, "EXAMPLE.COM", cfg, s4uTestTicket(), key, sname, false, TGSReqOptions{PACOptions: []int{999}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "PA-PAC-OPTIONS")
}

// FuzzMessageUnmarshal fuzzes every wire-format decoder in the package with
// the valid message vectors as seeds. Malformed inputs must never panic.
func FuzzMessageUnmarshal(f *testing.F) {
	vectors := messageUnmarshalVectors(f)
	names := make([]string, 0, len(vectors))
	for name, vector := range vectors {
		names = append(names, name)
		b, err := hex.DecodeString(vector.hex)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(len(names)-1, b)
	}
	f.Fuzz(func(_ *testing.T, index int, b []byte) {
		i := index % len(names)
		if i < 0 {
			i += len(names)
		}
		_ = vectors[names[i]].unmarshal(b)
	})
}
