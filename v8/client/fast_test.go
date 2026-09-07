package client

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func newFASTTestState(t *testing.T) (*Client, *fastState, messages.ASReq) {
	t.Helper()
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")
	armorKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	armorTicket := s4uTestTicket("EXAMPLE.ORG", "krbtgt/EXAMPLE.ORG")
	cl := NewWithKeytab("user", "EXAMPLE.ORG", phase5Keytab(t, etypeID.AES128_CTS_HMAC_SHA1_96), cfg,
		FASTArmorWithIdentity(armorTicket, armorKey, cname, "EXAMPLE.ORG"),
		DisablePAReqEncPARep(true),
	)
	state, err := cl.newFASTState("EXAMPLE.ORG", true)
	if err != nil {
		t.Fatal(err)
	}
	request, err := cl.newASReq()
	if err != nil {
		t.Fatal(err)
	}
	return cl, state, request
}

func TestFASTASRequestEncryptsInnerRequest(t *testing.T) {
	cl, state, request := newFASTTestState(t)
	request.PAData = types.PADataSequence{{PADataType: patype.PA_ENC_TIMESTAMP, PADataValue: []byte("outside-fast")}}
	if err := state.setASPreAuth(cl, nil, &request); err != nil {
		t.Fatal(err)
	}
	wrapped, err := state.wrapASRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped.PAData) != 1 || wrapped.PAData[0].PADataType != patype.PA_FX_FAST {
		t.Fatalf("outer padata = %#v, want only PA-FX-FAST", wrapped.PAData)
	}
	fastPA, err := wrapped.PAData[0].GetPAFXFastRequest()
	if err != nil {
		t.Fatal(err)
	}
	if fastPA.ArmoredData.Armor.ArmorType != fxFastArmorAPRequest {
		t.Fatalf("armor type = %d, want %d", fastPA.ArmoredData.Armor.ArmorType, fxFastArmorAPRequest)
	}
	var armorAPReq messages.APReq
	if err := armorAPReq.Unmarshal(fastPA.ArmoredData.Armor.ArmorValue); err != nil {
		t.Fatal(err)
	}
	if err := armorAPReq.DecryptAuthenticatorWithKeyUsage(state.armor.key, keyusage.AP_REQ_AUTHENTICATOR); err != nil {
		t.Fatal(err)
	}
	if err := armorAPReq.DecryptAuthenticatorWithKeyUsage(state.armor.key, keyusage.TGS_REQ_PA_TGS_REQ_AP_REQ_AUTHENTICATOR); err == nil {
		t.Fatal("FAST armor authenticator accepted TGS-REQ key usage")
	}
	if len(armorAPReq.Authenticator.SubKey.KeyValue) == 0 {
		t.Fatal("FAST armor authenticator omitted its subkey")
	}
	body, err := request.ReqBody.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	et, _ := crypto.GetEtype(state.armorKey.KeyType)
	if !et.VerifyChecksum(state.armorKey.KeyValue, body, fastPA.ArmoredData.ReqChecksum.Checksum, keyusage.FAST_REQ_CHKSUM) {
		t.Fatal("FAST outer request-body checksum did not verify")
	}
	plain, err := crypto.DecryptEncPart(fastPA.ArmoredData.EncFastReq, state.armorKey, keyusage.FAST_ENC)
	if err != nil {
		t.Fatal(err)
	}
	var inner types.KrbFastReq
	if err := inner.Unmarshal(plain); err != nil {
		t.Fatal(err)
	}
	if !inner.PAData.Contains(patype.PA_ENCRYPTED_CHALLENGE) || inner.PAData.Contains(patype.PA_ENC_TIMESTAMP) {
		t.Fatalf("inner padata types = %#v, want encrypted challenge without encrypted timestamp", inner.PAData)
	}
}

func TestFASTASPreAuthEchoesCookie(t *testing.T) {
	cl, state, request := newFASTTestState(t)
	info, err := asn1.Marshal(types.ETypeInfo2{{EType: etypeID.AES128_CTS_HMAC_SHA1_96}})
	if err != nil {
		t.Fatal(err)
	}
	methodData := types.PADataSequence{
		{PADataType: patype.PA_FX_COOKIE, PADataValue: []byte("opaque-cookie")},
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info},
	}
	encoded, err := asn1.Marshal(methodData)
	if err != nil {
		t.Fatal(err)
	}
	hint := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
	hint.CName = cl.Credentials.CName()
	hint.CRealm = cl.Credentials.Realm()
	hint.EData = encoded
	if err := state.setASPreAuth(cl, &hint, &request); err != nil {
		t.Fatal(err)
	}
	secondMethodData, err := asn1.Marshal(types.PADataSequence{{PADataType: patype.PA_FX_COOKIE, PADataValue: []byte("replacement-cookie")}})
	if err != nil {
		t.Fatal(err)
	}
	secondHint := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, "")
	secondHint.EData = secondMethodData
	if err := state.setASPreAuth(cl, &secondHint, &request); err != nil {
		t.Fatalf("second FAST round without ETYPE-INFO failed: %v", err)
	}
	for _, pa := range request.PAData {
		if pa.PADataType == patype.PA_FX_COOKIE && string(pa.PADataValue) == "replacement-cookie" {
			return
		}
	}
	t.Fatal("FAST pre-authentication did not echo PA-FX-COOKIE")
}

func TestFASTASPreAuthRejectsMalformedMethodData(t *testing.T) {
	cl, state, request := newFASTTestState(t)
	if err := state.setASPreAuth(cl, nil, &request); err != nil {
		t.Fatal(err)
	}
	hint := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KDC_ERR_MORE_PREAUTH_DATA_REQUIRED, "")
	hint.EData = []byte{0x30, 0x01, 0xff}

	err := state.setASPreAuth(cl, &hint, &request)
	if err == nil || !strings.Contains(err.Error(), "METHOD-DATA") {
		t.Fatalf("malformed FAST hint error = %v", err)
	}
}

func TestFASTUnwrapAuthenticatedError(t *testing.T) {
	_, state, request := newFASTTestState(t)
	inner := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KDC_ERR_PREAUTH_FAILED, "inner")
	innerBytes, err := inner.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fxError, err := types.NewPAFXErrorPAData(types.PAFXError(innerBytes))
	if err != nil {
		t.Fatal(err)
	}
	cookie := types.PAData{PADataType: patype.PA_FX_COOKIE, PADataValue: []byte("next")}
	outer := fastTestError(t, state, request.ReqBody.Nonce, types.PADataSequence{fxError, cookie})
	got, err := state.unwrapError(outer, request.ReqBody.Nonce)
	if err != nil {
		t.Fatal(err)
	}
	if got.ErrorCode != errorcode.KDC_ERR_PREAUTH_FAILED {
		t.Fatalf("inner error code = %d", got.ErrorCode)
	}
	methodData, err := got.MethodData()
	if err != nil {
		t.Fatal(err)
	}
	if !methodData.Contains(patype.PA_FX_COOKIE) {
		t.Fatal("authenticated FAST error lost its cookie")
	}
	if _, err := state.unwrapError(outer, request.ReqBody.Nonce+1); err == nil {
		t.Fatal("FAST error with a mismatched nonce was accepted")
	}
}

func TestFASTASExchangeRejectsUnarmoredReplyAfterActivation(t *testing.T) {
	cl, _, request := newFASTTestState(t)
	info, err := asn1.Marshal(types.ETypeInfo2{{EType: etypeID.AES128_CTS_HMAC_SHA1_96}})
	if err != nil {
		t.Fatal(err)
	}
	methodData, err := asn1.Marshal(types.PADataSequence{
		{PADataType: patype.PA_FX_FAST},
		{PADataType: patype.PA_ETYPE_INFO2, PADataValue: info},
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	cl.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		calls++
		if calls == 1 {
			kdcErr := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KDC_ERR_PREAUTH_REQUIRED, "")
			kdcErr.EData = methodData
			return nil, kdcErr
		}
		var wrapped messages.ASReq
		if err := wrapped.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if len(wrapped.PAData) != 1 || wrapped.PAData[0].PADataType != patype.PA_FX_FAST {
			t.Fatalf("retry padata = %#v, want only PA-FX-FAST", wrapped.PAData)
		}
		reply := messages.ASRep{KDCRepFields: messages.KDCRepFields{
			PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REP,
			CRealm: request.ReqBody.Realm, CName: request.ReqBody.CName,
			Ticket:  s4uTestTicket(request.ReqBody.Realm, request.ReqBody.SName.PrincipalNameString()),
			EncPart: types.EncryptedData{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Cipher: []byte("unarmored")},
		}}
		return reply.Marshal()
	}
	if _, err := cl.ASExchange("EXAMPLE.ORG", request, 0); err == nil {
		t.Fatal("unarmored AS-REP was accepted after FAST activation")
	}
	if calls != 2 {
		t.Fatalf("AS exchange calls = %d, want 2", calls)
	}
}

func TestFASTStateActivatesFromRealmMetadata(t *testing.T) {
	cl, _, _ := newFASTTestState(t)
	cl.sessions.update(&session{realm: "EXAMPLE.ORG", supportedEncTypes: msflags.SupportedEncTypeFAST})
	state, err := cl.newFASTState("EXAMPLE.ORG", false)
	if err != nil {
		t.Fatal(err)
	}
	if state == nil || !state.active {
		t.Fatal("cached FAST_SUPPORTED metadata did not activate FAST")
	}
}

func TestFASTArmorKeytabAcquisitionFailures(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTktEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}

	empty := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg, FASTArmorFromKeytab(keytab.New()))
	if _, err := empty.newFASTState("EXAMPLE.ORG", true); err == nil || !strings.Contains(err.Error(), "no principals") {
		t.Fatalf("empty armor keytab error = %v", err)
	}

	client := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg, FASTArmorFromKeytab(phase5Keytab(t, etypeID.AES128_CTS_HMAC_SHA1_96)))
	client.sendToKDCFunc = func([]byte, string) ([]byte, error) { return nil, errors.New("offline") }
	if _, err := client.newFASTState("EXAMPLE.ORG", true); err == nil || !strings.Contains(err.Error(), "acquire FAST armor TGT") {
		t.Fatalf("armor login error = %v", err)
	}
	if client.fastArmorCl != nil {
		t.Fatal("failed armor client was retained")
	}
}

func TestFASTExplicitArmorValidation(t *testing.T) {
	cfg := config.New()
	client := NewWithPassword("user", "EXAMPLE.ORG", "password", cfg)
	state := new(fastState)
	client.settings.fastArmor = &fastArmorCredentials{
		ticket: s4uTestTicket("EXAMPLE.ORG", "HTTP/not-a-tgt"),
		key:    types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")},
	}
	if err := state.activate(client, "EXAMPLE.ORG"); err == nil || !strings.Contains(err.Error(), "not a TGT") {
		t.Fatalf("invalid armor ticket error = %v", err)
	}
	client.settings.fastArmor.ticket = s4uTestTicket("EXAMPLE.ORG", "krbtgt/EXAMPLE.ORG")
	client.settings.fastArmor.key = types.EncryptionKey{KeyType: -1}
	if err := state.activate(client, "EXAMPLE.ORG"); err == nil || !strings.Contains(err.Error(), "session key") {
		t.Fatalf("invalid armor key error = %v", err)
	}
}

func fastTestError(t *testing.T, state *fastState, nonce int, paData types.PADataSequence) messages.KRBError {
	t.Helper()
	responseBytes, err := (&types.KrbFastResponse{PAData: paData, Nonce: uint32(nonce)}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.GetEncryptedData(responseBytes, state.armorKey, keyusage.FAST_REP, 0)
	if err != nil {
		t.Fatal(err)
	}
	fastPA, err := types.NewPAFXFastReplyPAData(types.PAFXFastReply{ArmoredData: types.KrbFastArmoredRep{EncFastRep: encrypted}})
	if err != nil {
		t.Fatal(err)
	}
	methodData, err := asn1.Marshal(types.PADataSequence{fastPA})
	if err != nil {
		t.Fatal(err)
	}
	outer := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.ORG", errorcode.KDC_ERR_PREAUTH_FAILED, "outer")
	outer.EData = methodData
	return outer
}

func TestFASTVerifyASReplyStrengthensKey(t *testing.T) {
	cl, state, request := newFASTTestState(t)
	if err := state.setASPreAuth(cl, nil, &request); err != nil {
		t.Fatal(err)
	}
	strengthen := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("strengthen-key!!")}
	strengthened, err := crypto.KRBFXCF2(strengthen, state.replyKey, []byte("strengthenkey"), []byte("replykey"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	reply := messages.ASRep{KDCRepFields: messages.KDCRepFields{
		PVNO: iana.PVNO, MsgType: msgtype.KRB_AS_REP,
		CRealm: request.ReqBody.Realm, CName: request.ReqBody.CName,
		Ticket: s4uTestTicket(request.ReqBody.Realm, request.ReqBody.SName.PrincipalNameString()),
	}}
	part := messages.EncKDCRepPart{
		Key:   types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("session-key-1234")},
		Nonce: request.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now,
		EndTime: now.Add(time.Hour), SRealm: request.ReqBody.Realm, SName: request.ReqBody.SName,
	}
	partBytes, err := part.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reply.EncPart, err = crypto.GetEncryptedData(partBytes, strengthened, keyusage.AS_REP_ENCPART, 0)
	if err != nil {
		t.Fatal(err)
	}
	challengeKey, err := crypto.KRBFXCF2(state.armorKey, state.replyKey, []byte("kdcchallengearmor"), []byte("challengelongterm"))
	if err != nil {
		t.Fatal(err)
	}
	challengeBytes, err := types.GetPAEncTSEncAsnMarshalledAt(now)
	if err != nil {
		t.Fatal(err)
	}
	challengeEncrypted, err := crypto.GetEncryptedData(challengeBytes, challengeKey, keyusage.ENC_CHALLENGE_KDC, 0)
	if err != nil {
		t.Fatal(err)
	}
	challengePA, err := types.NewPAEncryptedChallengePAData(types.PAEncryptedChallenge(challengeEncrypted))
	if err != nil {
		t.Fatal(err)
	}
	ticketBytes, err := reply.Ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	et, _ := crypto.GetEtype(state.armorKey.KeyType)
	ticketChecksum, err := et.GetChecksumHash(state.armorKey.KeyValue, ticketBytes, keyusage.FAST_FINISHED)
	if err != nil {
		t.Fatal(err)
	}
	response := types.KrbFastResponse{
		PAData: challengePASequence(challengePA), StrengthenKey: strengthen, Nonce: uint32(request.ReqBody.Nonce),
		Finished: types.KrbFastFinished{Timestamp: now, Usec: now.Nanosecond() / int(time.Microsecond), CRealm: reply.CRealm, CName: reply.CName,
			TicketChecksum: types.Checksum{CksumType: chksumtype.HMAC_SHA1_96_AES128, Checksum: ticketChecksum}},
	}
	responseBytes, err := response.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fastEncrypted, err := crypto.GetEncryptedData(responseBytes, state.armorKey, keyusage.FAST_REP, 0)
	if err != nil {
		t.Fatal(err)
	}
	fastPA, err := types.NewPAFXFastReplyPAData(types.PAFXFastReply{ArmoredData: types.KrbFastArmoredRep{EncFastRep: fastEncrypted}})
	if err != nil {
		t.Fatal(err)
	}
	reply.PAData = types.PADataSequence{fastPA}
	if err := state.verifyASReply(cl, &reply, request, nil); err != nil {
		t.Fatal(err)
	}
	if reply.DecryptedEncPart.Nonce != request.ReqBody.Nonce {
		t.Fatal("FAST-strengthened AS-REP was not decrypted")
	}

	response.Finished.TicketChecksum.Checksum[0] ^= 0xff
	responseBytes, _ = response.Marshal()
	fastEncrypted, _ = crypto.GetEncryptedData(responseBytes, state.armorKey, keyusage.FAST_REP, 0)
	fastPA, _ = types.NewPAFXFastReplyPAData(types.PAFXFastReply{ArmoredData: types.KrbFastArmoredRep{EncFastRep: fastEncrypted}})
	reply.PAData = types.PADataSequence{fastPA}
	if err := state.verifyASReply(cl, &reply, request, nil); err == nil {
		t.Fatal("tampered FAST finished checksum was accepted")
	}
}

func TestFASTTGSRequestUsesImplicitArmor(t *testing.T) {
	cl, _, _ := newFASTTestState(t)
	tgt := s4uTestTicket("EXAMPLE.ORG", "krbtgt/EXAMPLE.ORG")
	sessionKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("tgt-session-key!")}
	request, err := messages.NewTGSReq(cl.Credentials.CName(), "EXAMPLE.ORG", cl.Config, tgt, sessionKey,
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.org"), false)
	if err != nil {
		t.Fatal(err)
	}
	state := &fastState{active: true}
	wrapped, err := state.wrapTGSRequest(request, tgt, sessionKey)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrapped.PAData) != 2 || wrapped.PAData[0].PADataType != patype.PA_TGS_REQ || wrapped.PAData[1].PADataType != patype.PA_FX_FAST {
		t.Fatalf("outer TGS padata types = %#v, want PA-TGS-REQ and PA-FX-FAST", wrapped.PAData)
	}
	fastPA, err := wrapped.PAData[1].GetPAFXFastRequest()
	if err != nil {
		t.Fatal(err)
	}
	if fastPA.ArmoredData.Armor.ArmorType != 0 || len(fastPA.ArmoredData.Armor.ArmorValue) != 0 {
		t.Fatal("implicit TGS armor unexpectedly included an explicit armor value")
	}
	et, _ := crypto.GetEtype(state.armorKey.KeyType)
	if !et.VerifyChecksum(state.armorKey.KeyValue, wrapped.PAData[0].PADataValue, fastPA.ArmoredData.ReqChecksum.Checksum, keyusage.FAST_REQ_CHKSUM) {
		t.Fatal("FAST PA-TGS-REQ checksum did not verify")
	}
	plain, err := crypto.DecryptEncPart(fastPA.ArmoredData.EncFastReq, state.armorKey, keyusage.FAST_ENC)
	if err != nil {
		t.Fatal(err)
	}
	var inner types.KrbFastReq
	if err := inner.Unmarshal(plain); err != nil {
		t.Fatal(err)
	}
	if inner.PAData.Contains(patype.PA_TGS_REQ) || !inner.PAData.Contains(patype.PA_PAC_REQUEST) || !inner.PAData.Contains(patype.PA_PAC_OPTIONS) {
		t.Fatalf("inner TGS padata types = %#v", inner.PAData)
	}
}

func TestFASTVerifyTGSReplyUsesStrengthenedSubkey(t *testing.T) {
	cl, _, _ := newFASTTestState(t)
	tgt := s4uTestTicket("EXAMPLE.ORG", "krbtgt/EXAMPLE.ORG")
	sessionKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("tgt-session-key!")}
	request, err := messages.NewTGSReq(cl.Credentials.CName(), "EXAMPLE.ORG", cl.Config, tgt, sessionKey,
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.org"), false)
	if err != nil {
		t.Fatal(err)
	}
	state := &fastState{active: true}
	if _, err := state.wrapTGSRequest(request, tgt, sessionKey); err != nil {
		t.Fatal(err)
	}
	strengthen := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("strengthen-key!!")}
	replyKey, err := crypto.KRBFXCF2(strengthen, state.replyKey, []byte("strengthenkey"), []byte("replykey"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	reply := messages.TGSRep{KDCRepFields: messages.KDCRepFields{
		PVNO: iana.PVNO, MsgType: msgtype.KRB_TGS_REP, CRealm: request.ReqBody.Realm, CName: request.ReqBody.CName,
		Ticket: s4uTestTicket(request.ReqBody.Realm, request.ReqBody.SName.PrincipalNameString()),
	}}
	part := messages.EncKDCRepPart{
		Key:   types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("service-key-123")},
		Nonce: request.ReqBody.Nonce, Flags: types.NewKrbFlags(), AuthTime: now, StartTime: now,
		EndTime: now.Add(time.Hour), SRealm: request.ReqBody.Realm, SName: request.ReqBody.SName,
	}
	partBytes, err := part.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reply.EncPart, err = crypto.GetEncryptedData(partBytes, replyKey, keyusage.TGS_REP_ENCPART_AUTHENTICATOR_SUB_KEY, 0)
	if err != nil {
		t.Fatal(err)
	}
	ticketBytes, err := reply.Ticket.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	et, _ := crypto.GetEtype(state.armorKey.KeyType)
	checksum, err := et.GetChecksumHash(state.armorKey.KeyValue, ticketBytes, keyusage.FAST_FINISHED)
	if err != nil {
		t.Fatal(err)
	}
	response := types.KrbFastResponse{
		PAData: types.PADataSequence{}, StrengthenKey: strengthen, Nonce: uint32(request.ReqBody.Nonce),
		Finished: types.KrbFastFinished{Timestamp: now, Usec: now.Nanosecond() / int(time.Microsecond), CRealm: reply.CRealm, CName: reply.CName,
			TicketChecksum: types.Checksum{CksumType: chksumtype.HMAC_SHA1_96_AES128, Checksum: checksum}},
	}
	responseBytes, err := response.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.GetEncryptedData(responseBytes, state.armorKey, keyusage.FAST_REP, 0)
	if err != nil {
		t.Fatal(err)
	}
	fastPA, err := types.NewPAFXFastReplyPAData(types.PAFXFastReply{ArmoredData: types.KrbFastArmoredRep{EncFastRep: encrypted}})
	if err != nil {
		t.Fatal(err)
	}
	reply.PAData = types.PADataSequence{fastPA}
	if err := state.verifyTGSReply(cl, &reply, request); err != nil {
		t.Fatal(err)
	}
	if reply.DecryptedEncPart.Nonce != request.ReqBody.Nonce {
		t.Fatal("FAST-strengthened TGS-REP was not decrypted")
	}

	setFASTResponse := func(response types.KrbFastResponse) {
		t.Helper()
		responseBytes, marshalErr := response.Marshal()
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		encrypted, encryptErr := crypto.GetEncryptedData(responseBytes, state.armorKey, keyusage.FAST_REP, 0)
		if encryptErr != nil {
			t.Fatal(encryptErr)
		}
		fastPA, paErr := types.NewPAFXFastReplyPAData(types.PAFXFastReply{ArmoredData: types.KrbFastArmoredRep{EncFastRep: encrypted}})
		if paErr != nil {
			t.Fatal(paErr)
		}
		reply.PAData = types.PADataSequence{fastPA}
	}

	response.StrengthenKey = types.EncryptionKey{}
	setFASTResponse(response)
	if err := state.verifyTGSReply(cl, &reply, request); err == nil {
		t.Fatal("FAST TGS-REP without strengthen-key was accepted")
	}
	response.StrengthenKey = strengthen
	response.Nonce++
	setFASTResponse(response)
	if err := state.verifyTGSReply(cl, &reply, request); err == nil {
		t.Fatal("FAST TGS-REP with mismatched nonce was accepted")
	}
	response.Nonce = uint32(request.ReqBody.Nonce)
	response.Finished.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "other-user")
	setFASTResponse(response)
	if err := state.verifyTGSReply(cl, &reply, request); err == nil {
		t.Fatal("FAST TGS-REP with mismatched finished identity was accepted")
	}
}

func TestFASTTGSExchangeRejectsUnarmoredReply(t *testing.T) {
	cl, _, _ := newFASTTestState(t)
	cl.settings.requireFAST = true
	tgt := s4uTestTicket("EXAMPLE.ORG", "krbtgt/EXAMPLE.ORG")
	sessionKey := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("tgt-session-key!")}
	request, err := messages.NewTGSReq(cl.Credentials.CName(), "EXAMPLE.ORG", cl.Config, tgt, sessionKey,
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.org"), false)
	if err != nil {
		t.Fatal(err)
	}
	cl.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		var wrapped messages.TGSReq
		if err := wrapped.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if !wrapped.PAData.Contains(patype.PA_TGS_REQ) || !wrapped.PAData.Contains(patype.PA_FX_FAST) {
			t.Fatalf("TGS request padata = %#v, want PA-TGS-REQ and PA-FX-FAST", wrapped.PAData)
		}
		reply := messages.TGSRep{KDCRepFields: messages.KDCRepFields{
			PVNO: iana.PVNO, MsgType: msgtype.KRB_TGS_REP,
			CRealm: request.ReqBody.Realm, CName: request.ReqBody.CName,
			Ticket:  s4uTestTicket(request.ReqBody.Realm, request.ReqBody.SName.PrincipalNameString()),
			EncPart: types.EncryptedData{EType: etypeID.AES128_CTS_HMAC_SHA1_96, Cipher: []byte("unarmored")},
		}}
		return reply.Marshal()
	}
	if _, _, err := cl.TGSExchange(request, "EXAMPLE.ORG", tgt, sessionKey, 0); err == nil {
		t.Fatal("unarmored TGS-REP was accepted while FAST was required")
	}
}

func challengePASequence(pa types.PAData) types.PADataSequence {
	return types.PADataSequence{pa}
}
