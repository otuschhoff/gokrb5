package messages

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

const (
	testuser1EType18Keytab = "05020000004b0001000b544553542e474f4b5242350009746573747573657231000000015898e0770100120020bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de900000001"
	testuser1EType18ASREP  = "6b8202f3308202efa003020105a10302010ba22e302c302aa103020113a2230421301f301da003020112a1161b14544553542e474f4b524235746573747573657231a30d1b0b544553542e474f4b524235a4163014a003020101a10d300b1b09746573747573657231a582015a6182015630820152a003020105a10d1b0b544553542e474f4b524235a220301ea003020102a11730151b066b72627467741b0b544553542e474f4b524235a382011830820114a003020112a103020101a28201060482010237e486e32cd18ab1ac9f8d42e93f8babd7b3497084cc5599f18ec61961c6d5242d350354d99d67a7604c451116188d16cb719e84377212eac2743440e8c504ef69c755e489cc6b65f935dd032bfc076f9b2c56d816197845b8fe857d738bc59712787631a50e86833d1b0e4732c8712c856417a6a257758e7d01d3182adb3233f0dde65d228c240ed26aa1af69f8d765dc0bc69096fdb037a75af220fea176839528d44b70f7dabfaa2ea506de1296f847176a60c501fd8cef8e0a51399bb6d5f753962d96292e93ffe344c6630db912931d46d88c0279f00719e22d0efcfd4ee33a702d0b660c1f13970a9beec12c0c8af3dda68bd81ac1fe3f126d2a24ebb445c5a682012c30820128a003020112a282011f0482011bb149cc16018072c4c18788d95a33aba540e52c11b54a93e67e788d05de75d8f3d4aa1afafbbfa6fde3eb40e5aa1890644cea2607efd5213a3fd00345b02eeb9ae1b589f36c74c689cd4ec1239dfe61e42ba6afa33f6240e3cfab291e4abb465d273302dbf7dbd148a299a9369044dd03377c1687e7dd36aa66501284a4ca50c0a7b08f4f87aecfa23b0dd0b11490e3ad330906dab715de81fc52f120d09c39990b8b5330d4601cc396b2ed258834329c4cc02c563a12de3ef9bf11e946258bc2ab5257f4caa4d443a7daf0fc25f6f531c2fcba88af8ca55c85300997cd05abbea52811fe2d038ba8f62fc8e3bc71ce04362d356ea2e1df8ac55c784c53cfb07817d48e39fe99fc8788040d98209c79dcf044d97e80de9f47824646"
	testRealm              = "TEST.GOKRB5"
	testUser               = "testuser1"
	testUserPassword       = "passwordvalue"
)

func TestRequestAllowsCanonicalName(t *testing.T) {
	standard := KDCReqBody{KDCOptions: types.NewKrbFlags(), CName: types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL}}
	assert.False(t, requestAllowsCanonicalName(standard))

	canonicalized := standard
	types.SetFlag(&canonicalized.KDCOptions, flags.Canonicalize)
	assert.True(t, requestAllowsCanonicalName(canonicalized))

	enterprise := standard
	enterprise.CName.NameType = nametype.KRB_NT_ENTERPRISE
	assert.True(t, requestAllowsCanonicalName(enterprise))
}

func TestVerifyEncPARepRequiresAcknowledgementAndChecksum(t *testing.T) {
	rep := ASRep{KDCRepFields: KDCRepFields{DecryptedEncPart: EncKDCRepPart{Flags: types.NewKrbFlags()}}}
	req := ASReq{KDCReqFields: KDCReqFields{PAData: types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}}}
	err := rep.verifyEncPARep(req, types.EncryptionKey{}, nil)
	assert.ErrorContains(t, err, "did not acknowledge")

	types.SetFlag(&rep.DecryptedEncPart.Flags, flags.EncPARep)
	err = rep.verifyEncPARep(req, types.EncryptionKey{}, nil)
	assert.ErrorContains(t, err, "omitted PA-REQ-ENC-PA-REP")
}

func TestVerifyEncPARepUsesExplicitRequestBytes(t *testing.T) {
	request := ASReq{KDCReqFields: KDCReqFields{PAData: types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP}}}}
	replyKey := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	requestBytes := []byte("outer FAST AS-REQ")
	etype, err := crypto.GetEtype(replyKey.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := etype.GetChecksumHash(replyKey.KeyValue, requestBytes, keyusage.KEY_USAGE_AS_REQ)
	if err != nil {
		t.Fatal(err)
	}
	value, err := asn1.Marshal(types.PAReqEncPARep{ChksumType: etype.GetHashID(), Chksum: checksum})
	if err != nil {
		t.Fatal(err)
	}
	reply := ASRep{KDCRepFields: KDCRepFields{DecryptedEncPart: EncKDCRepPart{
		Flags:     types.NewKrbFlags(),
		EncPAData: types.PADataSequence{{PADataType: patype.PA_REQ_ENC_PA_REP, PADataValue: value}},
	}}}
	types.SetFlag(&reply.DecryptedEncPart.Flags, flags.EncPARep)

	if err := reply.verifyEncPARep(request, replyKey, requestBytes); err != nil {
		t.Fatalf("valid checksum over outer request rejected: %v", err)
	}
	if err := reply.verifyEncPARep(request, replyKey, []byte("inner AS-REQ")); err == nil {
		t.Fatal("checksum over outer request accepted for different inner request bytes")
	}
}

func TestASRepPublicVerificationPaths(t *testing.T) {
	replyBytes, err := hex.DecodeString(testuser1EType18ASREP)
	if err != nil {
		t.Fatal(err)
	}
	keytabBytes, err := hex.DecodeString(testuser1EType18Keytab)
	if err != nil {
		t.Fatal(err)
	}
	kt := keytab.New()
	if err := kt.Unmarshal(keytabBytes); err != nil {
		t.Fatal(err)
	}

	var inspected ASRep
	if err := inspected.Unmarshal(replyBytes); err != nil {
		t.Fatal(err)
	}
	key, _, err := kt.GetEncryptionKey(inspected.CName, inspected.CRealm, inspected.EncPart.KVNO, inspected.EncPart.EType)
	if err != nil {
		t.Fatal(err)
	}
	if err := inspected.DecryptEncPartWithKey(key); err != nil {
		t.Fatal(err)
	}
	request := ASReq{KDCReqFields: KDCReqFields{ReqBody: KDCReqBody{
		CName: inspected.CName, Realm: inspected.CRealm,
		SName: inspected.DecryptedEncPart.SName, Nonce: inspected.DecryptedEncPart.Nonce,
		KDCOptions: types.NewKrbFlags(),
	}}}
	cfg := config.New()
	cfg.LibDefaults.Clockskew = 100 * 365 * 24 * time.Hour

	newReply := func() ASRep {
		var reply ASRep
		if err := reply.Unmarshal(replyBytes); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	passwordReply := newReply()
	if ok, err := passwordReply.Verify(cfg, credentials.New(testUser, testRealm).WithPassword(testUserPassword), request); !ok || err != nil {
		t.Fatalf("password verification = %v, %v", ok, err)
	}
	keyReply := newReply()
	if ok, err := keyReply.VerifyWithReplyKey(cfg, credentials.New(testUser, testRealm), request, key); !ok || err != nil {
		t.Fatalf("explicit-key verification = %v, %v", ok, err)
	}
	bytesReply := newReply()
	if ok, err := bytesReply.VerifyWithReplyKeyAndRequestBytes(cfg, credentials.New(testUser, testRealm), request, key, []byte("unused")); !ok || err != nil {
		t.Fatalf("explicit request verification = %v, %v", ok, err)
	}

	missingSecret := newReply()
	if _, err := missingSecret.DecryptEncPart(credentials.New(testUser, testRealm)); err == nil {
		t.Fatal("AS reply decrypted without credentials")
	}
	wrongKey := key
	wrongKey.KeyValue = bytes.Repeat([]byte{0xff}, len(key.KeyValue))
	invalidReply := newReply()
	if ok, err := invalidReply.VerifyWithReplyKey(cfg, credentials.New(testUser, testRealm), request, wrongKey); ok || err == nil {
		t.Fatalf("wrong-key verification = %v, %v", ok, err)
	}
}

func TestUnmarshalASRep(t *testing.T) {
	t.Parallel()
	var a ASRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5as_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REP, a.MsgType, "MsgType not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestASRepVerifierInvariants(t *testing.T) {
	now := time.Now().UTC()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.ORG")
	address := types.HostAddress{AddrType: 2, Address: []byte{192, 0, 2, 1}}
	request := ASReq{KDCReqFields: KDCReqFields{ReqBody: KDCReqBody{CName: cname, Realm: "EXAMPLE.ORG", SName: sname, Nonce: 42, Addresses: []types.HostAddress{address}, KDCOptions: types.NewKrbFlags()}}}
	base := ASRep{KDCRepFields: KDCRepFields{CName: cname, CRealm: "EXAMPLE.ORG", DecryptedEncPart: EncKDCRepPart{Nonce: 42, SName: sname, SRealm: "EXAMPLE.ORG", CAddr: []types.HostAddress{address}, AuthTime: now}}}
	cfg := config.New()
	creds := credentials.New("original", "ORIGINAL.ORG")
	if ok, err := base.verifyWithReplyKey(cfg, creds, request, types.EncryptionKey{}, nil); !ok || err != nil || !creds.CName().Equal(cname) || creds.Domain() != "EXAMPLE.ORG" {
		t.Fatalf("valid AS reply = %v, %v, %v@%s", ok, err, creds.CName(), creds.Domain())
	}

	tests := map[string]func(*ASRep){
		"cname": func(reply *ASRep) { reply.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob") },
		"crealm": func(reply *ASRep) { reply.CRealm = "OTHER.ORG" },
		"nonce": func(reply *ASRep) { reply.DecryptedEncPart.Nonce++ },
		"sname": func(reply *ASRep) { reply.DecryptedEncPart.SName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/OTHER.ORG") },
		"srealm": func(reply *ASRep) { reply.DecryptedEncPart.SRealm = "OTHER.ORG" },
		"address": func(reply *ASRep) { reply.DecryptedEncPart.CAddr = []types.HostAddress{{AddrType: 2, Address: []byte{192, 0, 2, 2}}} },
		"clock skew": func(reply *ASRep) { reply.DecryptedEncPart.AuthTime = now.Add(-time.Hour) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			reply := base
			mutate(&reply)
			if ok, err := reply.verifyWithReplyKey(cfg, credentials.New("alice", "EXAMPLE.ORG"), request, types.EncryptionKey{}, nil); ok || err == nil {
				t.Fatalf("invalid AS reply accepted: %v, %v", ok, err)
			}
		})
	}
	canonicalRequest := request
	types.SetFlag(&canonicalRequest.ReqBody.KDCOptions, flags.Canonicalize)
	canonicalReply := base
	canonicalReply.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "canonical-alice")
	if ok, err := canonicalReply.verifyWithReplyKey(cfg, credentials.New("alice", "EXAMPLE.ORG"), canonicalRequest, types.EncryptionKey{}, nil); !ok || err != nil {
		t.Fatalf("canonical AS reply = %v, %v", ok, err)
	}
}

func TestTGSRepVerifierInvariants(t *testing.T) {
	now := time.Now().UTC()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	address := types.HostAddress{AddrType: 2, Address: []byte{192, 0, 2, 1}}
	request := TGSReq{KDCReqFields: KDCReqFields{ReqBody: KDCReqBody{CName: cname, Realm: "EXAMPLE.ORG", SName: sname, Nonce: 42, Addresses: []types.HostAddress{address}, KDCOptions: types.NewKrbFlags()}}}
	base := TGSRep{KDCRepFields: KDCRepFields{CName: cname, Ticket: Ticket{Realm: "EXAMPLE.ORG", SName: sname}, DecryptedEncPart: EncKDCRepPart{Nonce: 42, SRealm: "EXAMPLE.ORG", CAddr: []types.HostAddress{address}, StartTime: now, AuthTime: now}}}
	cfg := config.New()
	if ok, err := base.Verify(cfg, request); !ok || err != nil {
		t.Fatalf("valid TGS reply = %v, %v", ok, err)
	}
	tests := map[string]func(*TGSRep){
		"cname": func(reply *TGSRep) { reply.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob") },
		"ticket realm": func(reply *TGSRep) { reply.Ticket.Realm = "OTHER.ORG" },
		"nonce": func(reply *TGSRep) { reply.DecryptedEncPart.Nonce++ },
		"service realm": func(reply *TGSRep) { reply.DecryptedEncPart.SRealm = "OTHER.ORG" },
		"address": func(reply *TGSRep) { reply.DecryptedEncPart.CAddr = []types.HostAddress{{AddrType: 2, Address: []byte{192, 0, 2, 2}}} },
		"clock skew": func(reply *TGSRep) { reply.DecryptedEncPart.StartTime = now.Add(-time.Hour); reply.DecryptedEncPart.AuthTime = now.Add(-time.Hour) },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			reply := base
			mutate(&reply)
			if ok, err := reply.Verify(cfg, request); ok || err == nil {
				t.Fatalf("invalid TGS reply accepted: %v, %v", ok, err)
			}
		})
	}
	s4u := base
	s4u.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "impersonated")
	if ok, err := s4u.VerifyS4U(cfg, request); !ok || err != nil {
		t.Fatalf("S4U TGS reply = %v, %v", ok, err)
	}
}

func TestUnmarshalASRep_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a ASRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5as_repOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REP, a.MsgType, "MsgType not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestMarshalASRep(t *testing.T) {
	t.Parallel()
	var a ASRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5as_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of ASRep not as expected")
}

func TestUnmarshalTGSRep(t *testing.T) {
	t.Parallel()
	var a TGSRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REP, a.MsgType, "MsgType not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue, fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestUnmarshalTGSRep_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a TGSRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_repOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REP, a.MsgType, "MsgType not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.CRealm, "Client Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString), "CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString, "CName entries not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.Ticket.SName.NameString), "SName in ticket does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.Ticket.SName.NameString, "Ticket SName entries not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, iana.PVNO, a.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.Ticket.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
	assert.Equal(t, testdata.TEST_ETYPE, a.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, iana.PVNO, a.EncPart.KVNO, "Encrypted part KVNO not as expected")
	assert.Equal(t, testdata.TEST_CIPHERTEXT, string(a.EncPart.Cipher), "Ticket encrypted part cipher not as expected")
}

func TestMarshalTGSRep(t *testing.T) {
	t.Parallel()
	var a TGSRep
	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_rep)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Marshal errored: %v", err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of TGSRep not as expected")
}

func TestUnmarshalEncKDCRepPart(t *testing.T) {
	t.Parallel()
	var a EncKDCRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_kdc_rep_part)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, int32(1), a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, 2, len(a.LastReqs), "Number of last request entries not as expected")
	for i, r := range a.LastReqs {
		assert.Equal(t, int32(-5), r.LRType, fmt.Sprintf("Last request typ not as expected for last request entry %d", i+1))
		assert.Equal(t, tt, r.LRValue, fmt.Sprintf("Last request time value not as expected for last request entry %d", i+1))
	}
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Nonce not as expected")
	assert.Equal(t, tt, a.KeyExpiration, "key expiration time not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.StartTime, "Start time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, tt, a.RenewTill, "Renew Till time not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.SRealm, "SRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "SName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName string entries not as expected")
	assert.Equal(t, 2, len(a.CAddr), "Number of client addresses not as expected")
	for i, addr := range a.CAddr {
		assert.Equal(t, int32(2), addr.AddrType, fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address), fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
}

func TestUnmarshalEncKDCRepPart_optionalsNULL(t *testing.T) {
	t.Parallel()
	var a EncKDCRepPart
	b, err := hex.DecodeString(testdata.MarshaledKRB5enc_kdc_rep_partOptionalsNULL)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	//Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, int32(1), a.Key.KeyType, "Key type not as expected")
	assert.Equal(t, []byte("12345678"), a.Key.KeyValue, "Key value not as expected")
	assert.Equal(t, 2, len(a.LastReqs), "Number of last request entries not as expected")
	for i, r := range a.LastReqs {
		assert.Equal(t, int32(-5), r.LRType, fmt.Sprintf("Last request typ not as expected for last request entry %d", i+1))
		assert.Equal(t, tt, r.LRValue, fmt.Sprintf("Last request time value not as expected for last request entry %d", i+1))
	}
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Nonce not as expected")
	assert.Equal(t, "fe5cba98", hex.EncodeToString(a.Flags.Bytes), "Flags not as expected")
	assert.Equal(t, tt, a.AuthTime, "Auth time not as expected")
	assert.Equal(t, tt, a.EndTime, "End time not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.SRealm, "SRealm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "SName type not as expected")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString, "SName string entries not as expected")
}

func TestUnmarshalASRepDecodeAndDecrypt(t *testing.T) {
	t.Parallel()
	var asRep ASRep
	b, _ := hex.DecodeString(testuser1EType18ASREP)
	err := asRep.Unmarshal(b)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}
	assert.Equal(t, 5, asRep.PVNO, "PVNO not as expected")
	assert.Equal(t, 11, asRep.MsgType, "MsgType not as expected")
	assert.Equal(t, testRealm, asRep.CRealm, "Client Realm not as expected")
	assert.Equal(t, int32(1), asRep.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, testUser, asRep.CName.NameString[0], "CName NameType not as expected")
	assert.Equal(t, int32(19), asRep.PAData[0].PADataType, "PADataType not as expected")
	assert.Equal(t, 5, asRep.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testRealm, asRep.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, int32(2), asRep.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, "krbtgt", asRep.Ticket.SName.NameString[0], "Ticket service name string not as expected")
	assert.Equal(t, testRealm, asRep.Ticket.SName.NameString[1], "Ticket service name string not as expected")
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, 1, asRep.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, etypeID.ETypesByName["aes256-cts-hmac-sha1-96"], asRep.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, 0, asRep.EncPart.KVNO, "Encrypted part KVNO not as expected")
	//t.Log("Finished testing unecrypted parts of AS REP")
	ktb, _ := hex.DecodeString(testuser1EType18Keytab)
	kt := keytab.New()
	err = kt.Unmarshal(ktb)
	if err != nil {
		t.Fatalf("keytab parse error: %v\n", err)
	}
	cred := credentials.New(testUser, testRealm)
	_, err = asRep.DecryptEncPart(cred.WithKeytab(kt))
	if err != nil {
		t.Fatalf("Decryption of AS_REP EncPart failed: %v", err)
	}
	assert.Equal(t, int32(18), asRep.DecryptedEncPart.Key.KeyType, "KeyType in decrypted EncPart not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.LastReqs[0].LRValue, "LastReqs did not have a time value")
	assert.Equal(t, 2069991465, asRep.DecryptedEncPart.Nonce, "Nonce value not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.KeyExpiration, "Key expiration not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.AuthTime, "AuthTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.StartTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.EndTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.RenewTill, "RenewTill not a time type")
	assert.Equal(t, testRealm, asRep.DecryptedEncPart.SRealm, "Service realm not as expected")
	assert.Equal(t, int32(2), asRep.DecryptedEncPart.SName.NameType, "Name type for AS_REP not as expected")
	assert.Equal(t, []string{"krbtgt", testRealm}, asRep.DecryptedEncPart.SName.NameString, "Service name string not as expected")
}

func TestUnmarshalASRepDecodeAndDecrypt_withPassword(t *testing.T) {
	t.Parallel()
	var asRep ASRep
	b, _ := hex.DecodeString(testuser1EType18ASREP)
	err := asRep.Unmarshal(b)
	if err != nil {
		t.Fatalf("AS REP Unmarshal error: %v\n", err)
	}
	assert.Equal(t, 5, asRep.PVNO, "PVNO not as expected")
	assert.Equal(t, 11, asRep.MsgType, "MsgType not as expected")
	assert.Equal(t, testRealm, asRep.CRealm, "Client Realm not as expected")
	assert.Equal(t, int32(1), asRep.CName.NameType, "CName NameType not as expected")
	assert.Equal(t, testUser, asRep.CName.NameString[0], "CName NameType not as expected")
	assert.Equal(t, int32(19), asRep.PAData[0].PADataType, "PADataType not as expected")
	assert.Equal(t, 5, asRep.Ticket.TktVNO, "TktVNO not as expected")
	assert.Equal(t, testRealm, asRep.Ticket.Realm, "Ticket Realm not as expected")
	assert.Equal(t, int32(2), asRep.Ticket.SName.NameType, "Ticket service nametype not as expected")
	assert.Equal(t, "krbtgt", asRep.Ticket.SName.NameString[0], "Ticket service name string not as expected")
	assert.Equal(t, testRealm, asRep.Ticket.SName.NameString[1], "Ticket service name string not as expected")
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, asRep.Ticket.EncPart.EType, "Etype of ticket encrypted part not as expected")
	assert.Equal(t, 1, asRep.Ticket.EncPart.KVNO, "Ticket encrypted part KVNO not as expected")
	assert.Equal(t, etypeID.AES256_CTS_HMAC_SHA1_96, asRep.EncPart.EType, "Etype of encrypted part not as expected")
	assert.Equal(t, 0, asRep.EncPart.KVNO, "Encrypted part KVNO not as expected")
	cred := credentials.New(testUser, testRealm)
	_, err = asRep.DecryptEncPart(cred.WithPassword(testUserPassword))
	if err != nil {
		t.Fatalf("Decryption of AS_REP EncPart failed: %v", err)
	}
	assert.Equal(t, int32(18), asRep.DecryptedEncPart.Key.KeyType, "KeyType in decrypted EncPart not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.LastReqs[0].LRValue, "LastReqs did not have a time value")
	assert.Equal(t, 2069991465, asRep.DecryptedEncPart.Nonce, "Nonce value not as expected")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.KeyExpiration, "Key expiration not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.AuthTime, "AuthTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.StartTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.EndTime, "StartTime not a time type")
	assert.IsType(t, time.Time{}, asRep.DecryptedEncPart.RenewTill, "RenewTill not a time type")
	assert.Equal(t, testRealm, asRep.DecryptedEncPart.SRealm, "Service realm not as expected")
	assert.Equal(t, nametype.KRB_NT_SRV_INST, asRep.DecryptedEncPart.SName.NameType, "Name type for AS_REP not as expected")
	assert.Equal(t, []string{"krbtgt", testRealm}, asRep.DecryptedEncPart.SName.NameString, "Service name string not as expected")
}
