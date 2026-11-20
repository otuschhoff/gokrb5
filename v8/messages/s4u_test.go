package messages

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc4757"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const s4uTestRealm = "EXAMPLE.COM"

func TestFindS4UX509UserDecodeError(t *testing.T) {
	t.Parallel()

	paData := types.PADataSequence{{PADataType: patype.PA_S4U_X509_USER, PADataValue: []byte{0xFF}}}
	_, err := findS4UX509User(paData)
	cause := errors.Unwrap(err)
	if _, ok := errors.AsType[asn1.SyntaxError](cause); err == nil || !ok ||
		!strings.HasPrefix(err.Error(), "decode PA-S4U-X509-USER:") {
		t.Fatalf("expected PA-DATA decode context and syntax cause, got %v", err)
	}
}

func mustNonceUint32(t *testing.T, value int) uint32 {
	t.Helper()
	result, err := nonceUint32(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func TestNewPAForUserPAData(t *testing.T) {
	user := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"alice", "admin"}}
	key := types.EncryptionKey{KeyType: 0, KeyValue: []byte("0123456789abcdef")}

	pa, err := NewPAForUserPAData(user, s4uTestRealm, key)
	if err != nil {
		t.Fatalf("NewPAForUserPAData() error = %v", err)
	}
	got, err := pa.GetPAForUser()
	if err != nil {
		t.Fatalf("GetPAForUser() error = %v", err)
	}
	wantData := append([]byte{1, 0, 0, 0}, []byte("aliceadminEXAMPLE.COMKerberos")...)
	wantChecksum, err := rfc4757.Checksum(key.KeyValue, keyusage.KERB_NON_KERB_CKSUM_SALT, wantData)
	if err != nil {
		t.Fatalf("calculate expected checksum: %v", err)
	}
	if got.Cksum.CksumType != chksumtype.KERB_CHECKSUM_HMAC_MD5 {
		t.Errorf("checksum type = %d, want %d", got.Cksum.CksumType, chksumtype.KERB_CHECKSUM_HMAC_MD5)
	}
	if !bytes.Equal(got.Cksum.Checksum, wantChecksum) {
		t.Errorf("checksum = %x, want %x", got.Cksum.Checksum, wantChecksum)
	}
	if got.AuthPackage != "Kerberos" {
		t.Errorf("auth package = %q, want Kerberos", got.AuthPackage)
	}
}

func TestNonceConversionRange(t *testing.T) {
	for _, value := range []int{-1} {
		if _, err := nonceUint32(value); err == nil {
			t.Fatalf("nonce %d was accepted", value)
		}
	}
}

func TestNewS4U2SelfTGSReq(t *testing.T) {
	config := s4uTestConfig()
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	var options S4U2SelfReqOptions
	req, err := NewS4U2SelfTGSReq(
		service, s4uTestRealm, config, s4uTestTicket(), key, service, user, s4uTestRealm, options,
	)
	if err != nil {
		t.Fatalf("NewS4U2SelfTGSReq() error = %v", err)
	}
	if !req.ReqBody.SName.Equal(service) {
		t.Errorf("service name = %v, want %v", req.ReqBody.SName, service)
	}
	if !req.PAData.Contains(patype.PA_FOR_USER) || !req.PAData.Contains(patype.PA_S4U_X509_USER) {
		t.Errorf("PAData types = %v, want PA-FOR-USER and PA-S4U-X509-USER", req.PAData)
	}
	pa := findTestPAData(t, req.PAData, patype.PA_S4U_X509_USER)
	x509, err := pa.GetPAS4UX509User()
	if err != nil {
		t.Fatalf("GetPAS4UX509User() error = %v", err)
	}
	userID, err := x509.GetUserID()
	if err != nil {
		t.Fatalf("GetUserID() error = %v", err)
	}
	if userID.Nonce != mustNonceUint32(t, req.ReqBody.Nonce) ||
		!types.IsFlagSet(&userID.Options, flags.S4UOptionUseReplyKeyUsage) {
		t.Errorf("S4UUserID = %+v, want matching nonce and reply-key-usage option", userID)
	}
}

func TestNewS4U2SelfTGSReqRejectsInvalidCertificate(t *testing.T) {
	config := s4uTestConfig()
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	var options S4U2SelfReqOptions
	options.SubjectCertificate = []byte("not DER")
	_, err := NewS4U2SelfTGSReq(
		service, s4uTestRealm, config, s4uTestTicket(), key, service, user, s4uTestRealm, options,
	)
	if err == nil {
		t.Fatal("NewS4U2SelfTGSReq() accepted an invalid certificate")
	}
}

func TestNewS4U2ProxyTGSReq(t *testing.T) {
	config := s4uTestConfig()
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	target := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/target.example.com")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	evidence := s4uTestTicket()
	var options TGSReqOptions
	options.PACOptions = []int{flags.PACOptionResourceBasedConstrainedDelegation}
	req, err := NewS4U2ProxyTGSReq(service, s4uTestRealm, config, s4uTestTicket(), key, target, evidence, options)
	if err != nil {
		t.Fatalf("NewS4U2ProxyTGSReq() error = %v", err)
	}
	if !types.IsFlagSet(&req.ReqBody.KDCOptions, flags.CNameInAddlTkt) ||
		types.IsFlagSet(&req.ReqBody.KDCOptions, flags.EncTktInSkey) {
		t.Errorf("KDC options = %08b, want cname-in-addl-tkt only", req.ReqBody.KDCOptions.Bytes)
	}
	if len(req.ReqBody.AdditionalTickets) != 1 || !req.ReqBody.AdditionalTickets[0].SName.Equal(evidence.SName) {
		t.Errorf("additional tickets = %v, want evidence ticket", req.ReqBody.AdditionalTickets)
	}
	pacOptions, err := findTestPAData(t, req.PAData, patype.PA_PAC_OPTIONS).GetPAPACOptions()
	if err != nil {
		t.Fatalf("GetPAPACOptions() error = %v", err)
	}
	if !types.IsFlagSet(&pacOptions.Options, flags.PACOptionResourceBasedConstrainedDelegation) {
		t.Error("PA-PAC-OPTIONS does not contain the RBCD bit")
	}
}

func TestPAS4UX509UserRequestAndReplyChecksums(t *testing.T) {
	config := s4uTestConfig()
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	var options S4U2SelfReqOptions
	request, err := NewS4U2SelfTGSReq(
		service, s4uTestRealm, config, s4uTestTicket(), key, service, user, s4uTestRealm, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	requestValue, err := findTestPAData(t, request.PAData, patype.PA_S4U_X509_USER).GetPAS4UX509User()
	if err != nil {
		t.Fatal(err)
	}
	requestUserID, err := requestValue.GetUserID()
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, err := requestUserID.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	enctype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	if !enctype.VerifyChecksum(
		key.KeyValue, requestBytes, requestValue.Checksum.Checksum, keyusage.PA_S4U_X509_USER_REQUEST,
	) {
		t.Fatal("request checksum does not verify with usage 26")
	}
	checkS4UX509ReplyChecksum(t, request, requestUserID, key, enctype)
}

func checkS4UX509ReplyChecksum(
	t *testing.T, request TGSReq, requestUserID types.S4UUserID, key types.EncryptionKey, enctype etype.EType,
) {
	t.Helper()
	replyUserID := requestUserID
	replyUserID.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "Alice.Normalized")
	replyBytes, err := replyUserID.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	replyChecksum, err := enctype.GetChecksumHash(key.KeyValue, replyBytes, keyusage.PA_S4U_X509_USER_REPLY)
	if err != nil {
		t.Fatal(err)
	}
	replyValue, err := types.NewPAS4UX509User(
		replyUserID, types.Checksum{CksumType: enctype.GetHashID(), Checksum: replyChecksum},
	)
	if err != nil {
		t.Fatal(err)
	}
	replyPA, err := types.NewPAS4UX509UserPAData(replyValue)
	if err != nil {
		t.Fatal(err)
	}
	var reply TGSRep
	reply.PAData = types.PADataSequence{replyPA}
	got, err := reply.VerifyS4UX509UserReply(request, key)
	if err != nil {
		t.Fatalf("VerifyS4UX509UserReply() error = %v", err)
	}
	if !got.CName.Equal(replyUserID.CName) {
		t.Errorf("normalized cname = %v, want %v", got.CName, replyUserID.CName)
	}

	reply.PAData[0].PADataValue[len(reply.PAData[0].PADataValue)-1] ^= 0xff
	if _, err := reply.VerifyS4UX509UserReply(request, key); err == nil {
		t.Fatal("VerifyS4UX509UserReply() accepted a tampered checksum")
	}
}

func TestVerifyS4UX509UserReplyRequiresUsageAcknowledgement(t *testing.T) {
	config := s4uTestConfig()
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	var options S4U2SelfReqOptions
	request, err := NewS4U2SelfTGSReq(
		service, s4uTestRealm, config, s4uTestTicket(), key, service, user, s4uTestRealm, options,
	)
	if err != nil {
		t.Fatal(err)
	}
	userID := types.S4UUserID{
		Nonce:              mustNonceUint32(t, request.ReqBody.Nonce),
		CName:              user,
		CRealm:             s4uTestRealm,
		SubjectCertificate: nil,
		Options:            asn1.BitString{Bytes: nil, BitLength: 0},
	}
	userIDBytes, err := userID.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := etype.GetChecksumHash(key.KeyValue, userIDBytes, keyusage.PA_S4U_X509_USER_REQUEST)
	if err != nil {
		t.Fatal(err)
	}
	value, err := types.NewPAS4UX509User(userID, types.Checksum{CksumType: etype.GetHashID(), Checksum: checksum})
	if err != nil {
		t.Fatal(err)
	}
	pa, err := types.NewPAS4UX509UserPAData(value)
	if err != nil {
		t.Fatal(err)
	}
	var reply TGSRep
	reply.PAData = types.PADataSequence{pa}
	if _, err := reply.VerifyS4UX509UserReply(request, key); err == nil {
		t.Fatal("VerifyS4UX509UserReply() accepted a reply without usage-27 acknowledgement")
	}
}

func s4uTestConfig() *config.Config {
	c := config.New()
	c.LibDefaults.NoAddresses = true
	c.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	return c
}

func s4uTestTicket() Ticket {
	var ticket Ticket
	ticket.TktVNO = 5
	ticket.Realm = s4uTestRealm
	ticket.SName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM")
	ticket.EncPart = types.EncryptedData{
		EType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KVNO:   0,
		Cipher: []byte("ticket"),
	}
	return ticket
}

func findTestPAData(t *testing.T, paData types.PADataSequence, paType int32) *types.PAData {
	t.Helper()
	for i := range paData {
		if paData[i].PADataType == paType {
			return &paData[i]
		}
	}
	t.Fatalf("PA-DATA type %d not found", paType)
	return nil
}

func TestS4UChecksumDataEncodesSignedNameTypeLittleEndian(t *testing.T) {
	user := types.PrincipalName{NameType: -128, NameString: []string{"user"}}
	want := append([]byte{0x80, 0xff, 0xff, 0xff}, []byte("userREALMKerberos")...)
	if got := s4uChecksumData(user, "REALM", "Kerberos"); !bytes.Equal(got, want) {
		t.Errorf("s4uChecksumData() = %x, want %x", got, want)
	}
}
