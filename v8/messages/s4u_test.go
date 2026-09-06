package messages

import (
	"bytes"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc4757"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestNewPAForUserPAData(t *testing.T) {
	user := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"alice", "admin"}}
	realm := "EXAMPLE.COM"
	key := types.EncryptionKey{KeyValue: []byte("0123456789abcdef")}

	pa, err := NewPAForUserPAData(user, realm, key)
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

func TestNewS4U2SelfTGSReq(t *testing.T) {
	config := s4uTestConfig()
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	req, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", config, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{})
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
	if userID.Nonce != uint32(req.ReqBody.Nonce) || !types.IsFlagSet(&userID.Options, flags.S4UOptionUseReplyKeyUsage) {
		t.Errorf("S4UUserID = %+v, want matching nonce and reply-key-usage option", userID)
	}
}

func TestNewS4U2SelfTGSReqRejectsInvalidCertificate(t *testing.T) {
	config := s4uTestConfig()
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	_, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", config, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{SubjectCertificate: []byte("not DER")})
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
	options := TGSReqOptions{PACOptions: []int{flags.PACOptionResourceBasedConstrainedDelegation}}
	req, err := NewS4U2ProxyTGSReq(service, "EXAMPLE.COM", config, s4uTestTicket(), key, target, evidence, options)
	if err != nil {
		t.Fatalf("NewS4U2ProxyTGSReq() error = %v", err)
	}
	if !types.IsFlagSet(&req.ReqBody.KDCOptions, flags.CNameInAddlTkt) || types.IsFlagSet(&req.ReqBody.KDCOptions, flags.EncTktInSkey) {
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
	request, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", config, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{})
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
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		t.Fatal(err)
	}
	if !etype.VerifyChecksum(key.KeyValue, requestBytes, requestValue.Checksum.Checksum, keyusage.PA_S4U_X509_USER_REQUEST) {
		t.Fatal("request checksum does not verify with usage 26")
	}

	replyUserID := requestUserID
	replyUserID.CName = types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "Alice.Normalized")
	replyBytes, err := replyUserID.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	replyChecksum, err := etype.GetChecksumHash(key.KeyValue, replyBytes, keyusage.PA_S4U_X509_USER_REPLY)
	if err != nil {
		t.Fatal(err)
	}
	replyValue, err := types.NewPAS4UX509User(replyUserID, types.Checksum{CksumType: etype.GetHashID(), Checksum: replyChecksum})
	if err != nil {
		t.Fatal(err)
	}
	replyPA, err := types.NewPAS4UX509UserPAData(replyValue)
	if err != nil {
		t.Fatal(err)
	}
	reply := TGSRep{KDCRepFields: KDCRepFields{PAData: types.PADataSequence{replyPA}}}
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
	request, err := NewS4U2SelfTGSReq(service, "EXAMPLE.COM", config, s4uTestTicket(), key, service, user, "EXAMPLE.COM", S4U2SelfReqOptions{})
	if err != nil {
		t.Fatal(err)
	}
	userID := types.S4UUserID{Nonce: uint32(request.ReqBody.Nonce), CName: user, CRealm: "EXAMPLE.COM"}
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
	reply := TGSRep{KDCRepFields: KDCRepFields{PAData: types.PADataSequence{pa}}}
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
	return Ticket{
		TktVNO: 5,
		Realm:  "EXAMPLE.COM",
		SName:  types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.COM"),
		EncPart: types.EncryptedData{
			EType:  etypeID.AES128_CTS_HMAC_SHA1_96,
			Cipher: []byte("ticket"),
		},
	}
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
