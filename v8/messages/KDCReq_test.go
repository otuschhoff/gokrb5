package messages

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"testing"
	"testing/iotest"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/addrtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/msflags"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	kdcTestRealm      = "EXAMPLE.ORG"
	kdcTestRealmCOM   = "EXAMPLE.COM"
	kdcTestTGTService = "krbtgt"
)

func TestKDCRequestNonceErrors(t *testing.T) {
	// rand.Reader is process-wide; restore it before parallel tests run.
	cause := errors.New("test nonce reader failure")
	reader := rand.Reader
	t.Cleanup(func() { rand.Reader = reader })
	rand.Reader = iotest.ErrReader(cause)

	const realm = "NONCE-TEST.EXAMPLE"
	cfg := config.New()
	client := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "client")
	service := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/"+realm)
	asReq, asErr := NewASReq(realm, cfg, client, service)
	assert.Zero(t, asReq.PVNO)
	assert.ErrorIs(t, asErr, cause)
	assert.ErrorContains(t, asErr, "generate AS-REQ nonce:")

	var ticket Ticket
	var key types.EncryptionKey
	tgsReq, tgsErr := NewTGSReq(
		client,
		realm,
		cfg,
		ticket,
		key,
		service,
		false,
	)
	assert.Zero(t, tgsReq.PVNO)
	assert.ErrorIs(t, tgsErr, cause)
	assert.ErrorContains(t, tgsErr, "generate TGS-REQ nonce:")
}

func TestNewASReqRenewLifetimeHonoured(t *testing.T) {
	var emptyPrincipal types.PrincipalName
	cfg := config.New()
	cfg.LibDefaults.TicketLifetime = time.Hour
	cfg.LibDefaults.RenewLifetime = 7 * 24 * time.Hour
	req, err := NewASReq(kdcTestRealm, cfg, emptyPrincipal, emptyPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	assert.WithinDuration(t, req.ReqBody.Till.Add(cfg.LibDefaults.RenewLifetime-cfg.LibDefaults.TicketLifetime),
		req.ReqBody.RTime, time.Millisecond)
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renewable))

	zero := time.Duration(0)
	var options ASReqOptions
	options.RenewLifetime = &zero
	req, err = NewASReqWithOptions(kdcTestRealm, cfg, emptyPrincipal, emptyPrincipal, options)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, req.ReqBody.RTime.IsZero())
	assert.False(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renewable))
}

func TestNewASReqOptionsOverrideConfig(t *testing.T) {
	var emptyPrincipal types.PrincipalName
	cfg := config.New()
	cfg.LibDefaults.Forwardable = true
	cfg.LibDefaults.Proxiable = true
	cfg.LibDefaults.Canonicalize = true
	no := false
	lifetime := 2 * time.Hour
	start := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	service := types.PrincipalName{NameType: nametype.KRB_NT_SRV_INST, NameString: []string{"custom", "host"}}
	addresses := []types.HostAddress{{AddrType: addrtype.IPv4, Address: []byte{127, 0, 0, 1}}}
	var options ASReqOptions
	options.Lifetime = &lifetime
	options.Forwardable = &no
	options.Proxiable = &no
	options.Canonicalize = &no
	options.Addresses = addresses
	options.Enterprise = new(true)
	options.ServicePrincipal = &service
	options.StartTime = &start
	req, err := NewASReqWithOptions(kdcTestRealm, cfg, emptyPrincipal, emptyPrincipal, options)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, start.Add(lifetime), req.ReqBody.Till)
	assert.False(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwardable))
	assert.False(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Proxiable))
	assert.False(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Canonicalize))
	assert.Equal(t, nametype.KRB_NT_ENTERPRISE, req.ReqBody.CName.NameType)
	assert.Equal(t, service, req.ReqBody.SName)
	assert.Equal(t, start, req.ReqBody.From)
	assert.Equal(t, addresses, req.ReqBody.Addresses)
}

func TestNewASReqIncludesPACRequest(t *testing.T) {
	var emptyPrincipal types.PrincipalName
	cfg := config.New()
	req, err := NewASReq(kdcTestRealm, cfg, emptyPrincipal, emptyPrincipal)
	if err != nil {
		t.Fatal(err)
	}
	if len(req.PAData) != 1 {
		t.Fatalf("PA-DATA count = %d, want 1", len(req.PAData))
	}
	pacRequest, err := req.PAData[0].GetKerbPAPACRequest()
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, pacRequest.IncludePAC)

	cfg.LibDefaults.RequestPAC = false
	yes := true
	var includePAC ASReqOptions
	includePAC.IncludePAC = &yes
	req, err = NewASReqWithOptions(kdcTestRealm, cfg, emptyPrincipal, emptyPrincipal, includePAC)
	if err != nil {
		t.Fatal(err)
	}
	pacRequest, err = req.PAData[0].GetKerbPAPACRequest()
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, pacRequest.IncludePAC)

	no := false
	var omitPAC ASReqOptions
	omitPAC.IncludePAC = &no
	req, err = NewASReqWithOptions(kdcTestRealm, config.New(), emptyPrincipal, emptyPrincipal, omitPAC)
	if err != nil {
		t.Fatal(err)
	}
	pacRequest, err = req.PAData[0].GetKerbPAPACRequest()
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, pacRequest.IncludePAC)
}

func TestASRequestConvenienceConstructors(t *testing.T) {
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")

	tgt, err := NewASReqForTGT(kdcTestRealmCOM, cfg, cname)
	if err != nil {
		t.Fatal(err)
	}
	if tgt.ReqBody.SName.NameType != nametype.KRB_NT_SRV_INST ||
		!assert.ObjectsAreEqual(tgt.ReqBody.SName.NameString, []string{kdcTestTGTService, kdcTestRealmCOM}) {
		t.Fatalf("TGT service principal = %+v", tgt.ReqBody.SName)
	}
	lifetime := 30 * time.Minute
	var options ASReqOptions
	options.Lifetime = &lifetime
	tgt, err = NewASReqForTGTWithOptions(kdcTestRealmCOM, cfg, cname, options)
	if err != nil {
		t.Fatal(err)
	}
	if time.Until(tgt.ReqBody.Till) > lifetime+time.Second {
		t.Fatalf("TGT lifetime exceeds requested value: %v", time.Until(tgt.ReqBody.Till))
	}

	changePassword, err := NewASReqForChgPasswd(kdcTestRealmCOM, cfg, cname)
	if err != nil {
		t.Fatal(err)
	}
	if !assert.ObjectsAreEqual(changePassword.ReqBody.SName.NameString, []string{"kadmin", "changepw"}) {
		t.Fatalf("change-password service principal = %+v", changePassword.ReqBody.SName)
	}
}

func TestKDCRequestsAdvertiseConfiguredEnctypes(t *testing.T) {
	t.Parallel()

	const explicitLists = "default_tkt_enctypes=rc4-hmac aes128-sha1 des3-cbc-sha1-kd\n" +
		"default_tgs_enctypes=rc4-hmac aes128-sha1 des3-cbc-sha1-kd\n"
	for _, tc := range []struct {
		name string
		body string
		want []int32
	}{
		{name: "defaults", body: "", want: []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96}},
		{name: "legacy filtered", body: explicitLists, want: []int32{etypeID.AES128_CTS_HMAC_SHA1_96}},
		{
			name: "legacy opted in", body: explicitLists + "allow_weak_crypto=true\n",
			want: []int32{etypeID.RC4_HMAC, etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.DES3_CBC_SHA1_KD},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			checkKDCRequestEnctypeOffers(t, tc.body, tc.want)
		})
	}
}

func TestTGSReqMSKILEOptions(t *testing.T) {
	var emptyPrincipal types.PrincipalName
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{
		etypeID.RC4_HMAC, etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96,
	}
	original := append([]int32(nil), cfg.LibDefaults.DefaultTGSEnctypeIDs...)
	var reqOptions TGSReqOptions
	reqOptions.SupportedEncTypes = msflags.SupportedEncTypeAES256CTSHMACSHA196SK | msflags.SupportedEncTypeClaims
	req, err := tgsReq(emptyPrincipal, emptyPrincipal, kdcTestRealm, false, cfg, reqOptions)
	if err != nil {
		t.Fatal(err)
	}
	var claimsOnly TGSReqOptions
	claimsOnly.SupportedEncTypes = msflags.SupportedEncTypeClaims
	if ierr := req.addMSKILEPAData(cfg, claimsOnly); ierr != nil {
		t.Fatal(ierr)
	}
	assert.Equal(t, []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.RC4_HMAC, etypeID.AES128_CTS_HMAC_SHA1_96},
		req.ReqBody.EType)
	assert.Equal(t, original, cfg.LibDefaults.DefaultTGSEnctypeIDs)

	var options types.PAPACOptions
	for i := range req.PAData {
		if req.PAData[i].PADataType == patype.PA_PAC_OPTIONS {
			options, err = req.PAData[i].GetPAPACOptions()
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, types.IsFlagSet(&options.Options, flags.PACOptionBranchAware))
	assert.True(t, types.IsFlagSet(&options.Options, flags.PACOptionClaims))
}

func TestTGSReqForwardedOptions(t *testing.T) {
	var emptyPrincipal types.PrincipalName
	cfg := config.New()
	cfg.LibDefaults.Forwardable = false
	cfg.LibDefaults.NoAddresses = false
	yes := true
	addresses := types.HostAddresses{}
	var options TGSReqOptions
	options.Forwardable = &yes
	options.Forwarded = &yes
	options.Addresses = &addresses
	req, err := tgsReq(emptyPrincipal, emptyPrincipal, kdcTestRealm, false, cfg, options)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwardable))
	assert.True(t, types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwarded))
	assert.Empty(t, req.ReqBody.Addresses)
}

func TestTGSReqFalseOverridesAndHelpers(t *testing.T) {
	var emptyPrincipal types.PrincipalName
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	cfg.LibDefaults.Forwardable = true
	no := false
	var options TGSReqOptions
	options.Forwardable = &no
	options.Forwarded = &no
	req, err := tgsReq(emptyPrincipal, emptyPrincipal, kdcTestRealm, true, cfg, options)
	if err != nil {
		t.Fatal(err)
	}
	if types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwardable) ||
		types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Forwarded) {
		t.Fatal("false flag overrides were not honored")
	}
	if !types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renew) ||
		!types.IsFlagSet(&req.ReqBody.KDCOptions, flags.Renewable) {
		t.Fatal("renewal flags were not set")
	}

	checkTGSReqHelpers(t)
}

func checkTGSReqHelpers(t *testing.T) {
	t.Helper()
	for _, keyType := range []int32{etypeID.DES_CBC_CRC, etypeID.DES_CBC_MD4, etypeID.DES_CBC_MD5, etypeID.RC4_HMAC} {
		if supportsS4UX509(keyType) {
			t.Fatalf("legacy enctype %d supports S4U X509", keyType)
		}
	}
	if !supportsS4UX509(etypeID.AES128_CTS_HMAC_SHA1_96) {
		t.Fatal("AES enctype does not support S4U X509")
	}
	options := []int{flags.PACOptionClaims}
	if got := appendPACOption(options, flags.PACOptionClaims); len(got) != 1 {
		t.Fatalf("duplicate PAC option appended: %v", got)
	}
	if got := appendPACOption(options, flags.PACOptionBranchAware); len(got) != 2 {
		t.Fatalf("new PAC option not appended: %v", got)
	}
}

func TestSetPADataWithSubkeyRejectsUnsupportedEType(t *testing.T) {
	var defaultOptions TGSReqOptions
	var emptyPrincipal types.PrincipalName
	var emptyTicket Ticket
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	req, err := tgsReq(emptyPrincipal, emptyPrincipal, kdcTestRealm, false, cfg, defaultOptions)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := req.SetPADataWithSubkey(emptyTicket, types.EncryptionKey{KeyType: -1, KeyValue: nil}); err == nil {
		t.Fatal("unsupported session-key enctype accepted")
	}
}

func TestTGSRequestConvenienceConstructors(t *testing.T) {
	cfg := s4uTestConfig()
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	tgt := s4uTestTicket()
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}

	request, err := NewTGSReq(cname, kdcTestRealmCOM, cfg, tgt, key, sname, false)
	if err != nil {
		t.Fatal(err)
	}
	if !request.ReqBody.CName.Equal(cname) || !request.ReqBody.SName.Equal(sname) || len(request.PAData) == 0 {
		t.Fatalf("TGS request = %+v", request.ReqBody)
	}

	forwarded := true
	var options TGSReqOptions
	options.Forwarded = &forwarded
	request, err = NewTGSReqWithOptions(cname, kdcTestRealmCOM, cfg, tgt, key, sname, false, options)
	if err != nil || !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) {
		t.Fatalf("TGS options request = %+v, %v", request.ReqBody, err)
	}

	checkUser2UserTGSConstructors(t, cfg, cname, sname, tgt, key, options)
}

func checkUser2UserTGSConstructors(
	t *testing.T,
	cfg *config.Config,
	cname, sname types.PrincipalName,
	tgt Ticket,
	key types.EncryptionKey,
	options TGSReqOptions,
) {
	t.Helper()
	verifyingTGT := s4uTestTicket()
	verifyingTGT.SName = types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/OTHER.COM")
	request, err := NewUser2UserTGSReq(cname, kdcTestRealmCOM, cfg, tgt, key, sname, false, verifyingTGT)
	if err != nil {
		t.Fatal(err)
	}
	if !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.EncTktInSkey) || len(request.ReqBody.AdditionalTickets) != 1 ||
		!request.ReqBody.AdditionalTickets[0].SName.Equal(verifyingTGT.SName) {
		t.Fatalf("user-to-user request = %+v", request.ReqBody)
	}

	request, err = NewUser2UserTGSReqWithOptions(cname, kdcTestRealmCOM, cfg, tgt, key, sname, true, verifyingTGT, options)
	if err != nil || !request.Renewal || !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) {
		t.Fatalf("user-to-user options request = %+v, %v", request.ReqBody, err)
	}
}

func TestUnmarshalKDCReqBody(t *testing.T) {
	t.Parallel()
	var a KDCReqBody
	b, err := hex.DecodeString(testdata.MarshaledKRB5kdc_req_body)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.CName.NameType, "Request body CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.CName.NameString),
		"Request body CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.CName.NameString,
		"Request body CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString),
		"Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString,
		"Request body SName entries not as expected")
	assert.Equal(t, tt, a.From, "Request body From time not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, tt, a.RTime, "Request body RTime time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(a.Addresses), "Number of client addresses not as expected")
	for i, addr := range a.Addresses {
		assert.Equal(t, addrtype.IPv4, addr.AddrType,
			fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address),
			fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	assert.Equal(t, testdata.TEST_ETYPE, a.EncAuthData.EType,
		"Etype of request body encrypted authorization data not as expected")
	assert.Equal(t, iana.PVNO, a.EncAuthData.KVNO, "KVNO of request body encrypted authorization data not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), a.EncAuthData.Cipher,
		"Ciphertext of request body encrypted authorization data not as expected")
	assert.Equal(t, 2, len(a.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType,
			fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString),
			fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString,
			fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType,
			fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher,
			fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalKDCReqBody_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()
	var a KDCReqBody
	b, err := hex.DecodeString(testdata.MarshaledKRB5kdc_req_bodyOptionalsNULLexceptsecond_ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba98", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType,
			fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString),
			fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString,
			fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType,
			fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher,
			fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalKDCReqBody_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()
	var a KDCReqBody
	b, err := hex.DecodeString(testdata.MarshaledKRB5kdc_req_bodyOptionalsNULLexceptserver)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, "fedcba90", hex.EncodeToString(a.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.SName.NameString),
		"Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.SName.NameString,
		"Request body SName entries not as expected")
	assert.Equal(t, tt, a.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.EncAuthData.Cipher), "Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.AdditionalTickets), "Number of additional tickets not empty")
}

func TestUnmarshalASReq(t *testing.T) {
	t.Parallel()
	var a ASReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5as_req)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue,
			fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	checkFullKDCReqBody(t, a.ReqBody, tt)
}

func TestUnmarshalASReq_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()
	var a ASReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5as_reqOptionalsNULLexceptsecond_ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher),
		"Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType,
			fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString),
			fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString,
			fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType,
			fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher,
			fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalASReq_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()
	var a ASReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5as_reqOptionalsNULLexceptserver)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_AS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString),
		"Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString,
		"Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher),
		"Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not empty")
}

func TestUnmarshalTGSReq(t *testing.T) {
	t.Parallel()
	var a TGSReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_req)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 2, len(a.PAData), "Number of PAData items in the sequence not as expected")
	for i, pa := range a.PAData {
		assert.Equal(t, patype.PA_SAM_RESPONSE, pa.PADataType, fmt.Sprintf("PAData type for entry %d not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_PADATA_VALUE), pa.PADataValue,
			fmt.Sprintf("PAData valye for entry %d not as expected", i+1))
	}
	checkFullKDCReqBody(t, a.ReqBody, tt)
}

func TestUnmarshalTGSReq_optionalsNULLexceptsecond_ticket(t *testing.T) {
	t.Parallel()
	var a TGSReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_reqOptionalsNULLexceptsecond_ticket)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba98", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher),
		"Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 2, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not as expected")
	for i, tkt := range a.ReqBody.AdditionalTickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType,
			fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString),
			fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString,
			fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType,
			fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher,
			fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func TestUnmarshalTGSReq_optionalsNULLexceptserver(t *testing.T) {
	t.Parallel()
	var a TGSReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_reqOptionalsNULLexceptserver)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Parse the test time value into a time.Time type
	tt, _ := time.Parse(testdata.TEST_TIME_FORMAT, testdata.TEST_TIME)

	assert.Equal(t, iana.PVNO, a.PVNO, "PVNO not as expected")
	assert.Equal(t, msgtype.KRB_TGS_REQ, a.MsgType, "Message ID not as expected")
	assert.Equal(t, 0, len(a.PAData), "Number of PAData items in the sequence not as expected")
	assert.Equal(t, "fedcba90", hex.EncodeToString(a.ReqBody.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, testdata.TEST_REALM, a.ReqBody.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, a.ReqBody.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(a.ReqBody.SName.NameString),
		"Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, a.ReqBody.SName.NameString,
		"Request body SName entries not as expected")
	assert.Equal(t, tt, a.ReqBody.Till, "Request body Till time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, a.ReqBody.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, a.ReqBody.EType, "Etype list not as expected")
	assert.Equal(t, 0, len(a.ReqBody.Addresses), "Number of client addresses not empty")
	assert.Equal(t, 0, len(a.ReqBody.EncAuthData.Cipher),
		"Ciphertext of request body encrypted authorization data not empty")
	assert.Equal(t, 0, len(a.ReqBody.AdditionalTickets), "Number of additional tickets not empty")
}

//// Marshal Tests ////

func TestMarshalKDCReqBody(t *testing.T) {
	t.Parallel()
	var a KDCReqBody
	b, err := hex.DecodeString(testdata.MarshaledKRB5kdc_req_body)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	err = a.Unmarshal(b)
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	// Marshal and re-unmarshal the result nd then compare
	mb, err := a.Marshal()
	if err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	assert.Equal(t, b, mb, "Marshal bytes of KDCReqBody not as expected")
}

func TestMarshalASReq(t *testing.T) {
	t.Parallel()
	var a ASReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5as_req)
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
	assert.Equal(t, b, mb, "Marshal bytes of ASReq not as expected")
}

func TestMarshalTGSReq(t *testing.T) {
	t.Parallel()
	var a TGSReq
	b, err := hex.DecodeString(testdata.MarshaledKRB5tgs_req)
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
	assert.Equal(t, b, mb, "Marshal bytes of TGSReq not as expected")
}

func checkFullKDCReqBody(t *testing.T, body KDCReqBody, tt time.Time) {
	t.Helper()
	assert.Equal(t, "fedcba90", hex.EncodeToString(body.KDCOptions.Bytes), "Request body flags not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, body.CName.NameType, "Request body CName NameType not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(body.CName.NameString),
		"Request body CName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, body.CName.NameString,
		"Request body CName entries not as expected")
	assert.Equal(t, testdata.TEST_REALM, body.Realm, "Request body Realm not as expected")
	assert.Equal(t, nametype.KRB_NT_PRINCIPAL, body.SName.NameType, "Request body SName nametype not as expected")
	assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(body.SName.NameString),
		"Request body SName does not have the expected number of NameStrings")
	assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, body.SName.NameString,
		"Request body SName entries not as expected")
	assert.Equal(t, tt, body.From, "Request body From time not as expected")
	assert.Equal(t, tt, body.Till, "Request body Till time not as expected")
	assert.Equal(t, tt, body.RTime, "Request body RTime time not as expected")
	assert.Equal(t, testdata.TEST_NONCE, body.Nonce, "Request body nounce not as expected")
	assert.Equal(t, []int32{0, 1}, body.EType, "Etype list not as expected")
	assert.Equal(t, 2, len(body.Addresses), "Number of client addresses not as expected")
	for i, addr := range body.Addresses {
		assert.Equal(t, addrtype.IPv4, addr.AddrType,
			fmt.Sprintf("Host address type not as expected for address item %d", i+1))
		assert.Equal(t, "12d00023", hex.EncodeToString(addr.Address),
			fmt.Sprintf("Host address not as expected for address item %d", i+1))
	}
	assert.Equal(t, testdata.TEST_ETYPE, body.EncAuthData.EType,
		"Etype of request body encrypted authorization data not as expected")
	assert.Equal(t, iana.PVNO, body.EncAuthData.KVNO, "KVNO of request body encrypted authorization data not as expected")
	assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), body.EncAuthData.Cipher,
		"Ciphertext of request body encrypted authorization data not as expected")
	checkKDCReqAdditionalTickets(t, body.AdditionalTickets)
}

func checkKDCReqAdditionalTickets(t *testing.T, tickets []Ticket) {
	t.Helper()
	assert.Equal(t, 2, len(tickets), "Number of additional tickets not as expected")
	for i, tkt := range tickets {
		assert.Equal(t, iana.PVNO, tkt.TktVNO, fmt.Sprintf("Additional ticket (%v) ticket-vno not as expected", i+1))
		assert.Equal(t, testdata.TEST_REALM, tkt.Realm, fmt.Sprintf("Additional ticket (%v) realm not as expected", i+1))
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, tkt.SName.NameType,
			fmt.Sprintf("Additional ticket (%v) SName NameType not as expected", i+1))
		assert.Equal(t, len(testdata.TEST_PRINCIPALNAME_NAMESTRING), len(tkt.SName.NameString),
			fmt.Sprintf("Additional ticket (%v) SName does not have the expected number of NameStrings", i+1))
		assert.Equal(t, testdata.TEST_PRINCIPALNAME_NAMESTRING, tkt.SName.NameString,
			fmt.Sprintf("Additional ticket (%v) SName name string entries not as expected", i+1))
		assert.Equal(t, testdata.TEST_ETYPE, tkt.EncPart.EType,
			fmt.Sprintf("Additional ticket (%v) encPart etype not as expected", i+1))
		assert.Equal(t, iana.PVNO, tkt.EncPart.KVNO, fmt.Sprintf("Additional ticket (%v) encPart KVNO not as expected", i+1))
		assert.Equal(t, []byte(testdata.TEST_CIPHERTEXT), tkt.EncPart.Cipher,
			fmt.Sprintf("Additional ticket (%v) encPart cipher not as expected", i+1))
	}
}

func checkKDCRequestEnctypeOffers(t *testing.T, body string, want []int32) {
	t.Helper()
	cfg, err := config.NewFromString("[libdefaults]\n" + body)
	if err != nil {
		t.Fatal(err)
	}
	cname := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	as, err := NewASReqForTGT(kdcTestRealmCOM, cfg, cname)
	if err != nil {
		t.Fatal(err)
	}
	sname := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	tgs, err := NewTGSReq(
		cname,
		kdcTestRealmCOM,
		cfg,
		s4uTestTicket(),
		key,
		sname,
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	asDER, err := as.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	tgsDER, err := tgs.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	var decodedAS ASReq
	if err := decodedAS.Unmarshal(asDER); err != nil {
		t.Fatal(err)
	}
	var decodedTGS TGSReq
	if err := decodedTGS.Unmarshal(tgsDER); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, want, decodedAS.ReqBody.EType, "AS-REQ enctype offer")
	assert.Equal(t, want, decodedTGS.ReqBody.EType, "TGS-REQ enctype offer")
}
