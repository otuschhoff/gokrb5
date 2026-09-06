package client

import (
	"errors"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/msgtype"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestS4U2SelfFallbackAndReferralPreservePAForUser(t *testing.T) {
	cfg := s4uClientTestConfig()
	cl := NewWithPassword("HTTP/service.example.com", "SERVICE.EXAMPLE", "unused", cfg)
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/service.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	initialKey := s4uTestKey(1)
	referralKey := s4uTestKey(2)
	calls := 0
	cl.sendToKDCFunc = func(requestBytes []byte, realm string) ([]byte, error) {
		calls++
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if !request.PAData.Contains(patype.PA_FOR_USER) {
			t.Fatal("S4U request omitted PA-FOR-USER")
		}
		switch calls {
		case 1:
			if !request.PAData.Contains(patype.PA_S4U_X509_USER) {
				t.Fatal("first S4U request omitted PA-S4U-X509-USER")
			}
			return nil, messages.NewKRBError(types.PrincipalName{}, realm, errorcode.KDC_ERR_PADATA_TYPE_NOSUPP, "unsupported")
		case 2:
			if request.PAData.Contains(patype.PA_S4U_X509_USER) {
				t.Fatal("fallback request retained PA-S4U-X509-USER")
			}
			return marshalS4UTGSReply(t, request, initialKey, referralKey, cl.Credentials.CName(), cl.Credentials.Realm(), types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/SERVICE.EXAMPLE")), nil
		case 3:
			if realm != "SERVICE.EXAMPLE" {
				t.Fatalf("referral request realm = %q, want SERVICE.EXAMPLE", realm)
			}
			if request.PAData.Contains(patype.PA_S4U_X509_USER) || !request.PAData.Contains(patype.PA_FOR_USER) {
				t.Fatal("referral request did not preserve PA-FOR-USER-only fallback")
			}
			return marshalS4UTGSReply(t, request, referralKey, s4uTestKey(3), user, "USER.EXAMPLE", service), nil
		default:
			t.Fatalf("unexpected request %d", calls)
			return nil, nil
		}
	}

	reply, err := cl.s4u2SelfExchange(service, user, "USER.EXAMPLE", "USER.EXAMPLE", s4uTestTicket("USER.EXAMPLE", "krbtgt/USER.EXAMPLE"), initialKey, s4uOptions{})
	if err != nil {
		t.Fatalf("s4u2SelfExchange() error = %v", err)
	}
	if calls != 3 || !reply.CName.Equal(user) {
		t.Errorf("exchange calls = %d, cname = %v; want 3 and %v", calls, reply.CName, user)
	}
}

func TestS4U2SelfDoesNotSilentlyDowngrade(t *testing.T) {
	cfg := s4uClientTestConfig()
	cl := NewWithPassword("HTTP/service.example.com", "EXAMPLE.COM", "unused", cfg)
	service := cl.Credentials.CName()
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	key := s4uTestKey(1)
	cl.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		return marshalS4UTGSReply(t, request, key, s4uTestKey(2), user, "EXAMPLE.COM", service), nil
	}
	_, err := cl.s4u2SelfExchange(service, user, "EXAMPLE.COM", "EXAMPLE.COM", s4uTestTicket("EXAMPLE.COM", "krbtgt/EXAMPLE.COM"), key, s4uOptions{})
	if err == nil {
		t.Fatal("s4u2SelfExchange() accepted a reply that silently omitted PA-S4U-X509-USER")
	}
}

func TestS4U2ProxyReferralPreservesOptionsAndUsesReferralEvidence(t *testing.T) {
	cfg := s4uClientTestConfig()
	cl := NewWithPassword("HTTP/service.example.com", "SERVICE.EXAMPLE", "unused", cfg)
	target := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/target.example.com")
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	initialKey := s4uTestKey(1)
	referralKey := s4uTestKey(2)
	evidence := s4uTestTicket("SERVICE.EXAMPLE", "HTTP/service.example.com")
	var referralTicket messages.Ticket
	calls := 0
	cl.sendToKDCFunc = func(requestBytes []byte, realm string) ([]byte, error) {
		calls++
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.CNameInAddlTkt) || len(request.ReqBody.AdditionalTickets) != 1 {
			t.Fatal("S4U2proxy request omitted cname-in-addl-tkt or evidence")
		}
		pacOptions, err := findClientPAData(request.PAData, patype.PA_PAC_OPTIONS).GetPAPACOptions()
		if err != nil || !types.IsFlagSet(&pacOptions.Options, flags.PACOptionResourceBasedConstrainedDelegation) {
			t.Fatal("S4U2proxy request omitted RBCD PAC option")
		}
		switch calls {
		case 1:
			if !ticketsEqual(request.ReqBody.AdditionalTickets[0], evidence) {
				t.Fatal("first S4U2proxy request did not use original evidence")
			}
			referralTicket = s4uTestTicket(realm, "krbtgt/TARGET.EXAMPLE")
			return marshalS4UTGSReply(t, request, initialKey, referralKey, cl.Credentials.CName(), cl.Credentials.Realm(), referralTicket.SName), nil
		case 2:
			if realm != "TARGET.EXAMPLE" || !ticketsEqual(request.ReqBody.AdditionalTickets[0], referralTicket) {
				t.Fatal("referral S4U2proxy request did not use the user referral ticket")
			}
			return marshalS4UTGSReply(t, request, referralKey, s4uTestKey(3), user, "USER.EXAMPLE", target), nil
		default:
			t.Fatalf("unexpected request %d", calls)
			return nil, nil
		}
	}

	reply, err := cl.s4u2ProxyExchange(target, "SERVICE.EXAMPLE", s4uTestTicket("SERVICE.EXAMPLE", "krbtgt/SERVICE.EXAMPLE"), initialKey, evidence, s4uOptions{resourceBased: true})
	if err != nil {
		t.Fatalf("s4u2ProxyExchange() error = %v", err)
	}
	if calls != 2 || !reply.CName.Equal(user) {
		t.Errorf("exchange calls = %d, cname = %v; want 2 and %v", calls, reply.CName, user)
	}
}

func TestS4UCacheIsSeparateByUserAndSPN(t *testing.T) {
	cl := NewWithPassword("service", "EXAMPLE.COM", "unused", config.New())
	now := time.Now().UTC()
	spn := "HTTP/target.example.com"
	normalTicket := s4uTestTicket("EXAMPLE.COM", spn)
	normalKey := s4uTestKey(1)
	cl.cache.addEntry(normalTicket, now.Add(-time.Minute), now.Add(-time.Minute), now.Add(time.Hour), time.Time{}, normalKey)

	alice := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	s4uTicket := s4uTestTicket("EXAMPLE.COM", spn)
	s4uTicket.EncPart.Cipher = []byte("alice-ticket")
	s4uKey := s4uTestKey(2)
	ticketFlags := types.NewKrbFlags()
	types.SetFlag(&ticketFlags, flags.Forwardable)
	cl.addS4UCacheEntry(alice, "EXAMPLE.COM", spn, messages.TGSRep{KDCRepFields: messages.KDCRepFields{
		Ticket:           s4uTicket,
		DecryptedEncPart: messages.EncKDCRepPart{StartTime: now.Add(-time.Minute), EndTime: now.Add(time.Hour), Key: s4uKey, Flags: ticketFlags},
	}})

	gotNormal, gotNormalKey, ok := cl.GetCachedTicket(spn)
	if !ok || string(gotNormal.EncPart.Cipher) == string(s4uTicket.EncPart.Cipher) || string(gotNormalKey.KeyValue) != string(normalKey.KeyValue) {
		t.Fatal("normal cache entry was replaced by S4U entry")
	}
	gotS4U, gotS4UKey, ok := cl.GetCachedServiceTicketForUser(alice, "example.com", spn)
	if !ok || string(gotS4U.EncPart.Cipher) != "alice-ticket" || string(gotS4UKey.KeyValue) != string(s4uKey.KeyValue) {
		t.Fatal("S4U cache entry was not returned for alice")
	}
	if info, ok := cl.GetCachedServiceTicketForUserInfo(alice, "EXAMPLE.COM", spn); !ok || !info.Forwardable {
		t.Fatal("S4U cache did not expose the forwardable ticket flag")
	}
	bob := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob")
	if _, _, ok := cl.GetCachedServiceTicketForUser(bob, "EXAMPLE.COM", spn); ok {
		t.Fatal("alice's S4U ticket was returned for bob")
	}
}

func TestClassifyS4UErrorPreservesNTStatus(t *testing.T) {
	extended, err := types.NewKerbExtErrorData(types.KerbExtError{Status: ntstatus.STATUS_NO_MATCH})
	if err != nil {
		t.Fatal(err)
	}
	eData, err := extended.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	kdcError := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.COM", errorcode.KDC_ERR_BADOPTION, "denied")
	kdcError.EData = eData
	classified := classifyS4UError(kdcError, true)
	if !errors.Is(classified, krberror.ErrDelegationNotPermitted) {
		t.Fatalf("error = %v, want ErrDelegationNotPermitted", classified)
	}
	var statusProvider interface {
		NTStatus() (ntstatus.Code, bool)
	}
	if !errors.As(classified, &statusProvider) {
		t.Fatal("classified error does not expose NTSTATUS")
	}
	status, ok := statusProvider.NTStatus()
	if !ok || status != ntstatus.STATUS_NO_MATCH {
		t.Fatalf("NTSTATUS = %v, %v; want STATUS_NO_MATCH", status, ok)
	}
	policyError := messages.NewKRBError(types.PrincipalName{}, "EXAMPLE.COM", errorcode.KDC_ERR_POLICY, "denied")
	if got := classifyS4UError(policyError, true); !errors.Is(got, krberror.ErrDelegationNotPermitted) {
		t.Fatalf("KDC_ERR_POLICY classification = %v, want ErrDelegationNotPermitted", got)
	}
}

func s4uClientTestConfig() *config.Config {
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	return cfg
}

func s4uTestKey(seed byte) types.EncryptionKey {
	return types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte{seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed}}
}

func s4uTestTicket(realm, spn string) messages.Ticket {
	return messages.Ticket{
		TktVNO: iana.PVNO,
		Realm:  realm,
		SName:  types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn),
		EncPart: types.EncryptedData{
			EType:  etypeID.AES128_CTS_HMAC_SHA1_96,
			Cipher: []byte("ticket:" + realm + ":" + spn),
		},
	}
}

func marshalS4UTGSReply(t *testing.T, request messages.TGSReq, encryptionKey, replyKey types.EncryptionKey, cname types.PrincipalName, crealm string, ticketSName types.PrincipalName) []byte {
	t.Helper()
	now := time.Now().UTC()
	part := messages.EncKDCRepPart{
		Key:       replyKey,
		Nonce:     request.ReqBody.Nonce,
		Flags:     types.NewKrbFlags(),
		AuthTime:  now,
		StartTime: now,
		EndTime:   now.Add(time.Hour),
		SRealm:    request.ReqBody.Realm,
		SName:     request.ReqBody.SName,
	}
	plain, err := part.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	encrypted, err := crypto.GetEncryptedData(plain, encryptionKey, keyusage.TGS_REP_ENCPART_SESSION_KEY, 0)
	if err != nil {
		t.Fatal(err)
	}
	reply := messages.TGSRep{KDCRepFields: messages.KDCRepFields{
		PVNO:    iana.PVNO,
		MsgType: msgtype.KRB_TGS_REP,
		CRealm:  crealm,
		CName:   cname,
		Ticket:  s4uTestTicket(request.ReqBody.Realm, ticketSName.PrincipalNameString()),
		EncPart: encrypted,
	}}
	b, err := reply.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func findClientPAData(paData types.PADataSequence, paType int32) *types.PAData {
	for i := range paData {
		if paData[i].PADataType == paType {
			return &paData[i]
		}
	}
	return &types.PAData{}
}
