package client

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

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
	var defaultOptions s4uOptions

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
		require.NoError(t, request.Unmarshal(requestBytes))
		require.True(t, request.PAData.Contains(patype.PA_FOR_USER), "S4U request omitted PA-FOR-USER")
		switch calls {
		case 1:
			require.True(t, request.PAData.Contains(patype.PA_S4U_X509_USER), "first request omitted PA-S4U-X509-USER")
			return nil, s4uUnsupportedPAError(realm)
		case 2:
			require.False(t, request.PAData.Contains(patype.PA_S4U_X509_USER), "fallback retained PA-S4U-X509-USER")
			return marshalS4UTGSReply(
				t,
				request,
				initialKey,
				referralKey,
				cl.Credentials.CName(),
				cl.Credentials.Realm(),
				types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/SERVICE.EXAMPLE"),
			), nil
		case 3:
			require.Equal(t, "SERVICE.EXAMPLE", realm, "referral request realm")
			if request.PAData.Contains(patype.PA_S4U_X509_USER) || !request.PAData.Contains(patype.PA_FOR_USER) {
				t.Fatal("referral request did not preserve PA-FOR-USER-only fallback")
			}
			return marshalS4UTGSReply(t, request, referralKey, s4uTestKey(3), user, "USER.EXAMPLE", service), nil
		default:
			t.Fatalf("unexpected request %d", calls)
			return nil, nil
		}
	}

	reply, err := cl.s4u2SelfExchange(
		service,
		user,
		"USER.EXAMPLE",
		"USER.EXAMPLE",
		s4uTestTicket("USER.EXAMPLE", "krbtgt/USER.EXAMPLE"),
		initialKey,
		defaultOptions,
	)
	if err != nil {
		t.Fatalf("s4u2SelfExchange() error = %v", err)
	}
	if calls != 3 || !reply.CName.Equal(user) {
		t.Errorf("exchange calls = %d, cname = %v; want 3 and %v", calls, reply.CName, user)
	}
}

func TestS4U2SelfDoesNotSilentlyDowngrade(t *testing.T) {
	var defaultOptions s4uOptions

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
	_, err := cl.s4u2SelfExchange(
		service,
		user,
		"EXAMPLE.COM",
		"EXAMPLE.COM",
		s4uTestTicket("EXAMPLE.COM", "krbtgt/EXAMPLE.COM"),
		key,
		defaultOptions,
	)
	if err == nil {
		t.Fatal("s4u2SelfExchange() accepted a reply that silently omitted PA-S4U-X509-USER")
	}
}

func TestS4U2SelfRetriesPAForUserForForwardableEvidence(t *testing.T) {
	cfg := s4uClientTestConfig()
	cl := NewWithPassword("HTTP/service.example.com", "EXAMPLE.COM", "unused", cfg)
	service := cl.Credentials.CName()
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	key := s4uTestKey(1)
	calls := 0
	cl.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		calls++
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if calls == 1 {
			if !request.PAData.Contains(patype.PA_S4U_X509_USER) {
				t.Fatal("first S4U request omitted PA-S4U-X509-USER")
			}
			return marshalS4UTGSReply(t, request, key, s4uTestKey(2), user, "EXAMPLE.COM", service), nil
		}
		if request.PAData.Contains(patype.PA_S4U_X509_USER) {
			t.Fatal("retry retained PA-S4U-X509-USER")
		}
		return marshalS4UTGSReply(t, request, key, s4uTestKey(3), user, "EXAMPLE.COM", service, flags.Forwardable), nil
	}

	forwardable := true
	reply, err := cl.s4u2SelfExchange(
		service,
		user,
		"EXAMPLE.COM",
		"EXAMPLE.COM",
		s4uTestTicket("EXAMPLE.COM", "krbtgt/EXAMPLE.COM"),
		key,
		s4uOptions{resourceBased: false, subjectCertificate: nil, forwardable: &forwardable},
	)
	if err != nil {
		t.Fatalf("s4u2SelfExchange() error = %v", err)
	}
	if calls != 2 || !types.IsFlagSet(&reply.DecryptedEncPart.Flags, flags.Forwardable) {
		t.Fatalf(
			"exchange calls = %d, forwardable = %t; want 2 and true",
			calls,
			types.IsFlagSet(&reply.DecryptedEncPart.Flags, flags.Forwardable),
		)
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
		require.NoError(t, request.Unmarshal(requestBytes))
		checkS4UProxyRequestOptions(t, &request)
		switch calls {
		case 1:
			if !ticketsEqual(request.ReqBody.AdditionalTickets[0], evidence) {
				t.Fatal("first S4U2proxy request did not use original evidence")
			}
			referralTicket = s4uTestTicket(realm, "krbtgt/TARGET.EXAMPLE")
			return marshalS4UTGSReply(
				t,
				request,
				initialKey,
				referralKey,
				cl.Credentials.CName(),
				cl.Credentials.Realm(),
				referralTicket.SName,
			), nil
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

	reply, err := cl.s4u2ProxyExchange(
		target,
		"SERVICE.EXAMPLE",
		s4uTestTicket("SERVICE.EXAMPLE", "krbtgt/SERVICE.EXAMPLE"),
		initialKey,
		evidence,
		s4uOptions{forwardable: nil, subjectCertificate: nil, resourceBased: true},
	)
	if err != nil {
		t.Fatalf("s4u2ProxyExchange() error = %v", err)
	}
	if calls != 2 || !reply.CName.Equal(user) {
		t.Errorf("exchange calls = %d, cname = %v; want 2 and %v", calls, reply.CName, user)
	}
}

func checkS4UProxyRequestOptions(t *testing.T, request *messages.TGSReq) {
	t.Helper()
	require.True(t, types.IsFlagSet(&request.ReqBody.KDCOptions, flags.CNameInAddlTkt), "missing cname-in-addl-tkt")
	require.Len(t, request.ReqBody.AdditionalTickets, 1, "missing or extra evidence tickets")
	pacOptions, err := findClientPAData(request.PAData, patype.PA_PAC_OPTIONS).GetPAPACOptions()
	require.NoError(t, err, "decode S4U2proxy PAC options")
	require.True(t, types.IsFlagSet(&pacOptions.Options, flags.PACOptionResourceBasedConstrainedDelegation),
		"S4U2proxy request omitted RBCD PAC option")
}

func installS4UTestSession(client *Client, tgt messages.Ticket, tgtKey types.EncryptionKey) {
	var (
		emptyFlags     asn1.BitString
		emptyPrincipal types.PrincipalName
	)

	now := time.Now().UTC()
	client.addSession(tgt, messages.EncKDCRepPart{
		LastReqs:      nil,
		Nonce:         0,
		KeyExpiration: time.Time{},
		Flags:         emptyFlags,
		SRealm:        "",
		SName:         emptyPrincipal,
		CAddr:         nil,
		EncPAData:     nil,
		Key:           tgtKey, AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), RenewTill: now.Add(2 * time.Hour),
	})
}

func TestPublicS4UServiceTicketRoundTripsAndCaches(t *testing.T) {
	client, _, tgt, tgtKey := newCoverageTGSRequest(t)
	installS4UTestSession(client, tgt, tgtKey)
	user := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "bob")
	selfSPN := "HTTP/self.example.org"
	targetSPN := "HTTP/target.example.org"
	selfKey := s4uTestKey(4)
	proxyKey := s4uTestKey(5)
	calls := 0
	client.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		calls++
		var request messages.TGSReq
		require.NoError(t, request.Unmarshal(requestBytes))
		if len(request.ReqBody.AdditionalTickets) == 0 {
			if request.PAData.Contains(patype.PA_S4U_X509_USER) {
				return nil, s4uUnsupportedPAError(request.ReqBody.Realm)
			}
			return marshalS4UTGSReply(
				t,
				request,
				tgtKey,
				selfKey,
				user,
				exchangeFixtureRealm,
				types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, selfSPN),
				flags.Forwardable,
			), nil
		}
		return marshalS4UTGSReply(
			t,
			request,
			tgtKey,
			proxyKey,
			user,
			exchangeFixtureRealm,
			types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, targetSPN),
		), nil
	}

	evidence, gotSelfKey, err := client.GetServiceTicketForUser(user, "", selfSPN, S4UWithForwardable(true))
	require.NoError(t, err)
	if string(gotSelfKey.KeyValue) != string(selfKey.KeyValue) {
		t.Fatalf("S4U2self key = %x", gotSelfKey.KeyValue)
	}
	if _, _, ierr := client.GetServiceTicketForUser(user, exchangeFixtureRealm, selfSPN); ierr != nil || calls != 2 {
		t.Fatalf("cached S4U2self = calls %d, error %v", calls, ierr)
	}

	ticket, gotProxyKey, err := client.GetServiceTicketOnBehalfOf(evidence, targetSPN, S4UWithResourceBasedDelegation())
	require.NoError(t, err)
	if ticket.SName.PrincipalNameString() != targetSPN || string(gotProxyKey.KeyValue) != string(proxyKey.KeyValue) {
		t.Fatalf("S4U2proxy ticket/key = %s/%x", ticket.SName.PrincipalNameString(), gotProxyKey.KeyValue)
	}
	if _, _, err := client.GetServiceTicketOnBehalfOf(evidence, targetSPN); err != nil || calls != 3 {
		t.Fatalf("cached S4U2proxy = calls %d, error %v", calls, err)
	}
}

func s4uUnsupportedPAError(realm string) messages.KRBError {
	var emptyPrincipal types.PrincipalName
	return messages.NewKRBError(emptyPrincipal, realm, errorcode.KDC_ERR_PADATA_TYPE_NOSUPP, "unsupported")
}

func TestS4UCacheIsSeparateByUserAndSPN(t *testing.T) {
	cl := NewWithPassword("service", "EXAMPLE.COM", "unused", config.New())
	now := time.Now().UTC()
	spn := "HTTP/target.example.com"
	normalTicket := s4uTestTicket("EXAMPLE.COM", spn)
	normalKey := s4uTestKey(1)
	cl.cache.addEntry(
		normalTicket,
		now.Add(-time.Minute),
		now.Add(-time.Minute),
		now.Add(time.Hour),
		time.Time{},
		normalKey,
	)

	alice := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice")
	s4uTicket := s4uTestTicket("EXAMPLE.COM", spn)
	s4uTicket.EncPart.Cipher = []byte("alice-ticket")
	s4uKey := s4uTestKey(2)
	ticketFlags := types.NewKrbFlags()
	types.SetFlag(&ticketFlags, flags.Forwardable)
	var reply messages.TGSRep
	reply.Ticket = s4uTicket
	reply.DecryptedEncPart.StartTime = now.Add(-time.Minute)
	reply.DecryptedEncPart.EndTime = now.Add(time.Hour)
	reply.DecryptedEncPart.Key = s4uKey
	reply.DecryptedEncPart.Flags = ticketFlags
	cl.addS4UCacheEntry(alice, "EXAMPLE.COM", spn, reply)

	gotNormal, gotNormalKey, ok := cl.GetCachedTicket(spn)
	if !ok || string(gotNormal.EncPart.Cipher) == string(
		s4uTicket.EncPart.Cipher,
	) || string(gotNormalKey.KeyValue) != string(normalKey.KeyValue) {
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
	var emptyPrincipal types.PrincipalName

	extended, err := types.NewKerbExtErrorData(types.KerbExtError{Reserved: 0, Flags: 0, Status: ntstatus.STATUS_NO_MATCH})
	if err != nil {
		t.Fatal(err)
	}
	eData, err := extended.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	kdcError := messages.NewKRBError(emptyPrincipal, "EXAMPLE.COM", errorcode.KDC_ERR_BADOPTION, "denied")
	kdcError.EData = eData
	cause := fmt.Errorf("kdc reply: %w", kdcError)
	for _, tt := range []struct {
		name  string
		proxy bool
		kind  error
	}{
		{name: "delegation", proxy: true, kind: krberror.ErrDelegationNotPermitted},
		{name: "protocol transition", proxy: false, kind: krberror.ErrProtocolTransitionNotPermitted},
	} {
		t.Run(tt.name, func(t *testing.T) {
			classified := classifyS4UError(cause, tt.proxy)
			require.ErrorIs(t, classified, tt.kind)
			require.ErrorIs(t, classified, cause)
			require.IsType(t, krberror.PolicyError{Kind: tt.kind, Cause: cause}, classified)
			var policy krberror.PolicyError
			require.ErrorAs(t, classified, &policy)
			status, ok := policy.NTStatus()
			require.True(t, ok)
			require.Equal(t, ntstatus.STATUS_NO_MATCH, status)
		})
	}
	policyError := messages.NewKRBError(emptyPrincipal, "EXAMPLE.COM", errorcode.KDC_ERR_POLICY, "denied")
	if got := classifyS4UError(policyError, true); !errors.Is(got, krberror.ErrDelegationNotPermitted) {
		t.Fatalf("KDC_ERR_POLICY classification = %v, want ErrDelegationNotPermitted", got)
	}
}

func TestS4UExchangeRetainsDecodeError(t *testing.T) {
	client, request, _, key := newCoverageTGSRequest(t)
	client.sendToKDCFunc = func([]byte, string) ([]byte, error) {
		return []byte{0x6d, 0x01}, nil
	}
	reply, err := client.exchangeS4URequest(request, request.ReqBody.Realm, key)
	require.ErrorContains(t, err, "decode S4U TGS-REP")
	var structural asn1.StructuralError
	require.ErrorAs(t, err, &structural)
	require.Zero(t, reply)
}

func TestS4UExchangeRetainsVerificationError(t *testing.T) {
	client, request, _, key := newCoverageTGSRequest(t)
	client.sendToKDCFunc = func(requestBytes []byte, realm string) ([]byte, error) {
		var decoded messages.TGSReq
		require.NoError(t, decoded.Unmarshal(requestBytes))
		decoded.ReqBody.Nonce ^= 1
		return marshalS4UTGSReply(t, decoded, key, key, decoded.ReqBody.CName, realm, decoded.ReqBody.SName), nil
	}
	reply, err := client.exchangeS4URequest(request, request.ReqBody.Realm, key)
	require.ErrorContains(t, err, "verify S4U TGS-REP")
	require.ErrorContains(t, err, "nonce in response does not match")
	var classified krberror.Krberror
	require.ErrorAs(t, err, &classified)
	require.Equal(t, krberror.KRBMsgError, classified.RootCause)
	require.NotEqual(t, request.ReqBody.Nonce, reply.DecryptedEncPart.Nonce)
}

func s4uClientTestConfig() *config.Config {
	cfg := config.New()
	cfg.LibDefaults.NoAddresses = true
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	return cfg
}

func s4uTestKey(seed byte) types.EncryptionKey {
	return types.EncryptionKey{
		KeyType:  etypeID.AES128_CTS_HMAC_SHA1_96,
		KeyValue: []byte{seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed, seed},
	}
}

func s4uTestTicket(realm, spn string) messages.Ticket {
	var emptyTicketPart messages.EncTicketPart

	return messages.Ticket{
		DecryptedEncPart: emptyTicketPart,
		TktVNO:           iana.PVNO,
		Realm:            realm,
		SName:            types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, spn),
		EncPart: types.EncryptedData{
			KVNO:   0,
			EType:  etypeID.AES128_CTS_HMAC_SHA1_96,
			Cipher: []byte("ticket:" + realm + ":" + spn),
		},
	}
}

func marshalS4UTGSReply(
	t *testing.T,
	request messages.TGSReq,
	encryptionKey, replyKey types.EncryptionKey,
	cname types.PrincipalName,
	crealm string,
	ticketSName types.PrincipalName,
	replyFlags ...int,
) []byte {
	t.Helper()
	var emptyReplyPart messages.EncKDCRepPart

	now := time.Now().UTC()
	flagsValue := types.NewKrbFlags()
	for _, flag := range replyFlags {
		types.SetFlag(&flagsValue, flag)
	}
	part := messages.EncKDCRepPart{
		LastReqs:      nil,
		KeyExpiration: time.Time{},
		RenewTill:     time.Time{},
		CAddr:         nil,
		EncPAData:     nil,
		Key:           replyKey,
		Nonce:         request.ReqBody.Nonce,
		Flags:         flagsValue,
		AuthTime:      now,
		StartTime:     now,
		EndTime:       now.Add(time.Hour),
		SRealm:        request.ReqBody.Realm,
		SName:         request.ReqBody.SName,
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
		PAData:           nil,
		DecryptedEncPart: emptyReplyPart,
		PVNO:             iana.PVNO,
		MsgType:          msgtype.KRB_TGS_REP,
		CRealm:           crealm,
		CName:            cname,
		Ticket:           s4uTestTicket(request.ReqBody.Realm, ticketSName.PrincipalNameString()),
		EncPart:          encrypted,
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
	return new(types.PAData)
}
