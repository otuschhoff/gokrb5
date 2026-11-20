package client

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/addrtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func newCoverageTGSRequest(t *testing.T) (*Client, messages.TGSReq, messages.Ticket, types.EncryptionKey) {
	t.Helper()
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	client := NewWithPassword("alice", exchangeFixtureRealm, "password", cfg)
	tgt := s4uTestTicket(exchangeFixtureRealm, "krbtgt/EXAMPLE.ORG")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	request, err := messages.NewTGSReq(client.Credentials.CName(), exchangeFixtureRealm, cfg, tgt, key,
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/server.example.org"), false)
	if err != nil {
		t.Fatal(err)
	}
	return client, request, tgt, key
}

func TestTGSExchangeTopLevelFailures(t *testing.T) {
	tests := []struct {
		name string
		send func(messages.TGSReq) func([]byte, string) ([]byte, error)
		want string
	}{
		{"transport", func(messages.TGSReq) func([]byte, string) ([]byte, error) {
			return func([]byte, string) ([]byte, error) { return nil, errors.New("offline") }
		}, "issue sending"},
		{"KDC error", func(request messages.TGSReq) func([]byte, string) ([]byte, error) {
			return func([]byte, string) ([]byte, error) {
				return nil, messages.NewKRBError(
					request.ReqBody.CName,
					request.ReqBody.Realm,
					errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN,
					"missing",
				)
			}
		}, "kerberos error response"},
		{"malformed reply", func(messages.TGSReq) func([]byte, string) ([]byte, error) {
			return func([]byte, string) ([]byte, error) { return []byte("malformed"), nil }
		}, "failed to process"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, request, tgt, key := newCoverageTGSRequest(t)
			client.sendToKDCFunc = test.send(request)
			if _, _, err := client.TGSExchange(
				request,
				exchangeFixtureRealm,
				tgt,
				key,
				0,
			); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("TGS exchange error = %v", err)
			}
		})
	}
}

func TestServiceTicketCacheAndDelegationGuards(t *testing.T) {
	client, _, _, _ := newCoverageTGSRequest(t)
	spn := "HTTP/server.example.org"
	ticket := s4uTestTicket(exchangeFixtureRealm, spn)
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	now := time.Now().UTC()
	client.cache.addEntryWithDetails(
		ticket,
		now,
		now.Add(-time.Minute),
		now.Add(time.Hour),
		now.Add(time.Hour),
		key,
		types.NewKrbFlags(),
		nil,
		nil,
		false,
		nil,
	)
	gotTicket, gotKey, err := client.GetServiceTicket(spn)
	if err != nil || !gotTicket.SName.Equal(ticket.SName) || string(gotKey.KeyValue) != string(key.KeyValue) {
		t.Fatalf("cached service ticket = %+v/%x, %v", gotTicket, gotKey.KeyValue, err)
	}
	if _, err := client.GetDelegatedCredential(ticket, key, nil, false); err == nil || !strings.Contains(
		err.Error(),
		"not trusted",
	) {
		t.Fatalf("delegation guard error = %v", err)
	}
	client.cache.clear()
	if _, _, err := client.GetServiceTicket(spn); err == nil {
		t.Fatal("service ticket without a TGT returned no error")
	}
}

func TestTGSGenerateExchangeSuccess(t *testing.T) {
	client, _, tgt, key := newCoverageTGSRequest(t)
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/server.example.org")
	replyKey := s4uTestKey(9)
	client.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		return marshalS4UTGSReply(
			t,
			request,
			key,
			replyKey,
			client.Credentials.CName(),
			client.Credentials.Realm(),
			service,
		), nil
	}
	request, reply, err := client.TGSREQGenerateAndExchange(service, exchangeFixtureRealm, tgt, key, false)
	if err != nil || !request.ReqBody.SName.Equal(service) || !reply.Ticket.SName.Equal(service) {
		t.Fatalf("TGS success = request %+v, reply %+v, %v", request.ReqBody.SName, reply.Ticket.SName, err)
	}
	if ticket, cachedKey, ok := client.GetCachedTicket(
		service.PrincipalNameString(),
	); !ok || !ticket.SName.Equal(service) || string(cachedKey.KeyValue) != string(replyKey.KeyValue) {
		t.Fatalf("cached TGS reply = %+v/%x, %v", ticket.SName, cachedKey.KeyValue, ok)
	}
}

func TestTGSExchangeReferralLimitHasNoCause(t *testing.T) {
	client, request, tgt, key := newCoverageTGSRequest(t)
	referral := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/OTHER.ORG")
	calls := 0
	client.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		calls++
		var decoded messages.TGSReq
		require.NoError(t, decoded.Unmarshal(requestBytes))
		cname, realm := client.Credentials.CName(), client.Credentials.Realm()
		return marshalS4UTGSReply(t, decoded, key, s4uTestKey(9), cname, realm, referral), nil
	}
	gotReq, gotRep, err := client.TGSExchange(request, exchangeFixtureRealm, tgt, key, 6)
	require.ErrorContains(t, err, "maximum number of referrals exceeded")
	require.NotContains(t, err.Error(), "%!")
	var classified krberror.Krberror
	require.ErrorAs(t, err, &classified)
	require.Equal(t, krberror.KRBMsgError, classified.RootCause)
	require.NoError(t, errors.Unwrap(err))
	require.Equal(t, 1, calls)
	require.Equal(t, request.ReqBody.SName, gotReq.ReqBody.SName)
	require.True(t, referral.Equal(gotRep.Ticket.SName))
	_, hasSession := client.sessions.get("OTHER.ORG")
	require.False(t, hasSession)
}

func TestTGSExchangeRejectsMissingTicketServerName(t *testing.T) {
	client, request, tgt, key := newCoverageTGSRequest(t)
	client.sendToKDCFunc = func([]byte, string) ([]byte, error) {
		cname, realm := request.ReqBody.CName, request.ReqBody.Realm
		wire := marshalS4UTGSReply(t, request, key, key, cname, realm, request.ReqBody.SName)
		var reply messages.TGSRep
		require.NoError(t, reply.Unmarshal(wire))
		reply.Ticket.SName.NameString = nil
		return reply.Marshal()
	}

	_, reply, err := client.TGSExchange(request, request.ReqBody.Realm, tgt, key, 0)
	require.ErrorContains(t, err, "reply ticket has no server principal components")
	require.Empty(t, reply.Ticket.SName.NameString)
	_, _, cached := client.GetCachedTicket("")
	require.False(t, cached)
}

func TestTGSExchangePreservesUserToUserReferral(t *testing.T) {
	client, request, tgt, key := newCoverageTGSRequest(t)
	t.Cleanup(client.Destroy)
	target := request.ReqBody.SName
	homeRealm := request.ReqBody.Realm
	verifier := s4uTestTicket("OTHER.ORG", "krbtgt/OTHER.ORG")
	initial, err := messages.NewUser2UserTGSReqWithOptions(
		request.ReqBody.CName, homeRealm, client.Config, tgt, key, target, false, verifier,
		client.tgsReqOptions(homeRealm),
	)
	require.NoError(t, err)
	referralKey := s4uTestKey(9)
	var realms []string
	client.sendToKDCFunc = func(requestBytes []byte, realm string) ([]byte, error) {
		realms = append(realms, realm)
		var decoded messages.TGSReq
		require.NoError(t, decoded.Unmarshal(requestBytes))
		switch realm {
		case homeRealm:
			return marshalS4UTGSReply(t, decoded, key, referralKey, request.ReqBody.CName, realm, verifier.SName), nil
		case "OTHER.ORG":
			require.Equal(t, []messages.Ticket{verifier}, decoded.ReqBody.AdditionalTickets)
			require.True(t, types.IsFlagSet(&decoded.ReqBody.KDCOptions, flags.EncTktInSkey))
			require.Equal(t, target, decoded.ReqBody.SName)
			return marshalS4UTGSReply(t, decoded, referralKey, key, request.ReqBody.CName, realm, target), nil
		default:
			t.Fatalf("unexpected realm %q", realm)
			return nil, nil
		}
	}
	next, reply, err := client.TGSExchange(initial, homeRealm, tgt, key, 5)
	require.NoError(t, err)
	require.Equal(t, []string{homeRealm, verifier.Realm}, realms)
	require.Equal(t, "OTHER.ORG", next.ReqBody.Realm)
	require.Equal(t, target, reply.Ticket.SName)
}

func TestTGSExchangeReferralBuildError(t *testing.T) {
	for _, tt := range []struct {
		name string
		u2u  bool
		want string
	}{
		{name: "ordinary", u2u: false, want: "build referral TGS-REQ"},
		{name: "user to user", u2u: true, want: "build user-to-user referral TGS-REQ"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			client, request, tgt, key := newCoverageTGSRequest(t)
			t.Cleanup(client.Destroy)
			if tt.u2u {
				types.SetFlag(&request.ReqBody.KDCOptions, flags.EncTktInSkey)
				request.ReqBody.AdditionalTickets = []messages.Ticket{tgt}
			}
			client.sendToKDCFunc = func(requestBytes []byte, realm string) ([]byte, error) {
				require.Equal(t, exchangeFixtureRealm, realm, "failed referral rebuild must not reach transport")
				var decoded messages.TGSReq
				require.NoError(t, decoded.Unmarshal(requestBytes))
				referral := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/OTHER.ORG")
				unusableKey := s4uTestKey(9)
				unusableKey.KeyType = -1
				return marshalS4UTGSReply(t, decoded, key, unusableKey, decoded.ReqBody.CName, realm, referral), nil
			}
			gotReq, gotRep, err := client.TGSExchange(request, exchangeFixtureRealm, tgt, key, 0)
			require.ErrorContains(t, err, tt.want)
			var classified krberror.Krberror
			require.ErrorAs(t, err, &classified)
			require.Equal(t, krberror.EncryptingError, classified.RootCause)
			require.Equal(t, "OTHER.ORG", gotReq.ReqBody.Realm)
			require.Len(t, gotReq.ReqBody.AdditionalTickets, len(request.ReqBody.AdditionalTickets))
			require.Equal(t, "krbtgt/OTHER.ORG", gotRep.Ticket.SName.PrincipalNameString())
		})
	}
}

func TestReferralRealmPreservesASN1Error(t *testing.T) {
	data := types.PADataSequence{{PADataType: patype.PA_SVR_REFERRAL_INFO, PADataValue: []byte{0x30, 0x01}}}
	realm, err := referralRealm(data, "FALLBACK.ORG")
	require.ErrorContains(t, err, "decode referral realm from PA-SVR-REFERRAL-INFO")
	var syntax asn1.SyntaxError
	require.ErrorAs(t, err, &syntax)
	require.Empty(t, realm)
}

func TestGetDelegatedCredentialRoundTrip(t *testing.T) {
	var (
		emptyFlags     asn1.BitString
		emptyPrincipal types.PrincipalName
	)

	client, _, tgt, tgtKey := newCoverageTGSRequest(t)
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
	serviceTicket := s4uTestTicket(exchangeFixtureRealm, "HTTP/server.example.org")
	serviceKey := s4uTestKey(7)
	forwardedKey := s4uTestKey(8)
	addresses := types.HostAddresses{{AddrType: addrtype.IPv4, Address: []byte{192, 0, 2, 1}}}
	client.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		var request messages.TGSReq
		require.NoError(t, request.Unmarshal(requestBytes))
		if !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) || !types.IsFlagSet(
			&request.ReqBody.KDCOptions,
			flags.Forwardable,
		) ||
			len(request.ReqBody.Addresses) != 1 {
			t.Fatalf("forwarded TGT options = %+v/%+v", request.ReqBody.KDCOptions, request.ReqBody.Addresses)
		}
		return marshalS4UTGSReply(
			t,
			request,
			tgtKey,
			forwardedKey,
			client.Credentials.CName(),
			client.Credentials.Realm(),
			request.ReqBody.SName,
		), nil
	}
	wire, err := client.GetDelegatedCredential(serviceTicket, serviceKey, addresses, true)
	require.NoError(t, err)
	var credential messages.KRBCred
	require.NoError(t, credential.Unmarshal(wire))
	if err := credential.DecryptEncPart(serviceKey); err != nil || len(credential.Tickets) != 1 || len(
		credential.DecryptedEncPart.TicketInfo,
	) != 1 {
		t.Fatalf("delegated credential = %+v, %v", credential, err)
	}
	if got := credential.DecryptedEncPart.TicketInfo[0]; string(got.Key.KeyValue) != string(forwardedKey.KeyValue) {
		t.Fatalf("delegated key = %x", got.Key.KeyValue)
	}
}

func TestRealmLoginObtainsCrossRealmTGT(t *testing.T) {
	var (
		emptyFlags     asn1.BitString
		emptyPrincipal types.PrincipalName
	)

	client, _, homeTGT, homeKey := newCoverageTGSRequest(t)
	now := time.Now().UTC()
	client.addSession(homeTGT, messages.EncKDCRepPart{
		LastReqs:      nil,
		Nonce:         0,
		KeyExpiration: time.Time{},
		Flags:         emptyFlags,
		SRealm:        "",
		SName:         emptyPrincipal,
		CAddr:         nil,
		EncPAData:     nil,
		Key:           homeKey, AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), RenewTill: now.Add(2 * time.Hour),
	})
	foreignKey := s4uTestKey(9)
	client.sendToKDCFunc = func(requestBytes []byte, realm string) ([]byte, error) {
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if realm != exchangeFixtureRealm || request.ReqBody.SName.PrincipalNameString() != "krbtgt/OTHER.ORG" {
			t.Fatalf("cross-realm request = %q/%q", realm, request.ReqBody.SName.PrincipalNameString())
		}
		return marshalS4UTGSReply(
			t,
			request,
			homeKey,
			foreignKey,
			client.Credentials.CName(),
			client.Credentials.Realm(),
			request.ReqBody.SName,
		), nil
	}
	if err := client.realmLogin("OTHER.ORG"); err != nil {
		t.Fatal(err)
	}
	_, gotKey, err := client.sessionTGT("OTHER.ORG")
	if err != nil || string(gotKey.KeyValue) != string(foreignKey.KeyValue) {
		t.Fatalf("foreign session key = %x, %v", gotKey.KeyValue, err)
	}
}
