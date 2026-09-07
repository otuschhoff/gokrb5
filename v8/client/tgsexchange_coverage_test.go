package client

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/addrtype"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func newCoverageTGSRequest(t *testing.T) (*Client, messages.TGSReq, messages.Ticket, types.EncryptionKey) {
	t.Helper()
	cfg := config.New()
	cfg.LibDefaults.DNSLookupKDC = true
	cfg.LibDefaults.DefaultTGSEnctypeIDs = []int32{etypeID.AES128_CTS_HMAC_SHA1_96}
	client := NewWithPassword("alice", "EXAMPLE.ORG", "password", cfg)
	tgt := s4uTestTicket("EXAMPLE.ORG", "krbtgt/EXAMPLE.ORG")
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	request, err := messages.NewTGSReq(client.Credentials.CName(), "EXAMPLE.ORG", cfg, tgt, key,
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
				return nil, messages.NewKRBError(request.ReqBody.CName, request.ReqBody.Realm, errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN, "missing")
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
			if _, _, err := client.TGSExchange(request, "EXAMPLE.ORG", tgt, key, 0); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("TGS exchange error = %v", err)
			}
		})
	}
}

func TestServiceTicketCacheAndDelegationGuards(t *testing.T) {
	client, _, _, _ := newCoverageTGSRequest(t)
	spn := "HTTP/server.example.org"
	ticket := s4uTestTicket("EXAMPLE.ORG", spn)
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	now := time.Now().UTC()
	client.cache.addEntryWithDetails(ticket, now, now, now.Add(time.Hour), now.Add(time.Hour), key, types.NewKrbFlags(), nil, nil, false, nil)
	gotTicket, gotKey, err := client.GetServiceTicket(spn)
	if err != nil || !gotTicket.SName.Equal(ticket.SName) || string(gotKey.KeyValue) != string(key.KeyValue) {
		t.Fatalf("cached service ticket = %+v/%x, %v", gotTicket, gotKey.KeyValue, err)
	}
	if _, err := client.GetDelegatedCredential(ticket, key, nil, false); err == nil || !strings.Contains(err.Error(), "not trusted") {
		t.Fatalf("delegation guard error = %v", err)
	}
	client.cache.clear()
	if _, _, err := client.GetServiceTicket(spn); err == nil {
		t.Fatal("service ticket without a TGT returned no error")
	}
}

func TestTGSGenerateExchangeSuccessAndReferralLimit(t *testing.T) {
	client, _, tgt, key := newCoverageTGSRequest(t)
	service := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "HTTP/server.example.org")
	replyKey := s4uTestKey(9)
	client.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		return marshalS4UTGSReply(t, request, key, replyKey, client.Credentials.CName(), client.Credentials.Realm(), service), nil
	}
	request, reply, err := client.TGSREQGenerateAndExchange(service, "EXAMPLE.ORG", tgt, key, false)
	if err != nil || !request.ReqBody.SName.Equal(service) || !reply.Ticket.SName.Equal(service) {
		t.Fatalf("TGS success = request %+v, reply %+v, %v", request.ReqBody.SName, reply.Ticket.SName, err)
	}
	if ticket, cachedKey, ok := client.GetCachedTicket(service.PrincipalNameString()); !ok || !ticket.SName.Equal(service) || string(cachedKey.KeyValue) != string(replyKey.KeyValue) {
		t.Fatalf("cached TGS reply = %+v/%x, %v", ticket.SName, cachedKey.KeyValue, ok)
	}

	client, request, tgt, key = newCoverageTGSRequest(t)
	referral := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/OTHER.ORG")
	client.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		var decoded messages.TGSReq
		if err := decoded.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		return marshalS4UTGSReply(t, decoded, key, replyKey, client.Credentials.CName(), client.Credentials.Realm(), referral), nil
	}
	if _, _, err := client.TGSExchange(request, "EXAMPLE.ORG", tgt, key, 6); err == nil || !strings.Contains(err.Error(), "maximum number of referrals") {
		t.Fatalf("referral limit error = %v", err)
	}
}

func TestGetDelegatedCredentialRoundTrip(t *testing.T) {
	client, _, tgt, tgtKey := newCoverageTGSRequest(t)
	now := time.Now().UTC()
	client.addSession(tgt, messages.EncKDCRepPart{
		Key: tgtKey, AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), RenewTill: now.Add(2 * time.Hour),
	})
	serviceTicket := s4uTestTicket("EXAMPLE.ORG", "HTTP/server.example.org")
	serviceKey := s4uTestKey(7)
	forwardedKey := s4uTestKey(8)
	addresses := types.HostAddresses{{AddrType: addrtype.IPv4, Address: []byte{192, 0, 2, 1}}}
	client.sendToKDCFunc = func(requestBytes []byte, _ string) ([]byte, error) {
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwarded) || !types.IsFlagSet(&request.ReqBody.KDCOptions, flags.Forwardable) ||
			len(request.ReqBody.Addresses) != 1 {
			t.Fatalf("forwarded TGT options = %+v/%+v", request.ReqBody.KDCOptions, request.ReqBody.Addresses)
		}
		return marshalS4UTGSReply(t, request, tgtKey, forwardedKey, client.Credentials.CName(), client.Credentials.Realm(), request.ReqBody.SName), nil
	}
	wire, err := client.GetDelegatedCredential(serviceTicket, serviceKey, addresses, true)
	if err != nil {
		t.Fatal(err)
	}
	var credential messages.KRBCred
	if err := credential.Unmarshal(wire); err != nil {
		t.Fatal(err)
	}
	if err := credential.DecryptEncPart(serviceKey); err != nil || len(credential.Tickets) != 1 || len(credential.DecryptedEncPart.TicketInfo) != 1 {
		t.Fatalf("delegated credential = %+v, %v", credential, err)
	}
	if got := credential.DecryptedEncPart.TicketInfo[0]; string(got.Key.KeyValue) != string(forwardedKey.KeyValue) {
		t.Fatalf("delegated key = %x", got.Key.KeyValue)
	}
}

func TestRealmLoginObtainsCrossRealmTGT(t *testing.T) {
	client, _, homeTGT, homeKey := newCoverageTGSRequest(t)
	now := time.Now().UTC()
	client.addSession(homeTGT, messages.EncKDCRepPart{
		Key: homeKey, AuthTime: now, StartTime: now, EndTime: now.Add(time.Hour), RenewTill: now.Add(2 * time.Hour),
	})
	foreignKey := s4uTestKey(9)
	client.sendToKDCFunc = func(requestBytes []byte, realm string) ([]byte, error) {
		var request messages.TGSReq
		if err := request.Unmarshal(requestBytes); err != nil {
			t.Fatal(err)
		}
		if realm != "EXAMPLE.ORG" || request.ReqBody.SName.PrincipalNameString() != "krbtgt/OTHER.ORG" {
			t.Fatalf("cross-realm request = %q/%q", realm, request.ReqBody.SName.PrincipalNameString())
		}
		return marshalS4UTGSReply(t, request, homeKey, foreignKey, client.Credentials.CName(), client.Credentials.Realm(), request.ReqBody.SName), nil
	}
	if err := client.realmLogin("OTHER.ORG"); err != nil {
		t.Fatal(err)
	}
	_, gotKey, err := client.sessionTGT("OTHER.ORG")
	if err != nil || string(gotKey.KeyValue) != string(foreignKey.KeyValue) {
		t.Fatalf("foreign session key = %x, %v", gotKey.KeyValue, err)
	}
}
