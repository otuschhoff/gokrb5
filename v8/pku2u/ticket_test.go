package pku2u

import (
	"crypto/x509"
	"slices"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	asTestHost   = "pku2u-as.example.com"
	asTestTarget = "host/" + asTestHost
)

func TestASExchangeOwnsEnctypeOffer(t *testing.T) {
	t.Parallel()

	root, rootKey := newPKU2URoot(t)
	cert, key := newPKU2ULeaf(t, root, rootKey, "Offer test", nil, upnSAN(t, "offer@example.com"))
	identity, err := pkinit.NewIdentity(cert, []*x509.Certificate{root}, key, false)
	if err != nil {
		t.Fatal(err)
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	cfg := newSettings(identity, anchors, nil)
	want := []int32{
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.AES256_CTS_HMAC_SHA384_192,
		etypeID.AES128_CTS_HMAC_SHA256_128,
	}

	for range 2 {
		wire, state, buildErr := beginASExchange(cfg, "host/server.example.com")
		if buildErr != nil {
			t.Fatal(buildErr)
		}
		var decoded messages.ASReq
		if decodeErr := decoded.Unmarshal(wire); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		if !slices.Equal(want, decoded.ReqBody.EType) || !slices.Equal(want, state.request.ReqBody.EType) {
			t.Fatalf("wire offer = %v, state offer = %v; want %v", decoded.ReqBody.EType, state.request.ReqBody.EType, want)
		}

		// Editing one request must not affect membership or the next request.
		state.request.ReqBody.EType[0] = 0
		if !isPKU2UEType(want[0]) || isPKU2UEType(0) {
			t.Fatal("editing the request changed subkey validation")
		}
	}
}

func TestPKU2USubkeyEnctypePolicy(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		id   int32
		want bool
	}{
		{name: "aes256 sha1", id: etypeID.AES256_CTS_HMAC_SHA1_96, want: true},
		{name: "aes128 sha1", id: etypeID.AES128_CTS_HMAC_SHA1_96, want: true},
		{name: "aes256 sha384", id: etypeID.AES256_CTS_HMAC_SHA384_192, want: true},
		{name: "aes128 sha256", id: etypeID.AES128_CTS_HMAC_SHA256_128, want: true},
		{name: "rc4", id: etypeID.RC4_HMAC, want: false},
		{name: "triple des", id: etypeID.DES3_CBC_SHA1_KD, want: false},
		{name: "unknown", id: -1, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if got := isPKU2UEType(tt.id); got != tt.want {
				t.Fatalf("isPKU2UEType(%d) = %t, want %t", tt.id, got, tt.want)
			}
		})
	}
}

func TestFinishASExchangeRejectsInvalidReply(t *testing.T) {
	t.Parallel()

	client, server := newTestASExchangeSettings(t)
	requestDER, state, err := beginASExchange(client, asTestTarget)
	if err != nil {
		t.Fatal(err)
	}
	replyDER, _, err := acceptASExchange(requestDER, server)
	if err != nil {
		t.Fatal(err)
	}

	for _, tt := range []struct {
		name   string
		change func(*messages.ASRep)
		want   string
	}{
		{
			name: "missing pkinit reply",
			change: func(reply *messages.ASRep) {
				reply.PAData[0].PADataType = patype.PA_PAC_REQUEST
			},
			want: "PKU2U AS reply is missing PA-PK-AS-REP",
		},
		{
			name: "duplicate pkinit replies",
			change: func(reply *messages.ASRep) {
				reply.PAData = append(reply.PAData, reply.PAData[0])
			},
			want: "PKU2U AS reply contains duplicate PA-PK-AS-REP values",
		},
		{
			name: "malformed pkinit reply",
			change: func(reply *messages.ASRep) {
				reply.PAData[0].PADataValue = []byte{0x30}
			},
			want: "process PKU2U PKINIT reply: decode PA-PK-AS-REP:",
		},
		{
			name: "corrupt encrypted part",
			change: func(reply *messages.ASRep) {
				reply.EncPart.Cipher[len(reply.EncPart.Cipher)-1] ^= 1
			},
			want: "verify PKU2U AS reply:",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			reply := decodeTestASReply(t, replyDER)
			tt.change(&reply)
			encoded, err := reply.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			result, err := finishASExchange(state, encoded, client)
			if result != nil || err == nil || !strings.HasPrefix(err.Error(), tt.want) {
				t.Fatalf("want no result and error starting with %q, got result=%t, err=%v",
					tt.want, result != nil, err)
			}
		})
	}
}

func TestASExchangeTicketLifetime(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name        string
		endFromTill bool
	}{
		{name: "acceptor cap", endFromTill: false},
		{name: "request till", endFromTill: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			synctest.Test(t, func(t *testing.T) {
				client, server := newTestASExchangeSettings(t)
				requestDER, state, err := beginASExchange(client, asTestTarget)
				if err != nil {
					t.Fatal(err)
				}
				now := time.Now().UTC()
				server.ticketLifetime = time.Minute
				wantEnd := now.Add(server.ticketLifetime)
				if tt.endFromTill {
					wantEnd = state.request.ReqBody.Till
					server.ticketLifetime = wantEnd.Sub(now) + time.Minute
				}
				replyDER, issued, err := acceptASExchange(requestDER, server)
				if err != nil {
					t.Fatal(err)
				}
				requireTestASReplyTimes(t, replyDER, state, issued.ticketKey, wantEnd)
			})
		})
	}
}

func TestASExchangeRejectsZeroLifetime(t *testing.T) {
	t.Parallel()

	client, server := newTestASExchangeSettings(t)
	requestDER, _, err := beginASExchange(client, asTestTarget)
	if err != nil {
		t.Fatal(err)
	}
	server.ticketLifetime = 0
	wire, result, err := acceptASExchange(requestDER, server)
	const want = "PKU2U AS request ticket lifetime has expired"
	if wire != nil || result != nil || err == nil || err.Error() != want {
		t.Fatalf("want no reply or result and %q, got reply=%t, result=%t, err=%v",
			want, wire != nil, result != nil, err)
	}
}

func newTestASExchangeSettings(t *testing.T) (settings, settings) {
	t.Helper()

	root, rootKey := newPKU2URoot(t)
	clientCert, clientKey := newPKU2ULeaf(
		t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"),
	)
	serverCert, serverKey := newPKU2ULeaf(
		t, root, rootKey, "Server", []string{asTestHost}, nil,
	)
	client, err := pkinit.NewIdentity(clientCert, []*x509.Certificate{root}, clientKey, false)
	if err != nil {
		t.Fatal(err)
	}
	server, err := pkinit.NewIdentity(serverCert, []*x509.Certificate{root}, serverKey, false)
	if err != nil {
		t.Fatal(err)
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	return newSettings(client, anchors, nil), newSettings(server, anchors, nil)
}

func decodeTestASReply(t *testing.T, encoded []byte) messages.ASRep {
	t.Helper()

	var reply messages.ASRep
	if err := reply.Unmarshal(encoded); err != nil {
		t.Fatal(err)
	}
	if len(reply.PAData) != 1 || reply.PAData[0].PADataType != patype.PA_PK_AS_REP {
		t.Fatal("expected exactly one PA-PK-AS-REP in the issued reply")
	}
	return reply
}

func requireTestASReplyTimes(
	t *testing.T,
	wire []byte,
	state *initiatorASState,
	ticketKey types.EncryptionKey,
	wantEnd time.Time,
) {
	t.Helper()

	reply := decodeTestASReply(t, wire)
	pkResult, err := state.exchange.ProcessReply(reply.PAData[0].PADataValue, reply.EncPart.EType)
	if err != nil {
		t.Fatal(err)
	}
	if err := reply.DecryptEncPartWithKey(pkResult.ReplyKey); err != nil {
		t.Fatal(err)
	}
	if err := reply.Ticket.Decrypt(ticketKey); err != nil {
		t.Fatal(err)
	}
	part := &reply.Ticket.DecryptedEncPart
	requireTestTicketLifetime(t, part, wantEnd)

	replyPart := reply.DecryptedEncPart
	replyStartsWithTicket := replyPart.AuthTime.Equal(part.AuthTime) && replyPart.StartTime.Equal(part.StartTime)
	if !replyStartsWithTicket || !replyPart.EndTime.Equal(part.EndTime) {
		t.Fatalf("reply times = (%s, %s, %s), want (%s, %s, %s)",
			replyPart.AuthTime, replyPart.StartTime, replyPart.EndTime, part.AuthTime, part.StartTime, part.EndTime)
	}
}

func requireTestTicketLifetime(t *testing.T, part *messages.EncTicketPart, wantEnd time.Time) {
	t.Helper()

	now := time.Now().UTC()
	startsAtIssuance := part.AuthTime.Equal(now) && part.StartTime.Equal(now)
	if !startsAtIssuance || !part.EndTime.Equal(wantEnd) {
		t.Fatalf("ticket times = (%s, %s, %s), want (%s, %s, %s)",
			part.AuthTime, part.StartTime, part.EndTime, now, now, wantEnd)
	}
	initialAndPreauthenticated := types.IsFlagSet(&part.Flags, flags.Initial) &&
		types.IsFlagSet(&part.Flags, flags.PreAuthent)
	if !initialAndPreauthenticated || !part.RenewTill.IsZero() {
		t.Fatal("self-ticket should be initial, pre-authenticated, and non-renewable")
	}
}
