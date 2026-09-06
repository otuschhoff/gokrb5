package pku2u

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/goidentity/v6"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/chksumtype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/negoex"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/spnego"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestASExchangeIssuesSelfTicket(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{"server.example.com"}, nil)
	clientIdentity, err := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	if err != nil {
		t.Fatal(err)
	}
	serverIdentity, err := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	if err != nil {
		t.Fatal(err)
	}
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	clientSettings := newSettings(clientIdentity, anchors, nil)
	serverSettings := newSettings(serverIdentity, anchors, nil)

	requestDER, clientState, err := beginASExchange(clientSettings, "host/server.example.com")
	if err != nil {
		t.Fatal(err)
	}
	pacRequests := 0
	for _, pa := range clientState.request.PAData {
		if pa.PADataType == patype.PA_PAC_REQUEST {
			pacRequests++
			request, err := pa.GetKerbPAPACRequest()
			if err != nil || request.IncludePAC {
				t.Fatalf("PKU2U PAC request = %#v, %v", request, err)
			}
		}
	}
	if pacRequests != 1 {
		t.Fatalf("PAC request count = %d, want 1", pacRequests)
	}
	replyDER, serverState, err := acceptASExchange(requestDER, serverSettings)
	if err != nil {
		t.Fatal(err)
	}
	clientResult, err := finishASExchange(clientState, replyDER, clientSettings)
	if err != nil {
		t.Fatal(err)
	}
	if clientResult.sessionKey.KeyType != serverState.sessionKey.KeyType ||
		string(clientResult.sessionKey.KeyValue) != string(serverState.sessionKey.KeyValue) {
		t.Fatal("initiator and acceptor session keys differ")
	}
	ticket := clientResult.ticket
	if err := ticket.Decrypt(serverState.ticketKey); err != nil {
		t.Fatal(err)
	}
	if ticket.Realm != Realm || !ticket.SName.Equal(clientState.request.ReqBody.SName) ||
		!ticket.DecryptedEncPart.CName.Equal(clientState.request.ReqBody.CName) {
		t.Fatalf("issued ticket does not bind requested PKU2U names: %#v", ticket)
	}
}

func TestASExchangeRejectsPolicyViolations(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{"server.example.com"}, nil)
	clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	clientSettings := newSettings(clientIdentity, anchors, nil)
	serverSettings := newSettings(serverIdentity, anchors, nil)
	request := func(t *testing.T, target string) ([]byte, *initiatorASState) {
		t.Helper()
		encoded, state, err := beginASExchange(clientSettings, target)
		if err != nil {
			t.Fatal(err)
		}
		return encoded, state
	}
	mutate := func(t *testing.T, encoded []byte, change func(*messages.ASReq)) []byte {
		t.Helper()
		var decoded messages.ASReq
		if err := decoded.Unmarshal(encoded); err != nil {
			t.Fatal(err)
		}
		change(&decoded)
		encoded, err := decoded.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}

	t.Run("wrong realm", func(t *testing.T) {
		encoded, _ := request(t, "host/server.example.com")
		encoded = mutate(t, encoded, func(request *messages.ASReq) { request.ReqBody.Realm = "EXAMPLE.COM" })
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted a PKU2U request for another realm")
		}
	})
	t.Run("wrong service certificate", func(t *testing.T) {
		encoded, _ := request(t, "host/other.example.com")
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted a request targeting another service")
		}
	})
	t.Run("missing PAC suppression", func(t *testing.T) {
		encoded, _ := request(t, "host/server.example.com")
		encoded = mutate(t, encoded, func(request *messages.ASReq) {
			filtered := request.PAData[:0]
			for _, pa := range request.PAData {
				if pa.PADataType != patype.PA_PAC_REQUEST {
					filtered = append(filtered, pa)
				}
			}
			request.PAData = filtered
		})
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted a request without PAC suppression")
		}
	})
	t.Run("duplicate PAC suppression", func(t *testing.T) {
		encoded, _ := request(t, "host/server.example.com")
		encoded = mutate(t, encoded, func(request *messages.ASReq) {
			for _, pa := range request.PAData {
				if pa.PADataType == patype.PA_PAC_REQUEST {
					request.PAData = append(request.PAData, pa)
					return
				}
			}
		})
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted duplicate PAC suppression")
		}
	})
	t.Run("PAC requested", func(t *testing.T) {
		encoded, _ := request(t, "host/server.example.com")
		encoded = mutate(t, encoded, func(request *messages.ASReq) {
			value, err := (&types.KerbPAPACRequest{IncludePAC: true}).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			for index := range request.PAData {
				if request.PAData[index].PADataType == patype.PA_PAC_REQUEST {
					request.PAData[index].PADataValue = value
				}
			}
		})
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted a request enabling PAC issuance")
		}
	})
	t.Run("untrusted initiator", func(t *testing.T) {
		otherRoot, otherRootKey := newPKU2URoot(t)
		certificate, key := newPKU2ULeaf(t, otherRoot, otherRootKey, "Mallory", nil, upnSAN(t, "mallory@example.com"))
		identity, _ := pkinit.NewIdentity(certificate, []*x509.Certificate{otherRoot}, key, false)
		encoded, _, err := beginASExchange(newSettings(identity, anchors, nil), "host/server.example.com")
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted an untrusted initiator")
		}
	})
	t.Run("untrusted acceptor", func(t *testing.T) {
		otherRoot, _ := newPKU2URoot(t)
		otherAnchors := x509.NewCertPool()
		otherAnchors.AddCert(otherRoot)
		encoded, state, err := beginASExchange(newSettings(clientIdentity, otherAnchors, nil), "host/server.example.com")
		if err != nil {
			t.Fatal(err)
		}
		reply, _, err := acceptASExchange(encoded, serverSettings)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := finishASExchange(state, reply, newSettings(clientIdentity, otherAnchors, nil)); err == nil {
			t.Fatal("accepted an untrusted acceptor")
		}
	})
}

func TestEndToEndContext(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{"server.example.com"}, nil)
	clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	initiator := NewInitiator(clientIdentity, anchors)
	acceptor := NewAcceptor(serverIdentity, anchors)

	initiatorMetadata, err := initiator.QueryMetadata("host/server.example.com", true)
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptor.ExchangeMetadata(initiatorMetadata, false); err != nil {
		t.Fatal(err)
	}
	acceptorMetadata, err := acceptor.QueryMetadata("", false)
	if err != nil {
		t.Fatal(err)
	}
	if err := initiator.ExchangeMetadata(acceptorMetadata, true); err != nil {
		t.Fatal(err)
	}

	asRequest, _, done, err := initiator.InitSecContext("host/server.example.com", nil)
	if err != nil || done {
		t.Fatalf("init AS request: done=%t err=%v", done, err)
	}
	asReply, _, done, err := acceptor.AcceptSecContext(asRequest)
	if err != nil || done {
		t.Fatalf("accept AS request: done=%t err=%v", done, err)
	}
	apRequest, _, done, err := initiator.InitSecContext("host/server.example.com", asReply)
	if err != nil || done {
		t.Fatalf("init AP request: done=%t err=%v", done, err)
	}
	apReply, acceptorContext, done, err := acceptor.AcceptSecContext(apRequest)
	if err != nil || !done || acceptorContext == nil {
		t.Fatalf("accept AP request: done=%t err=%v", done, err)
	}
	output, initiatorContext, done, err := initiator.InitSecContext("host/server.example.com", apReply)
	if err != nil || !done || initiatorContext == nil || len(output) != 0 {
		t.Fatalf("init AP reply: output=%x done=%t err=%v", output, done, err)
	}
	initiatorKey, initiatorHasKey := initiatorContext.NegoExKey()
	acceptorKey, acceptorHasKey := acceptorContext.NegoExVerifyKey()
	if !initiatorHasKey || !acceptorHasKey || initiatorKey.KeyType != acceptorKey.KeyType || string(initiatorKey.KeyValue) != string(acceptorKey.KeyValue) {
		t.Fatal("established contexts have different NEGOEX keys")
	}
	assertProtectedMessage(t, initiatorContext, acceptorContext, []byte("initiator secret"), true)
	assertProtectedMessage(t, acceptorContext, initiatorContext, []byte("acceptor visible"), false)
	mic, err := initiatorContext.GetMIC([]byte("bound message"))
	if err != nil {
		t.Fatal(err)
	}
	if err := acceptorContext.VerifyMIC([]byte("bound message"), mic); err != nil {
		t.Fatal(err)
	}
	credentialContext, ok := acceptorContext.(interface {
		Credentials() *credentials.Credentials
	})
	if !ok {
		t.Fatal("acceptor context does not expose credentials")
	}
	identity, ok := credentialContext.Credentials().GetCertificateIdentity()
	if !ok || identity.UPN != "alice@example.com" || !identity.Certificate.Equal(clientCertificate) {
		t.Fatalf("certificate identity = %#v, %t", identity, ok)
	}
}

func TestAPExchangeRejectsInvalidRequests(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{"server.example.com"}, nil)
	clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	clientSettings := newSettings(clientIdentity, anchors, nil)
	serverSettings := newSettings(serverIdentity, anchors, nil)
	asRequest, clientState, err := beginASExchange(clientSettings, "host/server.example.com")
	if err != nil {
		t.Fatal(err)
	}
	asReply, serverState, err := acceptASExchange(asRequest, serverSettings)
	if err != nil {
		t.Fatal(err)
	}
	clientResult, err := finishASExchange(clientState, asReply, clientSettings)
	if err != nil {
		t.Fatal(err)
	}
	makeRequest := func(t *testing.T, mutate func(*types.Authenticator)) messages.APReq {
		t.Helper()
		authenticator, err := types.NewAuthenticator(Realm, clientState.request.ReqBody.CName)
		if err != nil {
			t.Fatal(err)
		}
		checksum, err := gssapi.NewAuthenticatorChecksum(nil, gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf).Marshal()
		if err != nil {
			t.Fatal(err)
		}
		authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
		if err := authenticator.GenerateSeqNumberAndSubKey(clientResult.sessionKey.KeyType, len(clientResult.sessionKey.KeyValue)); err != nil {
			t.Fatal(err)
		}
		if mutate != nil {
			mutate(&authenticator)
		}
		request, err := messages.NewAPReq(clientResult.ticket, clientResult.sessionKey, authenticator)
		if err != nil {
			t.Fatal(err)
		}
		types.SetFlag(&request.APOptions, flags.APOptionMutualRequired)
		return request
	}
	accept := func(request messages.APReq) error {
		encoded, err := request.Marshal()
		if err != nil {
			return err
		}
		acceptor := &Acceptor{settings: serverSettings, asResult: serverState}
		_, _, err = acceptor.acceptAPRequest(encoded)
		return err
	}

	t.Run("mutual authentication missing", func(t *testing.T) {
		request := makeRequest(t, nil)
		types.UnsetFlag(&request.APOptions, flags.APOptionMutualRequired)
		if err := accept(request); err == nil {
			t.Fatal("accepted AP request without mutual authentication")
		}
	})
	t.Run("GSS checksum missing", func(t *testing.T) {
		request := makeRequest(t, func(authenticator *types.Authenticator) { authenticator.Cksum = types.Checksum{} })
		if err := accept(request); err == nil {
			t.Fatal("accepted AP request without GSS checksum")
		}
	})
	t.Run("integrity flag missing", func(t *testing.T) {
		request := makeRequest(t, func(authenticator *types.Authenticator) {
			checksum, err := gssapi.NewAuthenticatorChecksum(nil, gssapi.ContextFlagMutual).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
		})
		if err := accept(request); err == nil {
			t.Fatal("accepted AP request without integrity protection")
		}
	})
	t.Run("wrong client identity", func(t *testing.T) {
		request := makeRequest(t, func(authenticator *types.Authenticator) {
			authenticator.CName = types.NewPrincipalName(1, "mallory@example.com")
		})
		if err := accept(request); err == nil {
			t.Fatal("accepted authenticator for another client")
		}
	})
	t.Run("stale authenticator", func(t *testing.T) {
		request := makeRequest(t, func(authenticator *types.Authenticator) {
			authenticator.CTime = time.Now().UTC().Add(-10 * time.Minute)
		})
		if err := accept(request); err == nil {
			t.Fatal("accepted stale authenticator")
		}
	})
	t.Run("invalid microseconds", func(t *testing.T) {
		request := makeRequest(t, func(authenticator *types.Authenticator) { authenticator.Cusec = 1000000 })
		if err := accept(request); err == nil {
			t.Fatal("accepted invalid authenticator microseconds")
		}
	})
	t.Run("missing subkey", func(t *testing.T) {
		request := makeRequest(t, func(authenticator *types.Authenticator) { authenticator.SubKey = types.EncryptionKey{} })
		if err := accept(request); err == nil {
			t.Fatal("accepted authenticator without a subkey")
		}
	})
	t.Run("RC4 subkey", func(t *testing.T) {
		request := makeRequest(t, func(authenticator *types.Authenticator) {
			authenticator.SubKey = types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: make([]byte, 16)}
		})
		if err := accept(request); err == nil {
			t.Fatal("accepted RC4 authenticator subkey")
		}
	})
	t.Run("tampered authenticator", func(t *testing.T) {
		request := makeRequest(t, nil)
		request.EncryptedAuthenticator.Cipher[len(request.EncryptedAuthenticator.Cipher)-1] ^= 1
		if err := accept(request); err == nil {
			t.Fatal("accepted tampered authenticator")
		}
	})
	t.Run("tampered ticket", func(t *testing.T) {
		request := makeRequest(t, nil)
		request.Ticket.EncPart.Cipher[len(request.Ticket.EncPart.Cipher)-1] ^= 1
		if err := accept(request); err == nil {
			t.Fatal("accepted tampered ticket")
		}
	})
}

func TestEndToEndOverNegoEx(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{"server.example.com"}, nil)
	clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	initiator, err := negoex.NewInitiator("host/server.example.com", negoex.NewPKU2UScheme(NewInitiator(clientIdentity, anchors)))
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := negoex.NewAcceptor(negoex.NewPKU2UScheme(NewAcceptor(serverIdentity, anchors)))
	if err != nil {
		t.Fatal(err)
	}

	initiatorToken, done, err := initiator.Step(nil)
	if err != nil || done {
		t.Fatalf("initiator AS: done=%t err=%v", done, err)
	}
	acceptorToken, done, err := acceptor.Step(initiatorToken)
	if err != nil || done {
		t.Fatalf("acceptor AS: done=%t err=%v", done, err)
	}
	initiatorToken, done, err = initiator.Step(acceptorToken)
	if err != nil || done {
		t.Fatalf("initiator AP: done=%t err=%v", done, err)
	}
	acceptorToken, done, err = acceptor.Step(initiatorToken)
	if err != nil || done {
		t.Fatalf("acceptor AP: done=%t err=%v", done, err)
	}
	initiatorToken, done, err = initiator.Step(acceptorToken)
	if err != nil || !done {
		t.Fatalf("initiator verify: done=%t err=%v", done, err)
	}
	acceptorToken, done, err = acceptor.Step(initiatorToken)
	if err != nil || !done || len(acceptorToken) != 0 {
		t.Fatalf("acceptor verify: output=%x done=%t err=%v", acceptorToken, done, err)
	}
	assertProtectedMessage(t, initiator.Context(), acceptor.Context(), []byte("negoex secret"), true)
}

func TestEndToEndOverSPNEGO(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(gssapi.ContextMechanism) gssapi.ContextMechanism
	}{
		{name: "standalone", wrap: func(mechanism gssapi.ContextMechanism) gssapi.ContextMechanism { return mechanism }},
		{name: "NEGOEX", wrap: func(mechanism gssapi.ContextMechanism) gssapi.ContextMechanism {
			return negoex.New(negoex.NewPKU2UScheme(mechanism.(negoex.PKU2UMechanism)))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, rootKey := newPKU2URoot(t)
			clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
			serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{"server.example.com"}, nil)
			clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
			serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
			anchors := x509.NewCertPool()
			anchors.AddCert(root)
			initiator := spnego.NewNegotiator(test.wrap(NewInitiator(clientIdentity, anchors)))
			acceptor := spnego.NewNegotiator(test.wrap(NewAcceptor(serverIdentity, anchors)))
			initiatorContext, acceptorContext := establishSPNEGO(t, initiator, acceptor)
			assertProtectedMessage(t, initiatorContext, acceptorContext, []byte("spnego secret"), true)
		})
	}
}

func TestEndToEndHTTP(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{"server.example.com"}, nil)
	clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	handler := spnego.SPNEGOContextAuthenticate(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		identity := goidentity.FromHTTPRequestContext(request)
		credentials, ok := identity.(*credentials.Credentials)
		if !ok {
			http.Error(writer, "missing PKU2U credentials", http.StatusInternalServerError)
			return
		}
		certificateIdentity, ok := credentials.GetCertificateIdentity()
		if !ok {
			http.Error(writer, "missing certificate identity", http.StatusInternalServerError)
			return
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			http.Error(writer, "read request body", http.StatusInternalServerError)
			return
		}
		fmt.Fprintf(writer, "%s:%s", certificateIdentity.UPN, body)
	}), func() gssapi.ContextMechanism {
		return negoex.New(negoex.NewPKU2UScheme(NewAcceptor(serverIdentity, anchors)))
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	client := spnego.NewNegotiatingClient(server.Client(), "host/server.example.com", func() gssapi.ContextMechanism {
		return negoex.New(negoex.NewPKU2UScheme(NewInitiator(clientIdentity, anchors)))
	})
	request, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || string(body) != "alice@example.com:payload" || client.Context() == nil {
		t.Fatalf("HTTP response = %d %q, context=%v", response.StatusCode, body, client.Context())
	}
}

func TestConcurrentHTTPExchanges(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{"server.example.com"}, nil)
	clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	handler := spnego.SPNEGOContextAuthenticate(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}), func() gssapi.ContextMechanism {
		return negoex.New(negoex.NewPKU2UScheme(NewAcceptor(serverIdentity, anchors)))
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	client := spnego.NewNegotiatingClient(server.Client(), "host/server.example.com", func() gssapi.ContextMechanism {
		return negoex.New(negoex.NewPKU2UScheme(NewInitiator(clientIdentity, anchors)))
	})
	start := make(chan struct{})
	errors := make(chan error, 2)
	var wait sync.WaitGroup
	for index := 0; index < 2; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			request, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				errors <- err
				return
			}
			response, err := client.Do(request)
			if err == nil {
				response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					err = fmt.Errorf("HTTP status %d", response.StatusCode)
				}
			}
			errors <- err
		}()
	}
	close(start)
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

func establishSPNEGO(t *testing.T, initiator, acceptor *spnego.Negotiator) (gssapi.Context, gssapi.Context) {
	t.Helper()
	initiatorToken, initiatorContext, initiatorDone, err := initiator.InitSecContext("host/server.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	var acceptorContext gssapi.Context
	acceptorDone := false
	for turn := 0; turn < 10; turn++ {
		acceptorToken, context, done, err := acceptor.AcceptSecContext(initiatorToken)
		if err != nil {
			t.Fatalf("SPNEGO acceptor turn %d: %v", turn, err)
		}
		if context != nil {
			acceptorContext = context
		}
		acceptorDone = done
		if acceptorDone && initiatorDone && len(acceptorToken) == 0 {
			break
		}
		if len(acceptorToken) == 0 {
			t.Fatalf("SPNEGO acceptor stalled on turn %d", turn)
		}
		initiatorToken, context, done, err = initiator.InitSecContext("host/server.example.com", acceptorToken)
		if err != nil {
			t.Fatalf("SPNEGO initiator turn %d: %v", turn, err)
		}
		if context != nil {
			initiatorContext = context
		}
		initiatorDone = done
		if acceptorDone && initiatorDone && len(initiatorToken) == 0 {
			break
		}
		if len(initiatorToken) == 0 {
			t.Fatalf("SPNEGO initiator stalled on turn %d", turn)
		}
	}
	if !initiatorDone || !acceptorDone || initiatorContext == nil || acceptorContext == nil {
		t.Fatalf("SPNEGO did not complete: initiator=%t acceptor=%t", initiatorDone, acceptorDone)
	}
	return initiatorContext, acceptorContext
}

func assertProtectedMessage(t *testing.T, sender, receiver gssapi.Context, message []byte, confidential bool) {
	t.Helper()
	token, err := sender.Wrap(message, confidential)
	if err != nil {
		t.Fatal(err)
	}
	got, gotConfidential, err := receiver.Unwrap(token)
	if err != nil {
		t.Fatal(err)
	}
	if gotConfidential != confidential || string(got) != string(message) {
		t.Fatalf("unwrapped message = %q, confidential=%t", got, gotConfidential)
	}
	if _, _, err := receiver.Unwrap(token); err == nil {
		t.Fatal("accepted replayed wrap token")
	}
}

func newPKU2URoot(t *testing.T) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(100), Subject: pkix.Name{CommonName: "PKU2U Test Root"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func newPKU2ULeaf(t *testing.T, root *x509.Certificate, rootKey *ecdsa.PrivateKey, commonName string, dnsNames []string, san []byte) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames,
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature,
	}
	if san != nil {
		template.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAlternativeName, Value: san}}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}
