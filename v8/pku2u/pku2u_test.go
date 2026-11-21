package pku2u

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
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

const (
	testServiceHost   = "server.example.com"
	testServiceTarget = "host/" + testServiceHost
)

func requirePKU2UError[E error](t *testing.T, err error, prefix string) {
	t.Helper()
	_, hasCause := errors.AsType[E](err)
	if err == nil || !hasCause || !strings.HasPrefix(err.Error(), prefix) {
		var cause E
		t.Fatalf("want error prefixed by %q with cause %T, got %v", prefix, cause, err)
	}
}

func TestASExchangeIssuesSelfTicket(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{testServiceHost}, nil)
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

	requestDER, clientState, err := beginASExchange(clientSettings, testServiceTarget)
	if err != nil {
		t.Fatal(err)
	}
	requirePACOptOut(t, clientState.request.PAData)

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
	requireTicketNames(t, &ticket, &clientState.request.ReqBody)
}

func requirePACOptOut(t *testing.T, paData types.PADataSequence) {
	t.Helper()

	pacRequests := 0
	for _, pa := range paData {
		if pa.PADataType != patype.PA_PAC_REQUEST {
			continue
		}
		pacRequests++
		request, err := pa.GetKerbPAPACRequest()
		if err != nil || request.IncludePAC {
			t.Fatalf("PKU2U PAC request = %#v, %v", request, err)
		}
	}
	if pacRequests != 1 {
		t.Fatalf("PAC request count = %d, want 1", pacRequests)
	}
}

func requireTicketNames(t *testing.T, ticket *messages.Ticket, requested *messages.KDCReqBody) {
	t.Helper()

	if ticket.Realm != Realm || !ticket.SName.Equal(requested.SName) ||
		!ticket.DecryptedEncPart.CName.Equal(requested.CName) {
		t.Fatalf("issued ticket does not bind requested PKU2U names: %#v", *ticket)
	}
}

func newExchangeTestIdentities(t *testing.T) (*pkinit.Identity, *pkinit.Identity, *x509.CertPool) {
	t.Helper()
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{testServiceHost}, nil)
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
	return clientIdentity, serverIdentity, anchors
}

func TestASExchangeRejectsInvalidTarget(t *testing.T) {
	clientIdentity, serverIdentity, anchors := newExchangeTestIdentities(t)
	clientSettings := newSettings(clientIdentity, anchors, nil)
	serverSettings := newSettings(serverIdentity, anchors, nil)

	t.Run("wrong realm", func(t *testing.T) {
		encoded := makeASRequest(t, clientSettings, testServiceTarget)
		encoded = changeASRequest(t, encoded, func(request *messages.ASReq) { request.ReqBody.Realm = "EXAMPLE.COM" })
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted a PKU2U request for another realm")
		}
	})
	t.Run("wrong service certificate", func(t *testing.T) {
		encoded := makeASRequest(t, clientSettings, "host/other.example.com")
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted a request targeting another service")
		}
	})
	t.Run("missing acceptor identity", func(t *testing.T) {
		encoded := makeASRequest(t, clientSettings, testServiceTarget)
		acceptor := NewAcceptor(nil, anchors)
		output, context, done, err := acceptor.AcceptSecContext(encoded)
		if err == nil || !strings.Contains(err.Error(), "PKU2U acceptor identity is required") {
			t.Fatalf("want missing acceptor identity error, got %v", err)
		}
		if output != nil || context != nil || done || acceptor.step != 0 {
			t.Fatal("acceptor advanced without a local identity")
		}
	})
}

func makeASRequest(t *testing.T, clientSettings settings, target string) []byte {
	t.Helper()
	encoded, _, err := beginASExchange(clientSettings, target)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func changeASRequest(t *testing.T, encoded []byte, change func(*messages.ASReq)) []byte {
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

func TestASExchangeRejectsInvalidPACRequests(t *testing.T) {
	clientIdentity, serverIdentity, anchors := newExchangeTestIdentities(t)
	clientSettings := newSettings(clientIdentity, anchors, nil)
	serverSettings := newSettings(serverIdentity, anchors, nil)

	t.Run("malformed PAC request", func(t *testing.T) {
		encoded := makeASRequest(t, clientSettings, testServiceTarget)
		encoded = changeASRequest(t, encoded, func(request *messages.ASReq) {
			for index := range request.PAData {
				if request.PAData[index].PADataType == patype.PA_PAC_REQUEST {
					request.PAData[index].PADataValue = []byte{0x30}
				}
			}
		})
		_, _, err := acceptASExchange(encoded, serverSettings)
		requirePKU2UError[asn1.SyntaxError](t, err, "decode PKU2U PA-PAC-REQUEST:")
	})
	t.Run("missing PAC suppression", func(t *testing.T) {
		encoded := makeASRequest(t, clientSettings, testServiceTarget)
		encoded = changeASRequest(t, encoded, func(request *messages.ASReq) {
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
		encoded := makeASRequest(t, clientSettings, testServiceTarget)
		encoded = changeASRequest(t, encoded, func(request *messages.ASReq) {
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
		encoded := makeASRequest(t, clientSettings, testServiceTarget)
		encoded = changeASRequest(t, encoded, func(request *messages.ASReq) { enablePACRequest(t, request) })
		if _, _, err := acceptASExchange(encoded, serverSettings); err == nil {
			t.Fatal("accepted a request enabling PAC issuance")
		}
	})
}

func enablePACRequest(t *testing.T, request *messages.ASReq) {
	t.Helper()
	value, err := (&types.KerbPAPACRequest{IncludePAC: true}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	for index := range request.PAData {
		if request.PAData[index].PADataType == patype.PA_PAC_REQUEST {
			request.PAData[index].PADataValue = value
		}
	}
}

func TestASExchangeRejectsUntrustedPeers(t *testing.T) {
	clientIdentity, serverIdentity, anchors := newExchangeTestIdentities(t)
	serverSettings := newSettings(serverIdentity, anchors, nil)

	t.Run("untrusted initiator", func(t *testing.T) {
		otherRoot, otherRootKey := newPKU2URoot(t)
		certificate, key := newPKU2ULeaf(t, otherRoot, otherRootKey, "Mallory", nil, upnSAN(t, "mallory@example.com"))
		identity, err := pkinit.NewIdentity(certificate, []*x509.Certificate{otherRoot}, key, false)
		if err != nil {
			t.Fatal(err)
		}
		encoded := makeASRequest(t, newSettings(identity, anchors, nil), testServiceTarget)
		_, _, err = acceptASExchange(encoded, serverSettings)
		requirePKU2UError[x509.UnknownAuthorityError](t, err, "accept PKU2U PKINIT exchange:")
	})
	t.Run("untrusted acceptor", func(t *testing.T) {
		otherRoot, _ := newPKU2URoot(t)
		otherAnchors := x509.NewCertPool()
		otherAnchors.AddCert(otherRoot)
		clientSettings := newSettings(clientIdentity, otherAnchors, nil)
		encoded, state, err := beginASExchange(clientSettings, testServiceTarget)
		if err != nil {
			t.Fatal(err)
		}
		reply, _, err := acceptASExchange(encoded, serverSettings)
		if err != nil {
			t.Fatal(err)
		}
		_, err = finishASExchange(state, reply, clientSettings)
		requirePKU2UError[x509.UnknownAuthorityError](t, err, "process PKU2U PKINIT reply:")
	})
}

func TestEndToEndContext(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{testServiceHost}, nil)
	clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	initiator := NewInitiator(clientIdentity, anchors)
	acceptor := NewAcceptor(serverIdentity, anchors)

	initiatorMetadata, err := initiator.QueryMetadata(testServiceTarget, true)
	if err != nil {
		t.Fatal(err)
	}
	if ierr := acceptor.ExchangeMetadata(initiatorMetadata, false); ierr != nil {
		t.Fatal(ierr)
	}
	acceptorMetadata, err := acceptor.QueryMetadata("", false)
	if err != nil {
		t.Fatal(err)
	}
	if ierr := initiator.ExchangeMetadata(acceptorMetadata, true); ierr != nil {
		t.Fatal(ierr)
	}

	asReply := exchangeTestASMessages(t, initiator, acceptor)
	exchangeTestAPMessages(t, initiator, acceptor, asReply, clientCertificate)
}

func assertEstablishedContexts(
	t *testing.T, initiatorContext, acceptorContext gssapi.Context, clientCertificate *x509.Certificate,
) {
	t.Helper()

	initiatorKey, initiatorHasKey := initiatorContext.NegoExKey()
	acceptorKey, acceptorHasKey := acceptorContext.NegoExVerifyKey()
	if !initiatorHasKey || !acceptorHasKey || initiatorKey.KeyType != acceptorKey.KeyType ||
		string(initiatorKey.KeyValue) != string(acceptorKey.KeyValue) {
		t.Fatal("established contexts have different NEGOEX keys")
	}
	assertProtectedMessage(t, initiatorContext, acceptorContext, []byte("initiator secret"), true)
	assertProtectedMessage(t, acceptorContext, initiatorContext, []byte("acceptor visible"), false)
	mic, err := initiatorContext.GetMIC([]byte("bound message"))
	if err != nil {
		t.Fatal(err)
	}
	if ierr := acceptorContext.VerifyMIC([]byte("bound message"), mic); ierr != nil {
		t.Fatal(ierr)
	}
	assertAcceptorCredential(t, acceptorContext, clientCertificate)
}

func assertAcceptorCredential(t *testing.T, acceptorContext gssapi.Context, clientCertificate *x509.Certificate) {
	t.Helper()

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

func exchangeTestASMessages(t *testing.T, initiator *Initiator, acceptor *Acceptor) []byte {
	t.Helper()

	asRequest, _, done, err := initiator.InitSecContext(testServiceTarget, nil)
	if err != nil || done {
		t.Fatalf("init AS request: done=%t err=%v", done, err)
	}
	requirePKU2UError[asn1.SyntaxError](t,
		requireAcceptorRejection(t, acceptor, []byte{0x6a}), "decode PKU2U AS request:")
	asReply, _, done, err := acceptor.AcceptSecContext(asRequest)
	if err != nil || done {
		t.Fatalf("accept AS request: done=%t err=%v", done, err)
	}
	return asReply
}

func exchangeTestAPMessages(
	t *testing.T, initiator *Initiator, acceptor *Acceptor, asReply []byte, clientCertificate *x509.Certificate,
) {
	t.Helper()

	_, _, _, decodeErr := initiator.InitSecContext(testServiceTarget, []byte{0x6b})
	requirePKU2UError[asn1.SyntaxError](t, decodeErr, "decode PKU2U AS reply:")
	apRequest, _, done, err := initiator.InitSecContext(testServiceTarget, asReply)
	if err != nil || done {
		t.Fatalf("init AP request: done=%t err=%v", done, err)
	}
	requirePKU2UError[asn1.SyntaxError](t,
		requireAcceptorRejection(t, acceptor, []byte{0x6e}), "decode PKU2U AP request:")
	apReply, acceptorContext, done, err := acceptor.AcceptSecContext(apRequest)
	if err != nil || !done || acceptorContext == nil {
		t.Fatalf("accept AP request: done=%t err=%v", done, err)
	}
	requireAcceptorEstablished(t, acceptor, apRequest)
	_, _, _, decodeErr = initiator.InitSecContext(testServiceTarget, []byte{0x6f})
	requirePKU2UError[asn1.SyntaxError](t, decodeErr, "decode PKU2U AP reply:")
	output, initiatorContext, done, err := initiator.InitSecContext(testServiceTarget, apReply)
	if err != nil || !done || initiatorContext == nil || len(output) != 0 {
		t.Fatalf("init AP reply: output=%x done=%t err=%v", output, done, err)
	}
	assertEstablishedContexts(t, initiatorContext, acceptorContext, clientCertificate)
}

func requireAcceptorRejection(t *testing.T, acceptor *Acceptor, input []byte) error {
	t.Helper()

	output, context, done, err := acceptor.AcceptSecContext(input)
	if output != nil || context != nil || done {
		t.Fatal("acceptor rejection returned output, a context, or completion")
	}
	return err
}

func requireAcceptorEstablished(t *testing.T, acceptor *Acceptor, input []byte) {
	t.Helper()

	err := requireAcceptorRejection(t, acceptor, input)
	if err == nil || err.Error() != "PKU2U acceptor context is already established" {
		t.Fatalf("want already established error, got %v", err)
	}
}

type apExchangeFixture struct {
	clientName     types.PrincipalName
	clientResult   *asResult
	serverSettings settings
	serverState    *asResult
}

func newAPExchangeFixture(t *testing.T) apExchangeFixture {
	t.Helper()
	clientIdentity, serverIdentity, anchors := newExchangeTestIdentities(t)
	clientSettings := newSettings(clientIdentity, anchors, nil)
	serverSettings := newSettings(serverIdentity, anchors, nil)
	asRequest, clientState, err := beginASExchange(clientSettings, testServiceTarget)
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
	return apExchangeFixture{
		clientName:     clientState.request.ReqBody.CName,
		clientResult:   clientResult,
		serverSettings: serverSettings,
		serverState:    serverState,
	}
}

func (f apExchangeFixture) makeRequest(t *testing.T, mutate func(*types.Authenticator)) messages.APReq {
	t.Helper()
	authenticator, err := types.NewAuthenticator(Realm, f.clientName)
	if err != nil {
		t.Fatal(err)
	}
	checksum, err := gssapi.NewAuthenticatorChecksum(
		nil, gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf,
	).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
	key := f.clientResult.sessionKey
	if subkeyErr := authenticator.GenerateSeqNumberAndSubKey(key.KeyType, len(key.KeyValue)); subkeyErr != nil {
		t.Fatal(subkeyErr)
	}
	if mutate != nil {
		mutate(&authenticator)
	}
	request, err := messages.NewAPReq(f.clientResult.ticket, key, authenticator)
	if err != nil {
		t.Fatal(err)
	}
	types.SetFlag(&request.APOptions, flags.APOptionMutualRequired)
	return request
}

func (f apExchangeFixture) accept(request messages.APReq) error {
	encoded, err := request.Marshal()
	if err != nil {
		return err
	}
	acceptor := &Acceptor{
		settings: f.serverSettings, asResult: f.serverState, metadata: nil, metadataPresent: false, step: 0,
	}
	_, _, err = acceptor.acceptAPRequest(encoded)
	return err
}

func TestAPExchangeRejectsMissingProtection(t *testing.T) {
	fixture := newAPExchangeFixture(t)
	t.Run("mutual authentication missing", func(t *testing.T) {
		request := fixture.makeRequest(t, nil)
		types.UnsetFlag(&request.APOptions, flags.APOptionMutualRequired)
		if err := fixture.accept(request); err == nil {
			t.Fatal("accepted AP request without mutual authentication")
		}
	})
	t.Run("GSS checksum missing", func(t *testing.T) {
		request := fixture.makeRequest(t, func(authenticator *types.Authenticator) {
			authenticator.Cksum = types.Checksum{CksumType: 0, Checksum: nil}
		})
		if err := fixture.accept(request); err == nil {
			t.Fatal("accepted AP request without GSS checksum")
		}
	})
	t.Run("integrity flag missing", func(t *testing.T) {
		request := fixture.makeRequest(t, func(authenticator *types.Authenticator) {
			checksum, err := gssapi.NewAuthenticatorChecksum(nil, gssapi.ContextFlagMutual).Marshal()
			if err != nil {
				t.Fatal(err)
			}
			authenticator.Cksum = types.Checksum{CksumType: chksumtype.GSSAPI, Checksum: checksum}
		})
		if err := fixture.accept(request); err == nil {
			t.Fatal("accepted AP request without integrity protection")
		}
	})
}

func TestAPExchangeRejectsInvalidAuthenticatorFields(t *testing.T) {
	fixture := newAPExchangeFixture(t)
	t.Run("wrong client identity", func(t *testing.T) {
		request := fixture.makeRequest(t, func(authenticator *types.Authenticator) {
			authenticator.CName = types.NewPrincipalName(1, "mallory@example.com")
		})
		if err := fixture.accept(request); err == nil {
			t.Fatal("accepted authenticator for another client")
		}
	})
	t.Run("stale authenticator", func(t *testing.T) {
		request := fixture.makeRequest(t, func(authenticator *types.Authenticator) {
			authenticator.CTime = time.Now().UTC().Add(-10 * time.Minute)
		})
		if err := fixture.accept(request); err == nil {
			t.Fatal("accepted stale authenticator")
		}
	})
	t.Run("invalid microseconds", func(t *testing.T) {
		request := fixture.makeRequest(t, func(authenticator *types.Authenticator) { authenticator.Cusec = 1000000 })
		if err := fixture.accept(request); err == nil {
			t.Fatal("accepted invalid authenticator microseconds")
		}
	})
	t.Run("missing subkey", func(t *testing.T) {
		request := fixture.makeRequest(t, func(authenticator *types.Authenticator) {
			authenticator.SubKey = types.EncryptionKey{KeyType: 0, KeyValue: nil}
		})
		if err := fixture.accept(request); err == nil {
			t.Fatal("accepted authenticator without a subkey")
		}
	})
}

func TestAPExchangeRejectsTamperedMessages(t *testing.T) {
	fixture := newAPExchangeFixture(t)
	t.Run("RC4 subkey", func(t *testing.T) {
		request := fixture.makeRequest(t, func(authenticator *types.Authenticator) {
			authenticator.SubKey = types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: make([]byte, 16)}
		})
		if err := fixture.accept(request); err == nil {
			t.Fatal("accepted RC4 authenticator subkey")
		}
	})
	t.Run("tampered authenticator", func(t *testing.T) {
		request := fixture.makeRequest(t, nil)
		request.EncryptedAuthenticator.Cipher[len(request.EncryptedAuthenticator.Cipher)-1] ^= 1
		err := fixture.accept(request)
		if err == nil || !strings.HasPrefix(err.Error(), "decrypt PKU2U authenticator:") || errors.Unwrap(err) == nil {
			t.Fatalf("want contextual authenticator decryption error, got %v", err)
		}
	})
	t.Run("tampered ticket", func(t *testing.T) {
		request := fixture.makeRequest(t, nil)
		request.Ticket.EncPart.Cipher[len(request.Ticket.EncPart.Cipher)-1] ^= 1
		err := fixture.accept(request)
		if err == nil || !strings.HasPrefix(err.Error(), "decrypt PKU2U ticket:") || errors.Unwrap(err) == nil {
			t.Fatalf("want contextual ticket decryption error, got %v", err)
		}
	})
}

func TestEndToEndOverNegoEx(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{testServiceHost}, nil)
	clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
	serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
	anchors := x509.NewCertPool()
	anchors.AddCert(root)
	initiator, err := negoex.NewInitiator(
		testServiceTarget,
		negoex.NewPKU2UScheme(NewInitiator(clientIdentity, anchors)),
	)
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := negoex.NewAcceptor(negoex.NewPKU2UScheme(NewAcceptor(serverIdentity, anchors)))
	if err != nil {
		t.Fatal(err)
	}

	var token []byte
	for _, step := range [...]struct {
		stage        string
		conversation *negoex.Conversation
		wantDone     bool
	}{
		{stage: "initiator AS", conversation: initiator, wantDone: false},
		{stage: "acceptor AS", conversation: acceptor, wantDone: false},
		{stage: "initiator AP", conversation: initiator, wantDone: false},
		{stage: "acceptor AP", conversation: acceptor, wantDone: false},
		{stage: "initiator verify", conversation: initiator, wantDone: true},
	} {
		output, done, stepErr := step.conversation.Step(token)
		if stepErr != nil || done != step.wantDone {
			t.Fatalf("%s: done=%t err=%v", step.stage, done, stepErr)
		}
		token = output
	}

	output, done, err := acceptor.Step(token)
	if err != nil || !done || len(output) != 0 {
		t.Fatalf("acceptor verify: output=%x done=%t err=%v", output, done, err)
	}
	assertProtectedMessage(t, initiator.Context(), acceptor.Context(), []byte("negoex secret"), true)
}

func TestEndToEndOverSPNEGO(t *testing.T) {
	for _, test := range []struct {
		name string
		wrap func(negoex.PKU2UMechanism) gssapi.ContextMechanism
	}{
		{name: "standalone", wrap: func(mechanism negoex.PKU2UMechanism) gssapi.ContextMechanism {
			return mechanism
		}},
		{name: "NEGOEX", wrap: func(mechanism negoex.PKU2UMechanism) gssapi.ContextMechanism {
			return negoex.New(negoex.NewPKU2UScheme(mechanism))
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			root, rootKey := newPKU2URoot(t)
			clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
			serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{testServiceHost}, nil)
			clientIdentity, _ := pkinit.NewIdentity(clientCertificate, []*x509.Certificate{root}, clientKey, false)
			serverIdentity, _ := pkinit.NewIdentity(serverCertificate, []*x509.Certificate{root}, serverKey, false)
			anchors := x509.NewCertPool()
			anchors.AddCert(root)
			initiator := spnego.NewNegotiator(test.wrap(NewInitiator(clientIdentity, anchors)))
			acceptor := spnego.NewNegotiator(test.wrap(NewAcceptor(serverIdentity, anchors)))
			exchange := establishSPNEGO(t, initiator, acceptor)
			assertProtectedMessage(t, exchange.initiatorContext, exchange.acceptorContext, []byte("spnego secret"), true)
		})
	}
}

func TestEndToEndHTTP(t *testing.T) {
	root, rootKey := newPKU2URoot(t)
	clientCertificate, clientKey := newPKU2ULeaf(t, root, rootKey, "Alice", nil, upnSAN(t, "alice@example.com"))
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{testServiceHost}, nil)
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
		_, _ = fmt.Fprintf(writer, "%s:%s", certificateIdentity.UPN, body)
	}), func() gssapi.ContextMechanism {
		return negoex.New(negoex.NewPKU2UScheme(NewAcceptor(serverIdentity, anchors)))
	})
	server := httptest.NewServer(handler)
	defer server.Close()
	client := spnego.NewNegotiatingClient(server.Client(), testServiceTarget, func() gssapi.ContextMechanism {
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
	defer response.Body.Close() //nolint:errcheck // test response cleanup is intentionally best effort
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
	serverCertificate, serverKey := newPKU2ULeaf(t, root, rootKey, "Server", []string{testServiceHost}, nil)
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
	client := spnego.NewNegotiatingClient(server.Client(), testServiceTarget, func() gssapi.ContextMechanism {
		return negoex.New(negoex.NewPKU2UScheme(NewInitiator(clientIdentity, anchors)))
	})
	const workerCount = 2
	start := make(chan struct{})
	errors := make(chan error, workerCount)
	var workers sync.WaitGroup
	for range workerCount {
		workers.Go(func() {
			<-start
			request, err := http.NewRequest(http.MethodGet, server.URL, nil)
			if err != nil {
				errors <- err
				return
			}
			response, err := client.Do(request)
			if err == nil {
				_ = response.Body.Close()
				if response.StatusCode != http.StatusNoContent {
					err = fmt.Errorf("HTTP status %d", response.StatusCode)
				}
			}
			errors <- err
		})
	}
	close(start)
	workers.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
}

type spnegoTestExchange struct {
	token            []byte
	initiatorContext gssapi.Context
	acceptorContext  gssapi.Context
	initiatorDone    bool
	acceptorDone     bool
}

func establishSPNEGO(t *testing.T, initiator, acceptor *spnego.Negotiator) spnegoTestExchange {
	t.Helper()
	var exchange spnegoTestExchange
	var err error
	exchange.token, exchange.initiatorContext, exchange.initiatorDone, err = initiator.InitSecContext(
		testServiceTarget, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	const maxTurns = 10
	for turn := range maxTurns {
		if exchange.runTurn(t, turn, initiator, acceptor) {
			break
		}
	}
	hasContexts := exchange.initiatorContext != nil && exchange.acceptorContext != nil
	if !exchange.initiatorDone || !exchange.acceptorDone || !hasContexts {
		t.Fatalf("SPNEGO did not complete: initiator=%t acceptor=%t", exchange.initiatorDone, exchange.acceptorDone)
	}

	return exchange
}

func (e *spnegoTestExchange) runTurn(
	t *testing.T,
	turn int,
	initiator, acceptor *spnego.Negotiator,
) bool {
	t.Helper()
	output, established, done, err := acceptor.AcceptSecContext(e.token)
	if err != nil {
		t.Fatalf("SPNEGO acceptor turn %d: %v", turn, err)
	}
	if established != nil {
		e.acceptorContext = established
	}
	e.acceptorDone = done
	e.token = output
	if e.checkTurnOutput(t, turn, "acceptor") {
		return true
	}

	output, established, done, err = initiator.InitSecContext(testServiceTarget, e.token)
	if err != nil {
		t.Fatalf("SPNEGO initiator turn %d: %v", turn, err)
	}
	if established != nil {
		e.initiatorContext = established
	}
	e.initiatorDone = done
	e.token = output
	return e.checkTurnOutput(t, turn, "initiator")
}

func (e *spnegoTestExchange) checkTurnOutput(t *testing.T, turn int, peer string) bool {
	t.Helper()
	if len(e.token) != 0 {
		return false
	}
	if !e.initiatorDone || !e.acceptorDone {
		t.Fatalf("SPNEGO %s stalled on turn %d", peer, turn)
	}
	return true
}

func assertProtectedMessage(t *testing.T, sender, receiver gssapi.Context, message []byte, confidential bool) {
	t.Helper()
	if sender == nil || receiver == nil {
		t.Fatal("protected-message context is nil")
	}
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
	var template x509.Certificate
	template.SerialNumber = big.NewInt(100)
	template.Subject.CommonName = "PKU2U Test Root"
	template.NotBefore = now.Add(-time.Hour)
	template.NotAfter = now.Add(time.Hour)
	template.IsCA = true
	template.BasicConstraintsValid = true
	template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}

func newPKU2ULeaf(
	t *testing.T,
	root *x509.Certificate,
	rootKey *ecdsa.PrivateKey,
	commonName string,
	dnsNames []string,
	san []byte,
) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	var template x509.Certificate
	template.SerialNumber = big.NewInt(now.UnixNano())
	template.Subject.CommonName = commonName
	template.DNSNames = dnsNames
	template.NotBefore = now.Add(-time.Hour)
	template.NotAfter = now.Add(time.Hour)
	template.KeyUsage = x509.KeyUsageDigitalSignature
	if san != nil {
		template.ExtraExtensions = []pkix.Extension{{Id: oidSubjectAlternativeName, Critical: false, Value: san}}
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, root, &key.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return certificate, key
}
