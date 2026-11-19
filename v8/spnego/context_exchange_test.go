package spnego

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/krberror"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

var contextExchangeID atomic.Uint64

func mustSPNEGOTestType[T any](t *testing.T, value any) T {
	t.Helper()
	result, ok := value.(T)
	if !ok {
		t.Fatalf("unexpected type %T", value)
	}
	return result
}

func TestSPNEGOInitiatorSetupRetainsCredentialErrors(t *testing.T) {
	t.Parallel()

	cl := client.NewWithPassword("", "EXAMPLE.COM", "", config.New())
	s := SPNEGOClient(cl, "HTTP/server.example.com")
	err := s.AcquireCred()
	require.ErrorContains(t, err, "acquire SPNEGO initiator credentials:")
	require.ErrorContains(t, err, "client does not have a username")

	token, err := s.InitSecContext()
	require.ErrorContains(t, err, "obtain SPNEGO service ticket:")
	require.ErrorContains(t, err, "client does not have a username")
	require.Equal(t, new(SPNEGOToken), token)
	require.Nil(t, s.SecurityContext())
}

func TestSPNEGOSecurityContextRetainsKeyError(t *testing.T) {
	t.Parallel()

	s := new(SPNEGO)
	s.contextKey.KeyType = etypeID.AES128_CTS_HMAC_SHA1_96
	err := s.completeSecurityContext(true)
	require.ErrorContains(t, err, "create SPNEGO security context:")
	require.ErrorContains(t, err, "invalid key length")
	require.Nil(t, s.SecurityContext())
}

func TestInitiatorAPRepRetainsSubkeyFailureWithoutTicketKey(t *testing.T) {
	t.Parallel()

	s := new(SPNEGO)
	key, err := s.verifyInitiatorAPRep(new(messages.APRep))
	require.Empty(t, key.KeyValue)
	require.ErrorContains(t, err, "verify AP_REP with authenticator subkey:")
	require.ErrorAs(t, err, new(krberror.Krberror))
}

func TestMutualContextExchange(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg})
	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	require.NotNil(t, acceptor.ResponseToken())

	authenticated, _, status = initiator.ContinueSecContext(acceptor.ResponseToken())
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	require.NotEmpty(t, initiator.contextKey.KeyValue)
	require.Equal(t, acceptor.contextKey, initiator.contextKey)
	require.Equal(t, acceptor.sequenceNumber, initiator.sequenceNumber)
	require.NotNil(t, initiator.SecurityContext())
	require.NotNil(t, acceptor.SecurityContext())

	request, err := initiator.SecurityContext().Wrap([]byte("request"), true)
	require.NoError(t, err)
	message, confidential, err := acceptor.SecurityContext().Unwrap(request)
	require.NoError(t, err)
	require.True(t, confidential)
	require.Equal(t, []byte("request"), message)

	response, err := acceptor.SecurityContext().Wrap([]byte("response"), true)
	require.NoError(t, err)
	message, confidential, err = initiator.SecurityContext().Unwrap(response)
	require.NoError(t, err)
	require.True(t, confidential)
	require.Equal(t, []byte("response"), message)
}

func TestMutualContextExchangeAcceptsTicketKeyAPRep(t *testing.T) {
	initiator, _, _ := newContextExchange(t, []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg, gssapi.ContextFlagConf})
	acceptorSubkey := types.EncryptionKey{
		KeyType: 18, KeyValue: []byte("0123456789abcdef0123456789abcdef"),
	}
	const acceptorSequence = 42
	reply, err := messages.NewAPRep(messages.EncAPRepPart{
		CTime: initiator.authenticator.CTime, Cusec: initiator.authenticator.Cusec,
		Subkey: acceptorSubkey, SequenceNumber: acceptorSequence,
	}, initiator.ticketKey)
	require.NoError(t, err)
	replyToken := NewKRB5TokenAPREP(reply, false)
	replyBytes, err := replyToken.Marshal()
	require.NoError(t, err)
	response := &SPNEGOToken{Resp: true, NegTokenResp: NegTokenResp{
		NegState:      asn1.Enumerated(NegStateAcceptCompleted),
		SupportedMech: initiator.offeredMechTypes[0], ResponseToken: replyBytes,
	}}
	authenticated, _, status := initiator.ContinueSecContext(response)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	require.Equal(t, acceptorSubkey, initiator.contextKey)

	initiatorSequence, err := sequenceNumberUint64(initiator.authenticator.SeqNumber)
	require.NoError(t, err)
	acceptorContext, err := gssapi.NewSecurityContext(
		acceptorSubkey, false, acceptorSequence, initiatorSequence, true,
	)
	require.NoError(t, err)
	request, err := initiator.SecurityContext().Wrap([]byte("request"), true)
	require.NoError(t, err)
	message, confidential, err := acceptorContext.Unwrap(request)
	require.NoError(t, err)
	require.True(t, confidential)
	require.Equal(t, []byte("request"), message)
	responseToken, err := acceptorContext.Wrap([]byte("response"), true)
	require.NoError(t, err)
	message, confidential, err = initiator.SecurityContext().Unwrap(responseToken)
	require.NoError(t, err)
	require.True(t, confidential)
	require.Equal(t, []byte("response"), message)
}

func TestSecurityContextUnavailableBeforeCompletion(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg})
	require.Nil(t, initiator.SecurityContext())
	require.Nil(t, acceptor.SecurityContext())

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	require.NotNil(t, acceptor.SecurityContext())
	require.Nil(t, initiator.SecurityContext())
}

func TestNonMutualInitiatorContextAvailableAfterInitialToken(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagInteg})
	require.NotNil(t, initiator.SecurityContext())
	require.Nil(t, acceptor.SecurityContext())

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	requireSecurityContextsExchange(t, initiator, acceptor)
}

func TestHTTPClientRejectsInvalidMutualContextType(t *testing.T) {
	request, err := http.NewRequest(http.MethodGet, "http://host.test.gokrb5", nil)
	require.NoError(t, err)
	_, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagMutual})
	_, _, status := acceptor.AcceptSecContext(initial)
	require.Equal(t, gssapi.StatusComplete, status.Code)
	responseBytes, err := acceptor.ResponseToken().Marshal()
	require.NoError(t, err)
	response := &http.Response{Header: make(http.Header), Body: http.NoBody}
	response.Header.Set(HTTPHeaderAuthResponse, "Negotiate "+base64.StdEncoding.EncodeToString(responseBytes))

	httpClient := NewClientWithOptions(nil, nil, "HTTP/host.test.gokrb5", KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagMutual},
	})
	httpClient.contexts.Store(request, "not a SPNEGO context")
	err = httpClient.verifyMutualResponse(request, response)
	require.Error(t, err)
	require.Contains(t, err.Error(), "invalid type")
}

func TestHTTPClientPublishesMutualSecurityContext(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg})
	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.True(t, authenticated, status.Error())

	responseBytes, err := acceptor.ResponseToken().Marshal()
	require.NoError(t, err)
	request, err := http.NewRequest(http.MethodPost, "http://host.test.gokrb5/wsman", nil)
	require.NoError(t, err)
	response := &http.Response{Header: make(http.Header), Body: http.NoBody}
	response.Header.Set(HTTPHeaderAuthResponse, "Negotiate "+base64.StdEncoding.EncodeToString(responseBytes))

	httpClient := NewClientWithOptions(nil, nil, "HTTP/host.test.gokrb5", KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg},
	})
	httpClient.contexts.Store(request, initiator)
	require.NoError(t, httpClient.verifyMutualResponse(request, response))
	require.Same(t, initiator.SecurityContext(), httpClient.Context())

	wrapped, err := httpClient.Context().Wrap([]byte("request"), true)
	require.NoError(t, err)
	message, confidential, err := acceptor.SecurityContext().Unwrap(wrapped)
	require.NoError(t, err)
	require.True(t, confidential)
	require.Equal(t, []byte("request"), message)
}

func TestMutualContextExchangeWithMechListMIC(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg})
	initialToken := mustSPNEGOTestType[*SPNEGOToken](t, initial)
	initialToken.NegTokenInit.MechTypes = []asn1.ObjectIdentifier{
		gssapi.OIDMSLegacyKRB5.OID(),
		gssapi.OIDKRB5.OID(),
	}
	sequenceNumber, err := sequenceNumberUint64(initiator.authenticator.SeqNumber)
	require.NoError(t, err)
	require.NoError(t, initialToken.NegTokenInit.SetMechListMIC(initiator.replyKey, sequenceNumber))
	initiator.offeredMechTypes = append([]asn1.ObjectIdentifier(nil), initialToken.NegTokenInit.MechTypes...)
	initiator.requireMechMIC = true

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	response := mustSPNEGOTestType[*SPNEGOToken](t, acceptor.ResponseToken())
	require.NotEmpty(t, response.NegTokenResp.MechListMIC)
	require.Equal(t, gssapi.OIDMSLegacyKRB5.OID(), response.NegTokenResp.SupportedMech)

	authenticated, _, status = initiator.ContinueSecContext(response)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
}

func TestSequenceNumberRange(t *testing.T) {
	for _, value := range []int64{-1, 0x40000000} {
		if _, err := sequenceNumberUint64(value); err == nil {
			t.Fatalf("sequence number %d was accepted", value)
		}
	}
	for _, value := range []int64{0, 0x3fffffff} {
		if _, err := sequenceNumberUint64(value); err != nil {
			t.Fatalf("sequence number %d rejected: %v", value, err)
		}
	}
}

func TestContextExchangeRejectsTamperedMechList(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagInteg})
	initialToken := mustSPNEGOTestType[*SPNEGOToken](t, initial)
	initialToken.NegTokenInit.MechTypes = []asn1.ObjectIdentifier{
		gssapi.OIDMSLegacyKRB5.OID(),
		gssapi.OIDKRB5.OID(),
	}
	sequenceNumber, err := sequenceNumberUint64(initiator.authenticator.SeqNumber)
	require.NoError(t, err)
	require.NoError(t, initialToken.NegTokenInit.SetMechListMIC(initiator.replyKey, sequenceNumber))
	initialToken.NegTokenInit.MechTypes[0] = asn1.ObjectIdentifier{1, 2, 3, 4}

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusBadMIC, status.Code)
}

func TestLegacyOIDFirstContextExchange(t *testing.T) {
	initiator, acceptor, initial := newContextExchangeWithOptions(t, KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg},
		MechTypes: []asn1.ObjectIdentifier{
			gssapi.OIDMSLegacyKRB5.OID(),
			gssapi.OIDKRB5.OID(),
		},
	})
	initialToken := mustSPNEGOTestType[*SPNEGOToken](t, initial)
	require.Equal(t, gssapi.OIDMSLegacyKRB5.OID(), initialToken.NegTokenInit.MechTypes[0])
	mechanismToken := mustSPNEGOTestType[*KRB5Token](t, initialToken.NegTokenInit.mechToken)
	require.Equal(t, gssapi.OIDMSLegacyKRB5.OID(), mechanismToken.OID)
	require.Empty(t, initialToken.NegTokenInit.MechListMIC)

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	authenticated, _, status = initiator.ContinueSecContext(acceptor.ResponseToken())
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
}

func TestRequestMICContextExchange(t *testing.T) {
	initiator, acceptor, initial := newContextExchangeWithPreferences(t, KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg},
		MechTypes: []asn1.ObjectIdentifier{
			gssapi.OIDMSLegacyKRB5.OID(),
			gssapi.OIDKRB5.OID(),
		},
	}, []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID(), gssapi.OIDMSLegacyKRB5.OID()})

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusContinueNeeded, status.Code)
	requestMIC := mustSPNEGOTestType[*SPNEGOToken](t, acceptor.ResponseToken())
	require.Equal(t, NegStateRequestMIC, requestMIC.NegTokenResp.State())
	require.Equal(t, gssapi.OIDKRB5.OID(), requestMIC.NegTokenResp.SupportedMech)
	require.NotEmpty(t, requestMIC.NegTokenResp.MechListMIC)

	authenticated, _, status = initiator.ContinueSecContext(requestMIC)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusContinueNeeded, status.Code)
	initiatorMIC := initiator.ResponseToken()
	require.NotNil(t, initiatorMIC)
	require.NotNil(t, initiator.SecurityContext())
	require.Nil(t, acceptor.SecurityContext())

	authenticated, _, status = acceptor.AcceptSecContext(initiatorMIC)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	requireSecurityContextsExchange(t, initiator, acceptor)
}

func TestRequestMICContextExchangeWithoutMutualAuth(t *testing.T) {
	initiator, acceptor, initial := newContextExchangeWithPreferences(t, KRB5TokenAPREQOptions{
		GSSAPIFlags: []int{gssapi.ContextFlagInteg},
		MechTypes: []asn1.ObjectIdentifier{
			gssapi.OIDMSLegacyKRB5.OID(),
			gssapi.OIDKRB5.OID(),
		},
	}, []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()})

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusContinueNeeded, status.Code)
	requestMIC := mustSPNEGOTestType[*SPNEGOToken](t, acceptor.ResponseToken())
	require.Empty(t, requestMIC.NegTokenResp.ResponseToken)

	authenticated, _, status = initiator.ContinueSecContext(requestMIC)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusContinueNeeded, status.Code)
	authenticated, _, status = acceptor.AcceptSecContext(initiator.ResponseToken())
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	requireSecurityContextsExchange(t, initiator, acceptor)
}

func TestRequestMICContextExchangeRejectsTampering(t *testing.T) {
	tests := map[string]func(*SPNEGOToken){
		"acceptor MIC": func(token *SPNEGOToken) {
			token.NegTokenResp.MechListMIC[len(token.NegTokenResp.MechListMIC)-1] ^= 0xff
		},
		"initiator MIC": nil,
	}
	for name, tamperResponse := range tests {
		t.Run(name, func(t *testing.T) {
			initiator, acceptor, initial := newContextExchangeWithPreferences(t, KRB5TokenAPREQOptions{
				GSSAPIFlags: []int{gssapi.ContextFlagMutual, gssapi.ContextFlagInteg},
				MechTypes: []asn1.ObjectIdentifier{
					gssapi.OIDMSLegacyKRB5.OID(),
					gssapi.OIDKRB5.OID(),
				},
			}, []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()})
			authenticated, _, status := acceptor.AcceptSecContext(initial)
			require.False(t, authenticated)
			require.Equal(t, gssapi.StatusContinueNeeded, status.Code)
			requestMIC := mustSPNEGOTestType[*SPNEGOToken](t, acceptor.ResponseToken())

			if tamperResponse != nil {
				tamperResponse(requestMIC)
				authenticated, _, status = initiator.ContinueSecContext(requestMIC)
				require.False(t, authenticated)
				require.Equal(t, gssapi.StatusBadMIC, status.Code)
				return
			}

			authenticated, _, status = initiator.ContinueSecContext(requestMIC)
			require.False(t, authenticated)
			require.Equal(t, gssapi.StatusContinueNeeded, status.Code)
			initiatorMIC := mustSPNEGOTestType[*SPNEGOToken](t, initiator.ResponseToken())
			initiatorMIC.NegTokenResp.MechListMIC[len(initiatorMIC.NegTokenResp.MechListMIC)-1] ^= 0xff
			authenticated, _, status = acceptor.AcceptSecContext(initiatorMIC)
			require.False(t, authenticated)
			require.Equal(t, gssapi.StatusBadMIC, status.Code)
		})
	}
}

func TestDCEContextExchange(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagDCEStyle, gssapi.ContextFlagInteg})
	initialKRB, ok := initial.(*KRB5Token)
	require.True(t, ok)
	require.True(t, initialKRB.raw)

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusContinueNeeded, status.Code)
	require.Nil(t, initiator.SecurityContext())
	require.Nil(t, acceptor.SecurityContext())
	require.NotNil(t, acceptor.ResponseToken())

	authenticated, _, status = initiator.ContinueSecContext(acceptor.ResponseToken())
	require.True(t, authenticated)
	require.Equal(t, gssapi.StatusComplete, status.Code)
	require.NotNil(t, initiator.SecurityContext())
	require.Nil(t, acceptor.SecurityContext())
	require.NotNil(t, initiator.ResponseToken())

	authenticated, _, status = acceptor.ContinueSecContext(initiator.ResponseToken())
	require.True(t, authenticated)
	require.Equal(t, gssapi.StatusComplete, status.Code)
	requireSecurityContextsExchange(t, initiator, acceptor)
}

func requireSecurityContextsExchange(t *testing.T, initiator, acceptor *SPNEGO) {
	t.Helper()
	require.NotNil(t, initiator.SecurityContext())
	require.NotNil(t, acceptor.SecurityContext())
	require.Equal(t, initiator.contextSend, acceptor.contextReceive)
	require.Equal(t, acceptor.contextSend, initiator.contextReceive)
	require.Equal(t, initiator.acceptorSubkey, acceptor.acceptorSubkey)
	request, err := initiator.SecurityContext().Wrap([]byte("request"), true)
	require.NoError(t, err)
	message, confidential, err := acceptor.SecurityContext().Unwrap(request)
	require.NoError(t, err)
	require.True(t, confidential)
	require.Equal(t, []byte("request"), message)
	response, err := acceptor.SecurityContext().Wrap([]byte("response"), true)
	require.NoError(t, err)
	message, confidential, err = initiator.SecurityContext().Unwrap(response)
	require.NoError(t, err)
	require.True(t, confidential)
	require.Equal(t, []byte("response"), message)
}

func TestDCEContextExchangeRejectsWrongFinalSequence(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagDCEStyle, gssapi.ContextFlagInteg})
	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusContinueNeeded, status.Code)

	authenticated, _, status = initiator.ContinueSecContext(acceptor.ResponseToken())
	require.True(t, authenticated)
	require.Equal(t, gssapi.StatusComplete, status.Code)

	wrongFinal, err := messages.NewAPRep(messages.EncAPRepPart{
		CTime:          time.Now().UTC(),
		Cusec:          microseconds(time.Now().UTC()),
		SequenceNumber: acceptor.sequenceNumber + 1,
	}, acceptor.contextKey)
	require.NoError(t, err)
	wrongToken := NewKRB5TokenAPREP(wrongFinal, true)
	authenticated, _, status = acceptor.ContinueSecContext(&wrongToken)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusDefectiveToken, status.Code)
}

func TestSPNEGOInvalidStateTransitions(t *testing.T) {
	clientMechanism := SPNEGOClient(client.NewWithPassword("alice", "EXAMPLE.ORG", "password", config.New()), "HTTP/server")
	require.True(t, clientMechanism.OID().Equal(gssapi.OIDSPNEGO.OID()))

	acceptor := SPNEGOService(keytab.New())
	authenticated, _, status := acceptor.AcceptSecContext(&SPNEGOToken{Init: true})
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusDefectiveToken, status.Code)
	authenticated, _, status = acceptor.AcceptSecContext(&KRB5Token{})
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusDefectiveToken, status.Code)

	clientMechanism.offeredMechTypes = []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}
	clientMechanism.initiatorOptions.GSSAPIFlags = []int{gssapi.ContextFlagMutual}
	tests := []struct {
		name  string
		token gssapi.ContextToken
		code  int
	}{
		{"not response", &SPNEGOToken{Init: true}, gssapi.StatusDefectiveToken},
		{"rejected", &SPNEGOToken{Resp: true, NegTokenResp: NegTokenResp{NegState: asn1.Enumerated(NegStateReject)}}, gssapi.StatusBadMech},
		{"unoffered mechanism", &SPNEGOToken{Resp: true, NegTokenResp: NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptCompleted), SupportedMech: gssapi.OIDNegoEx.OID()}}, gssapi.StatusBadMech},
		{"missing AP reply", &SPNEGOToken{Resp: true, NegTokenResp: NegTokenResp{NegState: asn1.Enumerated(NegStateAcceptCompleted), SupportedMech: gssapi.OIDKRB5.OID()}}, gssapi.StatusDefectiveToken},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotAuthenticated, _, gotStatus := clientMechanism.ContinueSecContext(test.token)
			require.False(t, gotAuthenticated)
			require.Equal(t, test.code, gotStatus.Code)
		})
	}

	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	reply, err := messages.NewAPRep(messages.EncAPRepPart{SequenceNumber: 1}, key)
	require.NoError(t, err)
	rawReply := NewKRB5TokenAPREP(reply, true)
	authenticated, _, status = acceptor.ContinueSecContext(&rawReply)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusNoContext, status.Code)
}

func TestSPNEGOContinuationRequiresMIC(t *testing.T) {
	mechanism := SPNEGOClientWithOptions(client.NewWithPassword("alice", "EXAMPLE.ORG", "password", config.New()), "HTTP/server", KRB5TokenAPREQOptions{})
	mechanism.offeredMechTypes = []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}
	mechanism.requireMechMIC = true
	mechanism.replyKey = types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	token := &SPNEGOToken{Resp: true, NegTokenResp: NegTokenResp{
		NegState: asn1.Enumerated(NegStateAcceptCompleted), SupportedMech: gssapi.OIDKRB5.OID(),
	}}
	authenticated, _, status := mechanism.ContinueSecContext(token)
	require.False(t, authenticated)
	require.Equal(t, gssapi.StatusBadMIC, status.Code)
}

func newContextExchange(t *testing.T, contextFlags []int) (*SPNEGO, *SPNEGO, gssapi.ContextToken) {
	return newContextExchangeWithOptions(t, KRB5TokenAPREQOptions{GSSAPIFlags: contextFlags})
}

func newContextExchangeWithOptions(t *testing.T, options KRB5TokenAPREQOptions) (*SPNEGO, *SPNEGO, gssapi.ContextToken) {
	return newContextExchangeWithPreferences(t, options, nil)
}

func newContextExchangeWithPreferences(t *testing.T, options KRB5TokenAPREQOptions, preferredMechs []asn1.ObjectIdentifier) (*SPNEGO, *SPNEGO, gssapi.ContextToken) {
	t.Helper()
	b, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	require.NoError(t, err)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))
	const realm = "TEST.GOKRB5"
	username := fmt.Sprintf("testuser%d", contextExchangeID.Add(1))
	cname := types.NewPrincipalName(1, username)
	sname := types.NewPrincipalName(1, "HTTP/host.test.gokrb5")
	now := time.Now().UTC()
	ticketFlags := types.NewKrbFlags()
	ticket, sessionKey, err := messages.NewTicket(
		cname, realm, sname, realm, ticketFlags, kt, 18, 1,
		now, now, now.Add(time.Hour), now.Add(2*time.Hour),
	)
	require.NoError(t, err)
	ticketBytes, err := ticket.Marshal()
	require.NoError(t, err)
	cache := credentials.NewCCache(cname, realm)
	cache.AddCredential(&credentials.Credential{
		Client: credentials.Principal{Realm: realm, PrincipalName: cname},
		Server: credentials.Principal{Realm: realm, PrincipalName: sname},
		Key:    sessionKey, AuthTime: now, StartTime: now.Add(-time.Minute), EndTime: now.Add(time.Hour),
		RenewTill: now.Add(2 * time.Hour), TicketFlags: ticketFlags, Ticket: ticketBytes,
	})
	cl, err := client.NewFromCCache(cache, config.New())
	require.NoError(t, err)
	initiator := SPNEGOClientWithOptions(cl, sname.PrincipalNameString(), options)
	initial, err := initiator.InitSecContext()
	require.NoError(t, err)
	acceptor := SPNEGOServiceWithMechTypes(kt, preferredMechs, service.DecodePAC(false))
	return initiator, acceptor, initial
}
