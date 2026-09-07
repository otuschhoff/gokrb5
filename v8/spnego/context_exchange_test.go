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
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/credentials"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/service"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/require"
)

var contextExchangeID atomic.Uint64

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

	acceptorContext, err := gssapi.NewSecurityContext(
		acceptorSubkey, false, acceptorSequence, uint64(initiator.authenticator.SeqNumber), true,
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
	initialToken := initial.(*SPNEGOToken)
	initialToken.NegTokenInit.MechTypes = []asn1.ObjectIdentifier{
		gssapi.OIDMSLegacyKRB5.OID(),
		gssapi.OIDKRB5.OID(),
	}
	require.NoError(t, initialToken.NegTokenInit.SetMechListMIC(initiator.replyKey, uint64(initiator.authenticator.SeqNumber)))
	initiator.offeredMechTypes = append([]asn1.ObjectIdentifier(nil), initialToken.NegTokenInit.MechTypes...)
	initiator.requireMechMIC = true

	authenticated, _, status := acceptor.AcceptSecContext(initial)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
	response := acceptor.ResponseToken().(*SPNEGOToken)
	require.NotEmpty(t, response.NegTokenResp.MechListMIC)
	require.Equal(t, gssapi.OIDMSLegacyKRB5.OID(), response.NegTokenResp.SupportedMech)

	authenticated, _, status = initiator.ContinueSecContext(response)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
}

func TestContextExchangeRejectsTamperedMechList(t *testing.T) {
	initiator, acceptor, initial := newContextExchange(t, []int{gssapi.ContextFlagInteg})
	initialToken := initial.(*SPNEGOToken)
	initialToken.NegTokenInit.MechTypes = []asn1.ObjectIdentifier{
		gssapi.OIDMSLegacyKRB5.OID(),
		gssapi.OIDKRB5.OID(),
	}
	require.NoError(t, initialToken.NegTokenInit.SetMechListMIC(initiator.replyKey, uint64(initiator.authenticator.SeqNumber)))
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
	initialToken := initial.(*SPNEGOToken)
	require.Equal(t, gssapi.OIDMSLegacyKRB5.OID(), initialToken.NegTokenInit.MechTypes[0])
	mechanismToken := initialToken.NegTokenInit.mechToken.(*KRB5Token)
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
	requestMIC := acceptor.ResponseToken().(*SPNEGOToken)
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
	requestMIC := acceptor.ResponseToken().(*SPNEGOToken)
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
			requestMIC := acceptor.ResponseToken().(*SPNEGOToken)

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
			initiatorMIC := initiator.ResponseToken().(*SPNEGOToken)
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
			authenticated, _, status := clientMechanism.ContinueSecContext(test.token)
			require.False(t, authenticated)
			require.Equal(t, test.code, status.Code)
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
