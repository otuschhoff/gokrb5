package spnego

import (
	"encoding/hex"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/client"
	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
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

	authenticated, _, status = acceptor.AcceptSecContext(initiatorMIC)
	require.True(t, authenticated, status.Error())
	require.Equal(t, gssapi.StatusComplete, status.Code)
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
	require.NotNil(t, acceptor.ResponseToken())

	authenticated, _, status = initiator.ContinueSecContext(acceptor.ResponseToken())
	require.True(t, authenticated)
	require.Equal(t, gssapi.StatusComplete, status.Code)
	require.NotNil(t, initiator.ResponseToken())

	authenticated, _, status = acceptor.ContinueSecContext(initiator.ResponseToken())
	require.True(t, authenticated)
	require.Equal(t, gssapi.StatusComplete, status.Code)
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
	cl := client.NewWithKeytab(username, realm, kt, config.New())
	sname := types.NewPrincipalName(1, "HTTP/host.test.gokrb5")
	now := time.Now().UTC()
	ticket, sessionKey, err := messages.NewTicket(
		cl.Credentials.CName(), cl.Credentials.Realm(), sname, realm,
		types.NewKrbFlags(), kt, 18, 1, now, now, now.Add(time.Hour), now.Add(2*time.Hour),
	)
	require.NoError(t, err)
	negTokenInit, err := NewNegTokenInitKRB5WithOptions(cl, ticket, sessionKey, options)
	require.NoError(t, err)
	mechanismToken := negTokenInit.mechToken.(*KRB5Token)
	initiator := SPNEGOClientWithOptions(cl, sname.PrincipalNameString(), options)
	initiator.authenticator = mechanismToken.APReq.Authenticator
	initiator.replyKey = mechanismToken.APReq.Authenticator.SubKey
	initiator.offeredMechTypes = append([]asn1.ObjectIdentifier(nil), negTokenInit.MechTypes...)
	initiator.requireMechMIC = len(negTokenInit.MechListMIC) > 0
	var initial gssapi.ContextToken
	if contextFlagSet(options.GSSAPIFlags, gssapi.ContextFlagDCEStyle) {
		mechanismToken.raw = true
		initial = mechanismToken
	} else {
		initial = &SPNEGOToken{Init: true, NegTokenInit: negTokenInit}
	}
	acceptor := SPNEGOServiceWithMechTypes(kt, preferredMechs, service.DecodePAC(false))
	return initiator, acceptor, initial
}
