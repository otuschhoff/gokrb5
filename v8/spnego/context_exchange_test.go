package spnego

import (
	"encoding/hex"
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
	t.Helper()
	b, err := hex.DecodeString(testdata.HTTP_KEYTAB)
	require.NoError(t, err)
	kt := keytab.New()
	require.NoError(t, kt.Unmarshal(b))
	const realm = "TEST.GOKRB5"
	cl := client.NewWithKeytab("testuser1", realm, kt, config.New())
	sname := types.NewPrincipalName(1, "HTTP/host.test.gokrb5")
	now := time.Now().UTC()
	ticket, sessionKey, err := messages.NewTicket(
		cl.Credentials.CName(), cl.Credentials.Realm(), sname, realm,
		types.NewKrbFlags(), kt, 18, 1, now, now, now.Add(time.Hour), now.Add(2*time.Hour),
	)
	require.NoError(t, err)
	options := KRB5TokenAPREQOptions{GSSAPIFlags: contextFlags}
	mechanismToken, err := NewKRB5TokenAPREQWithOptions(cl, ticket, sessionKey, options)
	require.NoError(t, err)
	initiator := SPNEGOClientWithOptions(cl, sname.PrincipalNameString(), options)
	initiator.authenticator = mechanismToken.APReq.Authenticator
	initiator.replyKey = mechanismToken.APReq.Authenticator.SubKey
	var initial gssapi.ContextToken
	if contextFlagSet(contextFlags, gssapi.ContextFlagDCEStyle) {
		mechanismToken.raw = true
		initial = &mechanismToken
	} else {
		mechanismBytes, err := mechanismToken.Marshal()
		require.NoError(t, err)
		initial = &SPNEGOToken{Init: true, NegTokenInit: NegTokenInit{
			MechTypes: []asn1.ObjectIdentifier{gssapi.OIDKRB5.OID()}, MechTokenBytes: mechanismBytes, mechToken: &mechanismToken,
		}}
	}
	acceptor := SPNEGOService(kt, service.DecodePAC(false))
	return initiator, acceptor, initial
}
