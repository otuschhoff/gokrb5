package client

import (
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/require"
)

func TestPKINITFreshnessTokenAbsent(t *testing.T) {
	token, found, err := pkinitFreshnessToken(messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED})
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, token)
}

func TestPKINITFreshnessToken(t *testing.T) {
	want := []byte("freshness")
	methodData := types.PADataSequence{{PADataType: patype.PA_AS_FRESHNESS, PADataValue: want}}
	encoded, err := asn1.Marshal(methodData)
	require.NoError(t, err)
	token, found, err := pkinitFreshnessToken(messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_REQUIRED, EData: encoded})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, want, token)
}

func TestPKINITFreshnessTokenRejectsMalformedMethodData(t *testing.T) {
	_, _, err := pkinitFreshnessToken(messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_REQUIRED, EData: []byte{0x30, 0x01}})
	require.Error(t, err)
}

func TestPKINITCredentialsReturnsDefensiveCopy(t *testing.T) {
	cl := &Client{pkinitCreds: &pac.CredentialData{
		CredentialCount: 1,
		Credentials:     []pac.SECPKGSupplementalCred{{Credentials: []byte{1, 2, 3}}},
	}}
	first, err := cl.PKINITCredentials()
	require.NoError(t, err)
	first.Credentials[0].Credentials[0] = 9
	second, err := cl.PKINITCredentials()
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, second.Credentials[0].Credentials)
}
