package client

import (
	"testing"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/pac"
	"github.com/otuschhoff/gokrb5/v8/pkinit"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestPKINITFreshnessTokenAbsent(t *testing.T) {
	var emptyPrincipal types.PrincipalName

	token, found, err := pkinitFreshnessToken(messages.KRBError{
		PVNO:      0,
		MsgType:   0,
		CTime:     time.Time{},
		Cusec:     0,
		STime:     time.Time{},
		Susec:     0,
		CRealm:    "",
		CName:     emptyPrincipal,
		Realm:     "",
		SName:     emptyPrincipal,
		EText:     "",
		EData:     nil,
		ErrorCode: errorcode.KDC_ERR_PREAUTH_FAILED,
	})
	require.NoError(t, err)
	require.False(t, found)
	require.Nil(t, token)
}

func TestPKINITFreshnessToken(t *testing.T) {
	var emptyPrincipal types.PrincipalName

	want := []byte("freshness")
	methodData := types.PADataSequence{{PADataType: patype.PA_AS_FRESHNESS, PADataValue: want}}
	encoded, err := asn1.Marshal(methodData)
	require.NoError(t, err)
	token, found, err := pkinitFreshnessToken(messages.KRBError{
		PVNO:      0,
		MsgType:   0,
		CTime:     time.Time{},
		Cusec:     0,
		STime:     time.Time{},
		Susec:     0,
		CRealm:    "",
		CName:     emptyPrincipal,
		Realm:     "",
		SName:     emptyPrincipal,
		EText:     "",
		ErrorCode: errorcode.KDC_ERR_PREAUTH_REQUIRED, EData: encoded,
	})
	require.NoError(t, err)
	require.True(t, found)
	require.Equal(t, want, token)
}

func TestPKINITFreshnessTokenRejectsMalformedMethodData(t *testing.T) {
	var emptyPrincipal types.PrincipalName

	token, found, err := pkinitFreshnessToken(messages.KRBError{
		PVNO:      0,
		MsgType:   0,
		CTime:     time.Time{},
		Cusec:     0,
		STime:     time.Time{},
		Susec:     0,
		CRealm:    "",
		CName:     emptyPrincipal,
		Realm:     "",
		SName:     emptyPrincipal,
		EText:     "",
		ErrorCode: errorcode.KDC_ERR_PREAUTH_REQUIRED,
		EData:     []byte{0x30, 0x01},
	})
	require.ErrorContains(t, err, "decode PKINIT freshness METHOD-DATA")
	var syntax asn1.SyntaxError
	require.ErrorAs(t, err, &syntax)
	require.False(t, found)
	require.Nil(t, token)
}

func TestProcessPKINITReplyRetainsDecodeCause(t *testing.T) {
	key, err := processPKINITReply(new(pkinit.Exchange), types.PADataSequence{
		{PADataType: patype.PA_PK_AS_REP, PADataValue: []byte{0x80, 0x01}},
	}, etypeID.AES128_CTS_HMAC_SHA1_96)
	require.ErrorContains(t, err, "process PKINIT reply")
	var syntax asn1.SyntaxError
	require.ErrorAs(t, err, &syntax)
	require.Zero(t, key)
}

func TestPKINITCredentialsReturnsDefensiveCopy(t *testing.T) {
	var supplemental pac.SECPKGSupplementalCred
	supplemental.Credentials = []byte{1, 2, 3}
	cl := new(Client)
	cl.pkinitCreds = &pac.CredentialData{
		CredentialCount: 1,
		Credentials:     []pac.SECPKGSupplementalCred{supplemental},
	}
	first, err := cl.PKINITCredentials()
	require.NoError(t, err)
	first.Credentials[0].Credentials[0] = 9
	second, err := cl.PKINITCredentials()
	require.NoError(t, err)
	require.Equal(t, []byte{1, 2, 3}, second.Credentials[0].Credentials)
}
