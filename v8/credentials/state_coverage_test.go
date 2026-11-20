package credentials

import (
	"crypto/x509"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	stateTestRealm = "EXAMPLE.COM"
	stateTestUser  = "user"
)

func TestCredentialsIdentityAndAuthorizationLifecycle(t *testing.T) {
	credentials := New("initial", "INITIAL.REALM")
	principal := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service/host")
	authTime := time.Date(2026, time.September, 7, 10, 11, 12, 0, time.UTC)

	credentials.SetUserName("effective")
	credentials.SetDisplayName("Example User")
	credentials.SetCName(principal)
	credentials.SetRealm(stateTestRealm)
	credentials.SetHuman(false)
	credentials.SetAuthTime(authTime)
	credentials.SetAuthenticated(true)

	assert.Equal(t, "effective", credentials.UserName())
	assert.Equal(t, "Example User", credentials.DisplayName())
	assert.Equal(t, "service/host", credentials.CName().PrincipalNameString())
	assert.Equal(t, stateTestRealm, credentials.Domain())
	assert.Equal(t, stateTestRealm, credentials.Realm())
	assert.False(t, credentials.Human())
	assert.True(t, credentials.Authenticated())
	assert.True(t, credentials.AuthTime().Equal(authTime))
	assert.NotEmpty(t, credentials.SessionID())

	credentials.AddAuthzAttribute("group-a")
	credentials.AddAuthzAttribute("group-b")
	credentials.DisableAuthzAttribute("group-a")
	credentials.DisableAuthzAttribute("missing")
	assert.False(t, credentials.Authorized("group-a"))
	assert.True(t, credentials.Authorized("group-b"))
	assert.False(t, credentials.Authorized("missing"))
	credentials.EnableAuthzAttribute("group-a")
	credentials.EnableAuthzAttribute("missing")
	assert.True(t, credentials.Authorized("group-a"))
	credentials.RemoveAuthzAttribute("missing")
	credentials.RemoveAuthzAttribute("group-b")
	assert.Equal(t, []string{"group-a"}, credentials.AuthzAttributes())
}

func TestCredentialsADAndCertificateAttributes(t *testing.T) {
	credentials := New("initial", stateTestRealm)
	var ad ADCredentials
	ad.EffectiveName = "effective"
	ad.FullName = "Example User"
	ad.GroupMembershipSIDs = []string{"S-1-5-21-1", "S-1-5-21-2"}
	ad.UserSID = "S-1-5-21-3"
	credentials.SetADCredentials(ad)
	assert.Equal(t, ad.UserSID, credentials.GetADCredentials().UserSID)
	assert.Equal(t, ad.EffectiveName, credentials.UserName())
	assert.Equal(t, ad.FullName, credentials.DisplayName())
	for _, sid := range ad.GroupMembershipSIDs {
		assert.True(t, credentials.Authorized(sid), "AD group %s was not authorized", sid)
	}

	chain := []*x509.Certificate{new(x509.Certificate), new(x509.Certificate)}
	identity := CertificateIdentity{
		Certificate: nil,
		Chain:       chain,
		SubjectDN:   "CN=client",
		UPN:         "user@example.com",
		IssuedBy:    "",
	}
	credentials.SetCertificateIdentity(identity)
	chain[0] = nil
	got, ok := credentials.GetCertificateIdentity()
	require.True(t, ok)
	assert.Equal(t, identity.SubjectDN, got.SubjectDN)
	require.NotEmpty(t, got.Chain)
	assert.NotNil(t, got.Chain[0])
	got.Chain[0] = nil
	again, ok := credentials.GetCertificateIdentity()
	require.True(t, ok)
	require.NotEmpty(t, again.Chain)
	assert.NotNil(t, again.Chain[0], "certificate chain slice was not defensively copied")

	empty := New(stateTestUser, stateTestRealm)
	missing := empty.GetADCredentials()
	assert.Empty(t, missing.UserSID)
	assert.Empty(t, missing.GroupMembershipSIDs)
	_, ok = empty.GetCertificateIdentity()
	assert.False(t, ok)
}

func TestCredentialsExpiryAttributesAndSerialization(t *testing.T) {
	credentials := New(stateTestUser, stateTestRealm)
	assert.False(t, credentials.Expired(), "credentials without expiry are expired")
	past := time.Now().UTC().Add(-time.Minute)
	credentials.SetValidUntil(past)
	assert.True(t, credentials.Expired())
	assert.True(t, credentials.ValidUntil().Equal(past))
	future := time.Now().UTC().Add(time.Hour)
	credentials.SetValidUntil(future)
	assert.False(t, credentials.Expired(), "future credentials are expired")

	credentials.SetAttribute("one", 1)
	assert.Equal(t, 1, credentials.Attributes()["one"])
	credentials.RemoveAttribute("one")
	credentials.SetAttributes(map[string]any{"two": "value"})
	assert.Equal(t, "value", credentials.Attributes()["two"])

	encoded, err := credentials.Marshal()
	require.NoError(t, err)
	decoded := New("", "")
	require.NoError(t, decoded.Unmarshal(encoded))
	assert.Equal(t, stateTestUser, decoded.UserName())
	assert.Equal(t, stateTestRealm, decoded.Realm())
	assert.True(t, decoded.ValidUntil().Equal(future))
	assert.Error(t, decoded.Unmarshal([]byte("not a gob")))

	jsonValue, err := credentials.JSON()
	require.NoError(t, err)
	var fields map[string]any
	require.NoError(t, json.Unmarshal([]byte(jsonValue), &fields))
	assert.Equal(t, stateTestUser, fields["Username"])
	assert.Equal(t, stateTestRealm, fields["Realm"])
}
