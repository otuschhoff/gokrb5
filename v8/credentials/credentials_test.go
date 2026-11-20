package credentials

import (
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/jcmturner/goidentity/v6"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const credentialTestRealm = "EXAMPLE.ORG"

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	u := new(Credentials)
	i := new(goidentity.Identity)
	assert.Implements(t, i, u, "Credentials type does not implement the Identity interface")
}

func TestDelegatedCredentialsDefensiveCopy(t *testing.T) {
	source := new(Credential)
	source.Key.KeyValue = []byte{1}
	source.AuthData = []types.AuthorizationDataEntry{{ADType: 0, ADData: []byte{2}}}
	source.Ticket = []byte{3}
	credentials := New("testuser", "TEST.REALM")
	credentials.SetDelegatedCredentials([]*Credential{source})
	source.Key.KeyValue[0] = 9
	source.AuthData[0].ADData[0] = 9

	first := credentials.DelegatedCredentials()
	assert.Equal(t, byte(1), first[0].Key.KeyValue[0])
	assert.Equal(t, byte(2), first[0].AuthData[0].ADData[0])
	first[0].Ticket[0] = 9
	assert.Equal(t, byte(3), credentials.DelegatedCredentials()[0].Ticket[0])
}

func TestCredentials_Marshal(t *testing.T) {
	t.Parallel()

	cred := New("testuser", credentialTestRealm).WithPassword("fixture-password")
	var ad ADCredentials
	ad.EffectiveName = "testuser"
	ad.FullName = "Test User"
	cred.SetADCredentials(ad)
	cred.SetAttribute("metadata", map[string]any{"source": "fixture"})
	b, err := cred.Marshal()
	require.NoError(t, err)
	var credum Credentials
	require.NoError(t, credum.Unmarshal(b))
	assert.Equal(t, cred.UserName(), credum.UserName())
	assert.Equal(t, cred.Domain(), credum.Domain())
	assert.Equal(t, cred.Attributes(), credum.Attributes())
	assert.False(t, credum.HasPassword())
}

func TestCredentialsMarshalError(t *testing.T) {
	t.Parallel()

	cred := New("testuser", credentialTestRealm)
	cred.SetAttribute("unsupported", make(chan int))
	b, err := cred.Marshal()
	assert.Empty(t, b)
	require.ErrorContains(t, err, "encode credentials gob:")
	assert.NotNil(t, errors.Unwrap(err))
}

func TestCredentialsUnmarshalError(t *testing.T) {
	t.Parallel()

	cred := New("testuser", credentialTestRealm)
	cred.SetAttribute("metadata", "original")
	err := cred.Unmarshal(nil)
	require.ErrorContains(t, err, "decode credentials gob:")
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, "testuser", cred.UserName())
	assert.Equal(t, "original", cred.Attributes()["metadata"])
}

func TestCredentialsJSON(t *testing.T) {
	t.Parallel()

	cred := New("testuser", credentialTestRealm).WithPassword("fixture-password")
	cred.SetAttribute("metadata", "not-for-json")
	output, err := cred.JSON()
	require.NoError(t, err)
	var fields map[string]json.RawMessage
	require.NoError(t, json.Unmarshal([]byte(output), &fields))
	assert.JSONEq(t, `"testuser"`, string(fields["Username"]))
	assert.JSONEq(t, `true`, string(fields["Password"]))
	assert.NotContains(t, fields, "Attributes")
	assert.NotContains(t, output, cred.Password())

	cred.SetValidUntil(time.Unix(253402300800, 0).UTC()) // Start of year 10000.
	output, err = cred.JSON()
	assert.Empty(t, output)
	require.ErrorContains(t, err, "encode credentials JSON:")
	_, ok := errors.AsType[*json.MarshalerError](err)
	assert.True(t, ok)
}

func TestCredentialsPrincipalAndKeySources(t *testing.T) {
	principal := types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "HTTP/server.example.org")
	credential := NewFromPrincipalName(principal, credentialTestRealm)
	assert.True(t, credential.CName().Equal(principal), "client principal was not retained")
	assert.Equal(t, credentialTestRealm, credential.Domain())

	kt := keytab.New()
	var entry keytab.Entry
	kt.Entries = append(kt.Entries, entry)
	assert.Same(t, credential, credential.WithKeytab(kt))
	assert.Same(t, kt, credential.Keytab())
	assert.True(t, credential.HasKeytab())
	assert.False(t, credential.HasPassword())

	assert.Same(t, credential, credential.WithPassword("secret"))
	assert.Equal(t, "secret", credential.Password())
	assert.True(t, credential.HasPassword())
	assert.False(t, credential.HasKeytab())
	credential.WithPassword("")
	assert.False(t, credential.HasPassword(), "empty password reported as configured")
}
