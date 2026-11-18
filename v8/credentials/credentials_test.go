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

func TestImplementsInterface(t *testing.T) {
	t.Parallel()
	u := new(Credentials)
	i := new(goidentity.Identity)
	assert.Implements(t, i, u, "Credentials type does not implement the Identity interface")
}

func TestDelegatedCredentialsDefensiveCopy(t *testing.T) {
	source := &Credential{
		Key:      types.EncryptionKey{KeyValue: []byte{1}},
		AuthData: []types.AuthorizationDataEntry{{ADData: []byte{2}}},
		Ticket:   []byte{3},
	}
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

	cred := New("testuser", "EXAMPLE.ORG").WithPassword("fixture-password")
	ad := ADCredentials{EffectiveName: "testuser", FullName: "Test User"}
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

	cred := New("testuser", "EXAMPLE.ORG")
	cred.SetAttribute("unsupported", make(chan int))
	b, err := cred.Marshal()
	assert.Empty(t, b)
	require.ErrorContains(t, err, "encode credentials gob:")
	assert.NotNil(t, errors.Unwrap(err))
}

func TestCredentialsUnmarshalError(t *testing.T) {
	t.Parallel()

	cred := New("testuser", "EXAMPLE.ORG")
	cred.SetAttribute("metadata", "original")
	err := cred.Unmarshal(nil)
	require.ErrorContains(t, err, "decode credentials gob:")
	assert.ErrorIs(t, err, io.EOF)
	assert.Equal(t, "testuser", cred.UserName())
	assert.Equal(t, "original", cred.Attributes()["metadata"])
}

func TestCredentialsJSON(t *testing.T) {
	t.Parallel()

	cred := New("testuser", "EXAMPLE.ORG").WithPassword("fixture-password")
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
	credential := NewFromPrincipalName(principal, "EXAMPLE.ORG")
	if !credential.CName().Equal(principal) || credential.Domain() != "EXAMPLE.ORG" {
		t.Fatalf("principal credential = %q@%q", credential.CName().PrincipalNameString(), credential.Domain())
	}

	kt := keytab.New()
	kt.Entries = append(kt.Entries, keytab.Entry{})
	if credential.WithKeytab(kt) != credential || credential.Keytab() != kt || !credential.HasKeytab() || credential.HasPassword() {
		t.Fatal("keytab credential state was not retained")
	}
	if credential.WithPassword("secret") != credential || credential.Password() != "secret" || !credential.HasPassword() || credential.HasKeytab() {
		t.Fatal("password credential state was not retained")
	}
	credential.WithPassword("")
	if credential.HasPassword() {
		t.Fatal("empty password reported as configured")
	}
}
