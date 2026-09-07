package credentials

import (
	"testing"

	"github.com/jcmturner/goidentity/v6"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
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
	var cred Credentials
	b, err := cred.Marshal()
	if err != nil {
		t.Fatalf("could not marshal credetials: %v", err)
	}
	var credum Credentials
	err = credum.Unmarshal(b)
	if err != nil {
		t.Fatalf("could not unmarshal credetials: %v", err)
	}
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
