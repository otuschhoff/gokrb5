package credentials

import (
	"testing"

	"github.com/jcmturner/goidentity/v6"
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
