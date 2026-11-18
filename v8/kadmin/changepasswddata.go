package kadmin

import (
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/types"
)

// ChangePasswdData is the payload to a password change message.
type ChangePasswdData struct {
	NewPasswd []byte              `asn1:"explicit,tag:0"`
	TargName  types.PrincipalName `asn1:"explicit,optional,tag:1"`
	TargRealm string              `asn1:"generalstring,optional,explicit,tag:2"`
}

// Marshal encodes the password-change payload as DER.
func (c *ChangePasswdData) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(*c)
	if err != nil {
		return []byte{}, fmt.Errorf("marshal kpasswd change data: %w", err)
	}
	return b, nil
}
