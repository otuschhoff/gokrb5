package pac

import (
	"bytes"
	"errors"
	"fmt"
	"math"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/pac/internal/ndr"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// https://msdn.microsoft.com/en-us/library/cc237931.aspx

// CredentialsInfo implements https://msdn.microsoft.com/en-us/library/cc237953.aspx
type CredentialsInfo struct {
	Version                    uint32 // A 32-bit unsigned integer in little-endian format that defines the version. MUST be 0x00000000.
	EType                      uint32
	PACCredentialDataEncrypted []byte // Key usage number for encryption: KERB_NON_KERB_SALT (16)
	PACCredentialData          CredentialData
}

// Unmarshal bytes into the CredentialsInfo struct
func (c *CredentialsInfo) Unmarshal(b []byte, k types.EncryptionKey) error {
	var err error
	r := bytes.NewReader(b)
	c.Version, err = readPACUint32(r, "PAC credentials version")
	if err != nil {
		return err
	}
	if c.Version != 0 {
		return errors.New("credentials info version is not zero")
	}
	c.EType, err = readPACUint32(r, "PAC credentials enctype")
	if err != nil {
		return err
	}
	c.PACCredentialDataEncrypted, err = readPACBytes(r, r.Len(), "PAC encrypted credential data")
	if err != nil {
		return err
	}
	return c.DecryptEncPart(k)
}

// DecryptEncPart decrypts the encrypted part of the CredentialsInfo.
func (c *CredentialsInfo) DecryptEncPart(k types.EncryptionKey) error {
	if c.EType > math.MaxInt32 {
		return fmt.Errorf("credential encryption type %d exceeds int32 range", c.EType)
	}
	if int64(k.KeyType) != int64(c.EType) {
		return fmt.Errorf("key provided is not the correct type. Type needed: %d, type provided: %d", c.EType, k.KeyType)
	}
	pt, err := crypto.DecryptMessage(c.PACCredentialDataEncrypted, k, keyusage.KERB_NON_KERB_SALT)
	if err != nil {
		return fmt.Errorf("error decrypting PAC credential data: %w", err)
	}
	return c.PACCredentialData.Unmarshal(pt)
}

// CredentialData implements https://msdn.microsoft.com/en-us/library/cc237952.aspx
type CredentialData struct {
	CredentialCount uint32
	Credentials     []SECPKGSupplementalCred // Size is the value of CredentialCount
}

// Unmarshal converts the bytes provided into a CredentialData type.
func (c *CredentialData) Unmarshal(b []byte) error {
	dec := ndr.NewDecoder(bytes.NewReader(b))
	if err := dec.Decode(c); err != nil {
		return fmt.Errorf("error unmarshaling PAC credential data: %w", err)
	}
	return nil
}
