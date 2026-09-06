package negoex

import (
	"crypto/hmac"
	"errors"
	"fmt"

	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/types"
)

var (
	ErrNoVerifyKey     = errors.New("no NEGOEX verification key")
	ErrInvalidChecksum = errors.New("invalid NEGOEX checksum")
)

// MakeChecksum computes the RFC 3961 keyed checksum for a transcript.
func MakeChecksum(key types.EncryptionKey, usage uint32, transcript []byte) (Checksum, error) {
	etype, err := krbcrypto.GetEtype(key.KeyType)
	if err != nil {
		return Checksum{}, err
	}
	value, err := etype.GetChecksumHash(key.KeyValue, transcript, usage)
	if err != nil {
		return Checksum{}, err
	}
	return Checksum{
		HeaderLength: 20,
		Scheme:       ChecksumSchemeRFC3961,
		Type:         uint32(etype.GetHashID()),
		Value:        value,
	}, nil
}

// VerifyChecksum validates a VERIFY checksum over a transcript.
func VerifyChecksum(key types.EncryptionKey, usage uint32, transcript []byte, checksum Checksum) error {
	if checksum.Scheme != ChecksumSchemeRFC3961 {
		return ErrUnsupportedChecksumScheme
	}
	checksumType, err := krbcrypto.GetChksumEtype(int32(checksum.Type))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrUnsupportedChecksumScheme, err)
	}
	if checksumType.GetETypeID() != key.KeyType {
		return ErrInvalidChecksum
	}
	expected, err := checksumType.GetChecksumHash(key.KeyValue, transcript, usage)
	if err != nil {
		return err
	}
	if !hmac.Equal(expected, checksum.Value) {
		return ErrInvalidChecksum
	}
	return nil
}