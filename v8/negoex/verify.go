package negoex

import (
	"crypto/hmac"
	"errors"
	"fmt"
	"math"

	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/types"
)

var (
	// ErrNoVerifyKey indicates no NEGOEX verification key is available.
	ErrNoVerifyKey = errors.New("no NEGOEX verification key")
	// ErrInvalidChecksum indicates a NEGOEX checksum verification failure.
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
	hashID := etype.GetHashID()
	if hashID < 0 {
		return Checksum{}, fmt.Errorf("negative NEGOEX checksum type %d", hashID)
	}
	return Checksum{
		HeaderLength: 20,
		Scheme:       ChecksumSchemeRFC3961,
		Type:         uint32(hashID), // #nosec G115 -- nonnegative check above.
		Value:        value,
	}, nil
}

// VerifyChecksum validates a VERIFY checksum over a transcript.
func VerifyChecksum(key types.EncryptionKey, usage uint32, transcript []byte, checksum Checksum) error {
	if checksum.Scheme != ChecksumSchemeRFC3961 {
		return ErrUnsupportedChecksumScheme
	}
	if checksum.Type > math.MaxInt32 {
		return ErrUnsupportedChecksumScheme
	}
	checksumType, err := krbcrypto.GetChksumEtype(int32(checksum.Type)) // #nosec G115 -- bounded by MaxInt32 above.
	if err != nil {
		return fmt.Errorf("%w: %w", ErrUnsupportedChecksumScheme, err)
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
