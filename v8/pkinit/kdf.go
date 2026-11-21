package pkinit

import (
	"crypto/sha1" // #nosec G505 -- RFC 4556 legacy KDF and RFC 8636 SHA-1 KDF OID.
	"crypto/sha256"
	"crypto/sha512"
	stdasn1 "encoding/asn1"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math"

	"github.com/jcmturner/gofork/encoding/asn1"

	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// DeriveReplyKey applies the negotiated RFC 8636 KDF to a padded DH shared secret.
func DeriveReplyKey(
	kdf KDFAlgorithmID,
	sharedSecret []byte,
	client, server KRB5PrincipalName,
	asReq, pkAsRep []byte,
	etypeID int32,
) (types.EncryptionKey, error) {
	hashFunc, err := kdfHash(kdf.ID)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	et, err := krbcrypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("PKINIT reply key enctype: %w", err)
	}
	seedBits := et.GetKeySeedBitLength()
	if seedBits <= 0 || seedBits%bitsPerByte != 0 {
		return types.EncryptionKey{}, fmt.Errorf("PKINIT enctype %d has invalid key seed length %d", etypeID, seedBits)
	}
	partyUInfo, err := marshalKDFPrincipal(client)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("marshal PKINIT KDF client principal: %w", err)
	}
	partyVInfo, err := marshalKDFPrincipal(server)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("marshal PKINIT KDF server principal: %w", err)
	}

	suppPubInfo, err := stdasn1.Marshal(PKINITSuppPubInfo{EType: etypeID, ASReq: asReq, PKASRep: pkAsRep})
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("marshal PKINIT KDF supplemental public info: %w", err)
	}
	var parameters asn1.RawValue
	otherInfo, err := asn1.Marshal(OtherInfo{
		AlgorithmID:  AlgorithmIdentifier{Algorithm: kdf.ID, Parameters: parameters},
		PartyUInfo:   partyUInfo,
		PartyVInfo:   partyVInfo,
		SuppPubInfo:  suppPubInfo,
		SuppPrivInfo: nil,
	})
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("marshal PKINIT KDF other info: %w", err)
	}

	seed, err := counterKDF(hashFunc, sharedSecret, otherInfo, seedBits/bitsPerByte)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	return types.EncryptionKey{KeyType: etypeID, KeyValue: et.RandomToKey(seed)}, nil
}

func marshalKDFPrincipal(name KRB5PrincipalName) ([]byte, error) {
	realm, err := stdasn1.Marshal(generalString(name.Realm))
	if err != nil {
		return nil, fmt.Errorf("marshal realm: %w", err)
	}

	var wire struct {
		Realm     stdasn1.RawValue
		Principal struct {
			NameType   int32              `asn1:"explicit,tag:0"`
			Components []stdasn1.RawValue `asn1:"explicit,tag:1"`
		} `asn1:"explicit,tag:1"`
	}
	// RawValue bypasses struct tags, so supply the explicit [0] wrapper.
	wire.Realm = stdasn1.RawValue{
		Class: stdasn1.ClassContextSpecific, Tag: 0, IsCompound: true,
		Bytes: realm, FullBytes: nil,
	}
	wire.Principal.NameType = name.PrincipalName.NameType
	wire.Principal.Components = make([]stdasn1.RawValue, len(name.PrincipalName.NameString))
	for i, component := range name.PrincipalName.NameString {
		wire.Principal.Components[i] = generalString(component)
	}
	der, err := stdasn1.Marshal(wire)
	if err != nil {
		return nil, fmt.Errorf("marshal principal sequence: %w", err)
	}
	return der, nil
}

func generalString(value string) stdasn1.RawValue {
	// GeneralString is universal tag 27. Preserve the input octets verbatim.
	const generalStringTag = 27
	return stdasn1.RawValue{
		Class: stdasn1.ClassUniversal, Tag: generalStringTag, IsCompound: false,
		Bytes: []byte(value), FullBytes: nil,
	}
}

// DeriveLegacyReplyKey applies octetstring2key from RFC 4556 section 3.2.3.1.
func DeriveLegacyReplyKey(sharedSecret, clientNonce, serverNonce []byte, etypeID int32) (types.EncryptionKey, error) {
	et, err := krbcrypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("PKINIT reply key enctype: %w", err)
	}
	seedBits := et.GetKeySeedBitLength()
	if seedBits <= 0 || seedBits%bitsPerByte != 0 {
		return types.EncryptionKey{}, fmt.Errorf("PKINIT enctype %d has invalid key seed length %d", etypeID, seedBits)
	}
	input := make([]byte, 0, len(sharedSecret)+len(clientNonce)+len(serverNonce))
	input = append(input, sharedSecret...)
	input = append(input, clientNonce...)
	input = append(input, serverNonce...)
	seedBytes := seedBits / bitsPerByte
	seed := make([]byte, 0, seedBytes)
	for counter := 0; len(seed) < seedBytes; counter++ {
		if counter > math.MaxUint8 {
			return types.EncryptionKey{}, errors.New("PKINIT legacy KDF output is too long")
		}
		digest := sha1.Sum(append([]byte{byte(counter)}, input...)) // #nosec G401 -- RFC 4556 octetstring2key.
		seed = append(seed, digest[:]...)
	}
	seed = seed[:seedBytes]
	return types.EncryptionKey{KeyType: etypeID, KeyValue: et.RandomToKey(seed)}, nil
}

func kdfHash(oid []int) (func() hash.Hash, error) {
	switch {
	case OIDKDFSHA1.Equal(oid):
		return sha1.New, nil
	case OIDKDFSHA256.Equal(oid):
		return sha256.New, nil
	case OIDKDFSHA384.Equal(oid):
		return sha512.New384, nil
	case OIDKDFSHA512.Equal(oid):
		return sha512.New, nil
	default:
		return nil, fmt.Errorf("unsupported PKINIT KDF OID %v", oid)
	}
}

func pkinitUint32(name string, value int) (uint32, error) {
	if value < 0 || int64(value) > math.MaxUint32 { // int is at most int64 on supported Go architectures.
		return 0, fmt.Errorf("PKINIT %s %d exceeds uint32 range", name, value)
	}
	return uint32(value), nil // #nosec G115 -- bounded by MaxUint32 above.
}

func counterKDF(hashFunc func() hash.Hash, secret, otherInfo []byte, outputBytes int) ([]byte, error) {
	if outputBytes < 0 {
		return nil, errors.New("PKINIT KDF output length cannot be negative")
	}
	hashSize := hashFunc().Size()
	blocks := outputBytes / hashSize
	if outputBytes%hashSize != 0 {
		blocks++
	}
	if int64(blocks) > math.MaxUint32 || blocks > math.MaxInt/hashSize {
		return nil, errors.New("PKINIT KDF output is too long")
	}
	output := make([]byte, 0, blocks*hashSize)
	var counter [4]byte
	for block := range blocks {
		counterValue, err := pkinitUint32("KDF counter", block+1)
		if err != nil {
			return nil, err
		}
		binary.BigEndian.PutUint32(counter[:], counterValue)
		digest := hashFunc()
		digest.Write(counter[:])
		digest.Write(secret)
		digest.Write(otherInfo)
		output = digest.Sum(output)
	}
	return output[:outputBytes], nil
}
