package pkinit

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"hash"
	"math"

	"github.com/jcmturner/gofork/encoding/asn1"
	krbcrypto "github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// DeriveReplyKey applies the negotiated RFC 8636 KDF to a padded DH shared secret.
func DeriveReplyKey(kdf KDFAlgorithmID, sharedSecret []byte, client, server KRB5PrincipalName, asReq, pkAsRep []byte, etypeID int32) (types.EncryptionKey, error) {
	hashFunc, err := kdfHash(kdf.ID)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	et, err := krbcrypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("PKINIT reply key enctype: %w", err)
	}
	seedBits := et.GetKeySeedBitLength()
	if seedBits <= 0 || seedBits%8 != 0 {
		return types.EncryptionKey{}, fmt.Errorf("PKINIT enctype %d has invalid key seed length %d", etypeID, seedBits)
	}
	partyUInfo, err := asn1.Marshal(client)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("marshal PKINIT KDF client principal: %w", err)
	}
	partyVInfo, err := asn1.Marshal(server)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("marshal PKINIT KDF server principal: %w", err)
	}

	suppPubInfo, err := asn1.Marshal(PKINITSuppPubInfo{EType: etypeID, ASReq: asReq, PKASRep: pkAsRep})
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("marshal PKINIT KDF supplemental public info: %w", err)
	}
	otherInfo, err := asn1.Marshal(OtherInfo{
		AlgorithmID: AlgorithmIdentifier{Algorithm: kdf.ID},
		PartyUInfo:  partyUInfo,
		PartyVInfo:  partyVInfo,
		SuppPubInfo: suppPubInfo,
	})
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("marshal PKINIT KDF other info: %w", err)
	}

	seed, err := counterKDF(hashFunc, sharedSecret, otherInfo, seedBits/8)
	if err != nil {
		return types.EncryptionKey{}, err
	}
	return types.EncryptionKey{KeyType: etypeID, KeyValue: et.RandomToKey(seed)}, nil
}

// DeriveLegacyReplyKey applies octetstring2key from RFC 4556 section 3.2.3.1.
func DeriveLegacyReplyKey(sharedSecret, clientNonce, serverNonce []byte, etypeID int32) (types.EncryptionKey, error) {
	et, err := krbcrypto.GetEtype(etypeID)
	if err != nil {
		return types.EncryptionKey{}, fmt.Errorf("PKINIT reply key enctype: %w", err)
	}
	seedBits := et.GetKeySeedBitLength()
	if seedBits <= 0 || seedBits%8 != 0 {
		return types.EncryptionKey{}, fmt.Errorf("PKINIT enctype %d has invalid key seed length %d", etypeID, seedBits)
	}
	input := make([]byte, 0, len(sharedSecret)+len(clientNonce)+len(serverNonce))
	input = append(input, sharedSecret...)
	input = append(input, clientNonce...)
	input = append(input, serverNonce...)
	seedBytes := seedBits / 8
	seed := make([]byte, 0, seedBytes)
	for counter := 0; len(seed) < seedBytes; counter++ {
		if counter > math.MaxUint8 {
			return types.EncryptionKey{}, fmt.Errorf("PKINIT legacy KDF output is too long")
		}
		digest := sha1.Sum(append([]byte{byte(counter)}, input...))
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

func counterKDF(hashFunc func() hash.Hash, secret, otherInfo []byte, outputBytes int) ([]byte, error) {
	hashSize := hashFunc().Size()
	blocks := (outputBytes + hashSize - 1) / hashSize
	if uint64(blocks) > math.MaxUint32 {
		return nil, fmt.Errorf("PKINIT KDF output is too long")
	}
	output := make([]byte, 0, blocks*hashSize)
	var counter [4]byte
	for block := 1; block <= blocks; block++ {
		binary.BigEndian.PutUint32(counter[:], uint32(block))
		digest := hashFunc()
		digest.Write(counter[:])
		digest.Write(secret)
		digest.Write(otherInfo)
		output = digest.Sum(output)
	}
	return output[:outputBytes], nil
}
