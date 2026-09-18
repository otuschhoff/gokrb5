package gssapi

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityContextBidirectionalProtection(t *testing.T) {
	testCases := []types.EncryptionKey{
		{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")},
		{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")},
		{KeyType: etypeID.AES128_CTS_HMAC_SHA256_128, KeyValue: []byte("0123456789abcdef")},
		{KeyType: etypeID.AES256_CTS_HMAC_SHA384_192, KeyValue: []byte("0123456789abcdef0123456789abcdef")},
	}
	for _, key := range testCases {
		t.Run(fmt.Sprintf("etype-%d", key.KeyType), func(t *testing.T) {
			initiator, err := NewSecurityContext(key, true, 7, 11, true)
			require.NoError(t, err)
			acceptor, err := NewSecurityContext(key, false, 11, 7, true)
			require.NoError(t, err)

			sealed, err := initiator.Wrap([]byte("secret"), true)
			require.NoError(t, err)
			message, confidential, err := acceptor.Unwrap(sealed)
			require.NoError(t, err)
			assert.True(t, confidential)
			assert.Equal(t, []byte("secret"), message)

			plain, err := acceptor.Wrap([]byte("visible"), false)
			require.NoError(t, err)
			message, confidential, err = initiator.Unwrap(plain)
			require.NoError(t, err)
			assert.False(t, confidential)
			assert.Equal(t, []byte("visible"), message)
		})
	}
}

func TestSecurityContextAcceptsADStyleRotation(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	initiator, err := NewSecurityContext(key, true, 0, 0, true)
	require.NoError(t, err)
	acceptor, err := NewSecurityContext(key, false, 0, 0, true)
	require.NoError(t, err)
	token, err := initiator.Wrap([]byte("LDAP sealed payload"), true)
	require.NoError(t, err)

	body := token[HdrLen:]
	rotateRight(body, 28)
	binary.BigEndian.PutUint16(token[6:8], 28)
	message, confidential, err := acceptor.Unwrap(token)
	require.NoError(t, err)
	assert.True(t, confidential)
	assert.Equal(t, []byte("LDAP sealed payload"), message)
}

func TestSecurityContextSignOnlyConnection(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	initiator, err := NewSecurityContext(key, true, 3, 0, true)
	require.NoError(t, err)
	acceptor, err := NewSecurityContext(key, false, 0, 3, true)
	require.NoError(t, err)
	token, err := initiator.Wrap([]byte("signed LDAP payload"), false)
	require.NoError(t, err)
	assert.Zero(t, token[2]&MICTokenFlagSealed)
	assert.True(t, bytes.Contains(token, []byte("signed LDAP payload")))

	body := token[HdrLen:]
	rotation := len(body) + 7
	rotateRight(body, rotation)
	binary.BigEndian.PutUint16(token[6:8], uint16(rotation))
	tampered := append([]byte(nil), token...)
	tampered[HdrLen+7] ^= 1
	_, _, err = acceptor.Unwrap(tampered)
	assert.Error(t, err)

	message, confidential, err := acceptor.Unwrap(token)
	require.NoError(t, err)
	assert.False(t, confidential)
	assert.Equal(t, []byte("signed LDAP payload"), message)
}

func TestSecurityContextIgnoresAuthenticatedUnknownWrapFlags(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	acceptor, _ := NewSecurityContext(key, false, 0, 0, true)
	token, err := initiator.Wrap([]byte("future flag"), false)
	require.NoError(t, err)
	token[2] |= 0x80

	checksumLength := int(binary.BigEndian.Uint16(token[4:6]))
	etype, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)
	checksum, err := etype.GetChecksumHash(
		key.KeyValue,
		append(append([]byte(nil), token[HdrLen:len(token)-checksumLength]...), checksumWrapHeader(token[:HdrLen])...),
		keyusage.GSSAPI_INITIATOR_SEAL,
	)
	require.NoError(t, err)
	copy(token[len(token)-checksumLength:], checksum)

	message, confidential, err := acceptor.Unwrap(token)
	require.NoError(t, err)
	assert.False(t, confidential)
	assert.Equal(t, []byte("future flag"), message)
}

func TestSecurityContextAcceptsConfidentialExtraCount(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	const extraCount = 5
	header := wrapHeader(MICTokenFlagSealed|MICTokenFlagAcceptorSubkey, extraCount, 0, 0)
	plaintext := append([]byte("message"), []byte{0xff, 0xff, 0xff, 0xff, 0xff}...)
	plaintext = append(plaintext, header...)
	etype, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)
	_, body, err := etype.EncryptMessage(key.KeyValue, plaintext, keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)

	const rotation = 31
	rotateRight(body, rotation)
	binary.BigEndian.PutUint16(header[6:8], rotation)
	acceptor, err := NewSecurityContext(key, false, 0, 0, true)
	require.NoError(t, err)
	message, confidential, err := acceptor.Unwrap(append(header, body...))
	require.NoError(t, err)
	assert.True(t, confidential)
	assert.Equal(t, []byte("message"), message)
}

func TestSecurityContextRejectsTamperingAndReplay(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	acceptor, _ := NewSecurityContext(key, false, 0, 0, true)
	token, err := initiator.Wrap([]byte("message"), true)
	require.NoError(t, err)

	tampered := append([]byte(nil), token...)
	tampered[len(tampered)-1] ^= 1
	_, _, err = acceptor.Unwrap(tampered)
	assert.Error(t, err)
	message, _, err := acceptor.Unwrap(token)
	require.NoError(t, err)
	assert.Equal(t, []byte("message"), message)
	_, _, err = acceptor.Unwrap(token)
	assert.Error(t, err)
}

func TestSecurityContextMICProtection(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef0123456789abcdef")}
	initiator, err := NewSecurityContext(key, true, 4, 0, true)
	require.NoError(t, err)
	acceptor, err := NewSecurityContext(key, false, 0, 4, true)
	require.NoError(t, err)
	token, err := initiator.GetMIC([]byte("signed message"))
	require.NoError(t, err)

	tampered := append([]byte(nil), token...)
	tampered[len(tampered)-1] ^= 1
	assert.Error(t, acceptor.VerifyMIC([]byte("signed message"), tampered))
	require.NoError(t, acceptor.VerifyMIC([]byte("signed message"), token))
	assert.Error(t, acceptor.VerifyMIC([]byte("signed message"), token))

	reply, err := acceptor.GetMIC([]byte("reply"))
	require.NoError(t, err)
	require.NoError(t, initiator.VerifyMIC([]byte("reply"), reply))
}

func TestNewSecurityContextRejectsUnsupportedKeys(t *testing.T) {
	_, err := NewSecurityContext(types.EncryptionKey{KeyType: etypeID.RC4_HMAC, KeyValue: make([]byte, 16)}, true, 0, 0, false)
	assert.ErrorContains(t, err, "requires an AES key")
	_, err = NewSecurityContext(types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: make([]byte, 15)}, true, 0, 0, false)
	assert.ErrorContains(t, err, "invalid key length")
	_, err = NewSecurityContext(types.EncryptionKey{KeyType: 999, KeyValue: make([]byte, 16)}, true, 0, 0, false)
	assert.Error(t, err)
}

func TestSecurityContextRejectsMalformedWrapTokens(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	valid, err := initiator.Wrap([]byte("message"), false)
	require.NoError(t, err)

	testCases := map[string][]byte{
		"short header":      {0x05, 0x04},
		"empty body":        wrapHeader(MICTokenFlagAcceptorSubkey, 12, 0, 0),
		"short sealed body": append(wrapHeader(MICTokenFlagSealed|MICTokenFlagAcceptorSubkey, 0, 0, 0), 0),
		"zero checksum":     append(wrapHeader(MICTokenFlagAcceptorSubkey, 0, 0, 0), 0),
		"short checksum":    append(wrapHeader(MICTokenFlagAcceptorSubkey, 12, 0, 0), 0),
	}
	badID := append([]byte(nil), valid...)
	badID[0] = 0
	testCases["token id"] = badID
	badFiller := append([]byte(nil), valid...)
	badFiller[3] = 0
	testCases["filler"] = badFiller
	badDirection := append([]byte(nil), valid...)
	badDirection[2] |= MICTokenFlagSentByAcceptor
	testCases["direction"] = badDirection
	badSubkey := append([]byte(nil), valid...)
	badSubkey[2] &^= MICTokenFlagAcceptorSubkey
	testCases["subkey"] = badSubkey
	badSequence := append([]byte(nil), valid...)
	binary.BigEndian.PutUint64(badSequence[8:16], 1)
	testCases["sequence"] = badSequence

	for name, token := range testCases {
		t.Run(name, func(t *testing.T) {
			acceptor, contextErr := NewSecurityContext(key, false, 0, 0, true)
			require.NoError(t, contextErr)
			_, _, unwrapErr := acceptor.Unwrap(token)
			assert.Error(t, unwrapErr)
		})
	}
}

func TestSecurityContextRejectsAuthenticatedHeaderMismatch(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	outerHeader := wrapHeader(MICTokenFlagSealed|MICTokenFlagAcceptorSubkey, 0, 0, 0)
	innerHeader := wrapHeader(MICTokenFlagSealed|MICTokenFlagAcceptorSubkey, 0, 0, 1)
	etype, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)
	_, body, err := etype.EncryptMessage(key.KeyValue, append([]byte("message"), innerHeader...), keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)
	acceptor, _ := NewSecurityContext(key, false, 0, 0, true)
	_, _, err = acceptor.Unwrap(append(outerHeader, body...))
	assert.ErrorContains(t, err, "encrypted header mismatch")
}

func TestSecurityContextRejectsInvalidConfidentialExtraCount(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	header := wrapHeader(MICTokenFlagSealed|MICTokenFlagAcceptorSubkey, 100, 0, 0)
	etype, err := crypto.GetEtype(key.KeyType)
	require.NoError(t, err)
	_, body, err := etype.EncryptMessage(key.KeyValue, append([]byte("message"), header...), keyusage.GSSAPI_INITIATOR_SEAL)
	require.NoError(t, err)
	acceptor, _ := NewSecurityContext(key, false, 0, 0, true)
	_, _, err = acceptor.Unwrap(append(header, body...))
	assert.ErrorContains(t, err, "extra count")
}

func TestSecurityContextPropagatesCryptoErrors(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}

	unknownEtype, _ := NewSecurityContext(key, true, 7, 0, true)
	unknownEtype.key.KeyType = 999
	_, err := unknownEtype.Wrap([]byte("message"), false)
	assert.Error(t, err)
	assert.Equal(t, uint64(7), unknownEtype.sendSequence)

	badSealKey, _ := NewSecurityContext(key, true, 7, 0, true)
	badSealKey.key.KeyValue = []byte("short")
	_, err = badSealKey.Wrap([]byte("message"), true)
	assert.Error(t, err)
	assert.Equal(t, uint64(7), badSealKey.sendSequence)

	badSignKey, _ := NewSecurityContext(key, true, 7, 0, true)
	badSignKey.key.KeyValue = []byte("short")
	_, err = badSignKey.Wrap([]byte("message"), false)
	assert.Error(t, err)
	assert.Equal(t, uint64(7), badSignKey.sendSequence)
	_, err = badSignKey.GetMIC([]byte("message"))
	assert.Error(t, err)
	assert.Equal(t, uint64(7), badSignKey.sendSequence)

	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	sealed, err := initiator.Wrap([]byte("message"), true)
	require.NoError(t, err)
	badDecryptKey, _ := NewSecurityContext(key, false, 0, 0, true)
	badDecryptKey.key.KeyValue = []byte("short")
	_, _, err = badDecryptKey.Unwrap(sealed)
	assert.Error(t, err)
	assert.Zero(t, badDecryptKey.receiveSequence)

	plainInitiator, _ := NewSecurityContext(key, true, 0, 0, true)
	plain, err := plainInitiator.Wrap([]byte("message"), false)
	require.NoError(t, err)
	badUnwrapEtype, _ := NewSecurityContext(key, false, 0, 0, true)
	badUnwrapEtype.key.KeyType = 999
	_, _, err = badUnwrapEtype.Unwrap(plain)
	assert.Error(t, err)
	assert.Zero(t, badUnwrapEtype.receiveSequence)
}

func TestSecurityContextRejectsMalformedMIC(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	acceptor, _ := NewSecurityContext(key, false, 0, 0, true)
	assert.Error(t, acceptor.VerifyMIC([]byte("message"), []byte{0x04}))

	initiator, _ := NewSecurityContext(key, true, 0, 0, true)
	token, err := initiator.GetMIC([]byte("message"))
	require.NoError(t, err)
	token[2] |= MICTokenFlagSealed
	assert.Error(t, acceptor.VerifyMIC([]byte("message"), token))
}

func TestRotateRightEmpty(t *testing.T) {
	rotateRight(nil, 42)
}

func TestSecurityContextNegoExKeysAreCloned(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	context, err := NewSecurityContext(key, true, 0, 0, true)
	require.NoError(t, err)

	localKey, ok := context.NegoExKey()
	assert.True(t, ok)
	verifyKey, ok := context.NegoExVerifyKey()
	assert.True(t, ok)
	assert.Equal(t, key, localKey)
	assert.Equal(t, key, verifyKey)
	localKey.KeyValue[0] ^= 1
	verifyKey.KeyValue[0] ^= 1
	assert.Equal(t, key.KeyValue, context.key.KeyValue)
}

func TestWrapTokenSealedRotationRoundTrip(t *testing.T) {
	original := &WrapToken{
		Flags:     MICTokenFlagSealed | MICTokenFlagAcceptorSubkey,
		EC:        3,
		RRC:       28,
		SndSeqNum: 42,
		Payload:   []byte("encrypted-body"),
	}
	encoded, err := original.Marshal()
	require.NoError(t, err)
	var decoded WrapToken
	require.NoError(t, decoded.Unmarshal(encoded, false))
	assert.Equal(t, original, &decoded)
}

func TestWrapTokenRejectsInvalidSealedState(t *testing.T) {
	token := &WrapToken{Flags: MICTokenFlagSealed, Payload: []byte("ciphertext"), CheckSum: []byte("separate")}
	_, err := token.Marshal()
	assert.ErrorContains(t, err, "separate checksum")
	assert.Error(t, token.SetCheckSum(getSessionKey(), initiatorSeal))
	valid, err := token.Verify(getSessionKey(), initiatorSeal)
	assert.False(t, valid)
	assert.Error(t, err)

	token = &WrapToken{Payload: []byte("message"), CheckSum: []byte{1}, EC: 2}
	_, err = token.Marshal()
	assert.ErrorContains(t, err, "does not match EC")
}
