package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"errors"
	"fmt"
	"sync"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// SecurityContext implements RFC 4121 per-message protection for an
// established AES Kerberos context.
type SecurityContext struct {
	key             types.EncryptionKey
	initiator       bool
	acceptorSubkey  bool
	mu              sync.Mutex
	sendSequence    uint64
	receiveSequence uint64
}

// NewSecurityContext creates an established RFC 4121 security context.
func NewSecurityContext(
	key types.EncryptionKey,
	initiator bool,
	sendSequence, receiveSequence uint64,
	acceptorSubkey bool,
) (*SecurityContext, error) {
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("select RFC 4121 context enctype: %w", err)
	}
	switch key.KeyType {
	case etypeID.AES128_CTS_HMAC_SHA1_96, etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA256_128, etypeID.AES256_CTS_HMAC_SHA384_192:
	default:
		return nil, fmt.Errorf("RFC 4121 context requires an AES key, got enctype %d", key.KeyType)
	}
	keySize := etype.GetKeyByteSize()
	if key.KeyType == etypeID.AES256_CTS_HMAC_SHA384_192 {
		keySize = aes256KeyByteSize
	}
	if len(key.KeyValue) != keySize {
		return nil, fmt.Errorf("invalid key length %d for enctype %d; want %d", len(key.KeyValue), key.KeyType, keySize)
	}
	key.KeyValue = append([]byte(nil), key.KeyValue...)
	result := new(SecurityContext)
	result.key = key
	result.initiator = initiator
	result.acceptorSubkey = acceptorSubkey
	result.sendSequence = sendSequence
	result.receiveSequence = receiveSequence
	return result, nil
}

const (
	aes256KeyByteSize = 32
	bitsPerByte       = 8
)

// Wrap protects a message with integrity and optional confidentiality.
func (context *SecurityContext) Wrap(message []byte, confidential bool) ([]byte, error) {
	if context == nil {
		return nil, errors.New("RFC 4121 security context is nil")
	}
	context.mu.Lock()
	defer context.mu.Unlock()

	flags := context.senderFlags(confidential)
	header := wrapHeader(flags, 0, 0, context.sendSequence)
	etype, err := crypto.GetEtype(context.key.KeyType)
	if err != nil {
		return nil, fmt.Errorf("select RFC 4121 wrap enctype: %w", err)
	}
	if confidential {
		plaintext := append(append([]byte(nil), message...), header...)
		_, ciphertext, cerr := etype.EncryptMessage(context.key.KeyValue, plaintext, context.sendSealUsage())
		if cerr != nil {
			return nil, fmt.Errorf("encrypt RFC 4121 wrap token: %w", cerr)
		}
		context.sendSequence++
		return append(header, ciphertext...), nil
	}

	checksumLength, err := gssUint16Length("checksum", etype.GetHMACBitLength()/bitsPerByte)
	if err != nil {
		return nil, err
	}
	header = wrapHeader(flags, checksumLength, 0, context.sendSequence)
	checksumInput := append(append([]byte(nil), message...), checksumWrapHeader(header)...)
	checksum, err := etype.GetChecksumHash(context.key.KeyValue, checksumInput, context.sendSealUsage())
	if err != nil {
		return nil, fmt.Errorf("compute RFC 4121 wrap checksum: %w", err)
	}
	context.sendSequence++
	header = append(header, message...)
	return append(header, checksum...), nil
}

// Unwrap verifies and optionally decrypts a peer RFC 4121 wrap token.
func (context *SecurityContext) Unwrap(token []byte) ([]byte, bool, error) {
	if context == nil {
		return nil, false, errors.New("RFC 4121 security context is nil")
	}
	context.mu.Lock()
	defer context.mu.Unlock()

	if len(token) < HdrLen {
		return nil, false, errors.New("RFC 4121 wrap token is shorter than its header")
	}
	header := token[:HdrLen]
	if err := context.validateWrapHeader(header); err != nil {
		return nil, false, err
	}
	body := append([]byte(nil), token[HdrLen:]...)
	if len(body) == 0 {
		return nil, false, errors.New("invalid RFC 4121 wrap body")
	}
	rotateLeft(body, int(binary.BigEndian.Uint16(header[6:8])))

	enctype, err := crypto.GetEtype(context.key.KeyType)
	if err != nil {
		return nil, false, fmt.Errorf("select RFC 4121 unwrap enctype: %w", err)
	}
	confidential := header[2]&MICTokenFlagSealed != 0
	var message []byte
	if confidential {
		message, err = context.unwrapSealed(header, body, enctype)
	} else {
		message, err = context.verifyIntegrityWrap(header, body, enctype)
	}
	if err != nil {
		return nil, false, err
	}
	context.receiveSequence++
	return append([]byte(nil), message...), confidential, nil
}

// GetMIC returns an RFC 4121 MIC token for message.
func (context *SecurityContext) GetMIC(message []byte) ([]byte, error) {
	if context == nil {
		return nil, errors.New("RFC 4121 security context is nil")
	}
	context.mu.Lock()
	defer context.mu.Unlock()
	token := MICToken{
		Flags: context.senderFlags(false), SndSeqNum: context.sendSequence, Payload: message, Checksum: nil,
	}
	if err := token.SetChecksum(context.key, context.sendSignUsage()); err != nil {
		return nil, err
	}
	encoded, err := token.Marshal()
	if err == nil {
		context.sendSequence++
	}
	return encoded, err
}

// VerifyMIC verifies an RFC 4121 MIC token and its sequence number.
func (context *SecurityContext) VerifyMIC(message, encoded []byte) error {
	if context == nil {
		return errors.New("RFC 4121 security context is nil")
	}
	context.mu.Lock()
	defer context.mu.Unlock()
	var token MICToken
	if err := token.Unmarshal(encoded, context.initiator); err != nil {
		return err
	}
	if err := context.validatePeerFlags(token.Flags, false); err != nil {
		return err
	}
	if token.SndSeqNum != context.receiveSequence {
		return fmt.Errorf("RFC 4121 MIC sequence %d, want %d", token.SndSeqNum, context.receiveSequence)
	}
	token.Payload = message
	_, err := token.Verify(context.key, context.receiveSignUsage())
	if err != nil {
		return fmt.Errorf("invalid RFC 4121 MIC: %w", err)
	}
	context.receiveSequence++
	return nil
}

// NegoExKey returns the key for locally generated NEGOEX VERIFY messages.
func (context *SecurityContext) NegoExKey() (types.EncryptionKey, bool) {
	if context == nil {
		var key types.EncryptionKey
		return key, false
	}
	return cloneContextKey(context.key), true
}

// NegoExVerifyKey returns the key for peer NEGOEX VERIFY messages.
func (context *SecurityContext) NegoExVerifyKey() (types.EncryptionKey, bool) {
	if context == nil {
		var key types.EncryptionKey
		return key, false
	}
	return cloneContextKey(context.key), true
}

func (context *SecurityContext) validateWrapHeader(header []byte) error {
	if !bytes.Equal(header[:2], wrapTokenID()[:]) || header[3] != FillerByte {
		return errors.New("invalid RFC 4121 wrap token header")
	}
	if err := context.validatePeerFlags(header[2], true); err != nil {
		return err
	}
	sequence := binary.BigEndian.Uint64(header[8:16])
	if sequence != context.receiveSequence {
		return fmt.Errorf("RFC 4121 wrap sequence %d, want %d", sequence, context.receiveSequence)
	}
	return nil
}

func (context *SecurityContext) unwrapSealed(header, body []byte, enctype etype.EType) ([]byte, error) {
	minimumLength := enctype.GetHMACBitLength()/bitsPerByte + enctype.GetConfounderByteSize() + HdrLen
	if len(body) < minimumLength {
		return nil, errors.New("RFC 4121 encrypted body is too short")
	}
	plaintext, err := crypto.DecryptMessage(body, context.key, context.receiveSealUsage())
	if err != nil {
		return nil, fmt.Errorf("decrypt RFC 4121 wrap token: %w", err)
	}
	ec := int(binary.BigEndian.Uint16(header[4:6]))
	if len(plaintext) < HdrLen+ec {
		return nil, errors.New("invalid RFC 4121 wrap extra count")
	}
	encryptedHeader := append([]byte(nil), header...)
	encryptedHeader[6], encryptedHeader[7] = 0, 0
	if !hmac.Equal(plaintext[len(plaintext)-HdrLen:], encryptedHeader) {
		return nil, errors.New("RFC 4121 encrypted header mismatch")
	}
	return plaintext[:len(plaintext)-HdrLen-ec], nil
}

func (context *SecurityContext) verifyIntegrityWrap(header, body []byte, enctype etype.EType) ([]byte, error) {
	ec := int(binary.BigEndian.Uint16(header[4:6]))
	if ec <= 0 || ec > len(body) || ec != enctype.GetHMACBitLength()/bitsPerByte {
		return nil, errors.New("invalid RFC 4121 integrity wrap lengths")
	}
	message, checksum := body[:len(body)-ec], body[len(body)-ec:]
	checksumInput := append(append([]byte(nil), message...), checksumWrapHeader(header)...)
	expected, err := enctype.GetChecksumHash(context.key.KeyValue, checksumInput, context.receiveSealUsage())
	if err != nil {
		return nil, fmt.Errorf("compute RFC 4121 wrap checksum: %w", err)
	}
	if !hmac.Equal(checksum, expected) {
		return nil, errors.New("invalid RFC 4121 wrap checksum")
	}
	return message, nil
}

func (context *SecurityContext) senderFlags(confidential bool) byte {
	var flags byte
	if !context.initiator {
		flags |= MICTokenFlagSentByAcceptor
	}
	if confidential {
		flags |= MICTokenFlagSealed
	}
	if context.acceptorSubkey {
		flags |= MICTokenFlagAcceptorSubkey
	}
	return flags
}

func (context *SecurityContext) validatePeerFlags(flags byte, wrap bool) error {
	if (!wrap && flags&MICTokenFlagSealed != 0) ||
		(flags&MICTokenFlagSentByAcceptor != 0) != context.initiator ||
		(flags&MICTokenFlagAcceptorSubkey != 0) != context.acceptorSubkey {
		return fmt.Errorf("invalid RFC 4121 token flags 0x%02x", flags)
	}
	return nil
}

func (context *SecurityContext) sendSealUsage() uint32 {
	if context.initiator {
		return keyusage.GSSAPI_INITIATOR_SEAL
	}
	return keyusage.GSSAPI_ACCEPTOR_SEAL
}

func (context *SecurityContext) receiveSealUsage() uint32 {
	if context.initiator {
		return keyusage.GSSAPI_ACCEPTOR_SEAL
	}
	return keyusage.GSSAPI_INITIATOR_SEAL
}

func (context *SecurityContext) sendSignUsage() uint32 {
	if context.initiator {
		return keyusage.GSSAPI_INITIATOR_SIGN
	}
	return keyusage.GSSAPI_ACCEPTOR_SIGN
}

func (context *SecurityContext) receiveSignUsage() uint32 {
	if context.initiator {
		return keyusage.GSSAPI_ACCEPTOR_SIGN
	}
	return keyusage.GSSAPI_INITIATOR_SIGN
}

func wrapHeader(flags byte, ec, rrc uint16, sequence uint64) []byte {
	header := make([]byte, HdrLen)
	copy(header, wrapTokenID()[:])
	header[2], header[3] = flags, FillerByte
	binary.BigEndian.PutUint16(header[4:6], ec)
	binary.BigEndian.PutUint16(header[6:8], rrc)
	binary.BigEndian.PutUint64(header[8:16], sequence)
	return header
}

func checksumWrapHeader(header []byte) []byte {
	checksumHeader := append([]byte(nil), header...)
	for index := 4; index < 8; index++ {
		checksumHeader[index] = 0
	}
	return checksumHeader
}

func rotateLeft(value []byte, count int) {
	if len(value) == 0 {
		return
	}
	count %= len(value)
	rotated := append(append([]byte(nil), value[count:]...), value[:count]...)
	copy(value, rotated)
}

func rotateRight(value []byte, count int) {
	if len(value) == 0 {
		return
	}
	count %= len(value)
	rotateLeft(value, len(value)-count)
}

func cloneContextKey(key types.EncryptionKey) types.EncryptionKey {
	key.KeyValue = append([]byte(nil), key.KeyValue...)
	return key
}
