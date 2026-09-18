package gssapi

import (
	"bytes"
	"crypto/hmac"
	"encoding/binary"
	"fmt"
	"sync"

	"github.com/otuschhoff/gokrb5/v8/crypto"
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
func NewSecurityContext(key types.EncryptionKey, initiator bool, sendSequence, receiveSequence uint64, acceptorSubkey bool) (*SecurityContext, error) {
	etype, err := crypto.GetEtype(key.KeyType)
	if err != nil {
		return nil, err
	}
	switch key.KeyType {
	case 17, 18, 19, 20:
	default:
		return nil, fmt.Errorf("RFC 4121 context requires an AES key, got enctype %d", key.KeyType)
	}
	keySize := etype.GetKeyByteSize()
	if key.KeyType == 20 {
		keySize = 32
	}
	if len(key.KeyValue) != keySize {
		return nil, fmt.Errorf("invalid key length %d for enctype %d; want %d", len(key.KeyValue), key.KeyType, keySize)
	}
	key.KeyValue = append([]byte(nil), key.KeyValue...)
	return &SecurityContext{
		key: key, initiator: initiator, acceptorSubkey: acceptorSubkey,
		sendSequence: sendSequence, receiveSequence: receiveSequence,
	}, nil
}

// Wrap protects a message with integrity and optional confidentiality.
func (context *SecurityContext) Wrap(message []byte, confidential bool) ([]byte, error) {
	context.mu.Lock()
	defer context.mu.Unlock()

	flags := context.senderFlags(confidential)
	header := wrapHeader(flags, 0, 0, context.sendSequence)
	etype, err := crypto.GetEtype(context.key.KeyType)
	if err != nil {
		return nil, err
	}
	if confidential {
		plaintext := append(append([]byte(nil), message...), header...)
		_, ciphertext, err := etype.EncryptMessage(context.key.KeyValue, plaintext, context.sendSealUsage())
		if err != nil {
			return nil, err
		}
		context.sendSequence++
		return append(header, ciphertext...), nil
	}

	checksumLength := uint16(etype.GetHMACBitLength() / 8)
	header = wrapHeader(flags, checksumLength, 0, context.sendSequence)
	checksumHeader := checksumWrapHeader(header)
	checksum, err := etype.GetChecksumHash(context.key.KeyValue, append(append([]byte(nil), message...), checksumHeader...), context.sendSealUsage())
	if err != nil {
		return nil, err
	}
	context.sendSequence++
	token := append(header, message...)
	return append(token, checksum...), nil
}

// Unwrap verifies and optionally decrypts a peer RFC 4121 wrap token.
func (context *SecurityContext) Unwrap(token []byte) ([]byte, bool, error) {
	context.mu.Lock()
	defer context.mu.Unlock()

	if len(token) < HdrLen {
		return nil, false, fmt.Errorf("RFC 4121 wrap token is shorter than its header")
	}
	header := token[:HdrLen]
	if !bytes.Equal(header[:2], getGssWrapTokenId()[:]) || header[3] != FillerByte {
		return nil, false, fmt.Errorf("invalid RFC 4121 wrap token header")
	}
	flags := header[2]
	if err := context.validatePeerFlags(flags, true); err != nil {
		return nil, false, err
	}
	sequence := binary.BigEndian.Uint64(header[8:16])
	if sequence != context.receiveSequence {
		return nil, false, fmt.Errorf("RFC 4121 wrap sequence %d, want %d", sequence, context.receiveSequence)
	}

	confidential := flags&MICTokenFlagSealed != 0
	ec := int(binary.BigEndian.Uint16(header[4:6]))
	rrc := int(binary.BigEndian.Uint16(header[6:8]))
	body := append([]byte(nil), token[HdrLen:]...)
	if len(body) == 0 {
		return nil, false, fmt.Errorf("invalid RFC 4121 wrap body")
	}
	rotateLeft(body, rrc)

	etype, err := crypto.GetEtype(context.key.KeyType)
	if err != nil {
		return nil, false, err
	}
	if confidential {
		minimumLength := etype.GetHMACBitLength()/8 + etype.GetConfounderByteSize() + HdrLen
		if len(body) < minimumLength {
			return nil, false, fmt.Errorf("RFC 4121 encrypted body is too short")
		}
		plaintext, err := crypto.DecryptMessage(body, context.key, context.receiveSealUsage())
		if err != nil {
			return nil, false, err
		}
		if len(plaintext) < HdrLen+ec {
			return nil, false, fmt.Errorf("invalid RFC 4121 wrap extra count")
		}
		encryptedHeader := append([]byte(nil), header...)
		encryptedHeader[6], encryptedHeader[7] = 0, 0
		if !hmac.Equal(plaintext[len(plaintext)-HdrLen:], encryptedHeader) {
			return nil, false, fmt.Errorf("RFC 4121 encrypted header mismatch")
		}
		context.receiveSequence++
		return append([]byte(nil), plaintext[:len(plaintext)-HdrLen-ec]...), true, nil
	}

	if ec <= 0 || ec > len(body) || ec != etype.GetHMACBitLength()/8 {
		return nil, false, fmt.Errorf("invalid RFC 4121 integrity wrap lengths")
	}
	message, checksum := body[:len(body)-ec], body[len(body)-ec:]
	expected, err := etype.GetChecksumHash(context.key.KeyValue, append(append([]byte(nil), message...), checksumWrapHeader(header)...), context.receiveSealUsage())
	if err != nil || !hmac.Equal(checksum, expected) {
		return nil, false, fmt.Errorf("invalid RFC 4121 wrap checksum")
	}
	context.receiveSequence++
	return append([]byte(nil), message...), false, nil
}

// GetMIC returns an RFC 4121 MIC token for message.
func (context *SecurityContext) GetMIC(message []byte) ([]byte, error) {
	context.mu.Lock()
	defer context.mu.Unlock()
	token := MICToken{Flags: context.senderFlags(false), SndSeqNum: context.sendSequence, Payload: message}
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
	return cloneContextKey(context.key), true
}

// NegoExVerifyKey returns the key for peer NEGOEX VERIFY messages.
func (context *SecurityContext) NegoExVerifyKey() (types.EncryptionKey, bool) {
	return cloneContextKey(context.key), true
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
	copy(header, getGssWrapTokenId()[:])
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
