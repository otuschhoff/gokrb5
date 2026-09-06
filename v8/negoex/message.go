// Package negoex implements the SPNEGO Extended Negotiation Security
// Mechanism defined by MS-NEGOEX.
package negoex

import (
	"encoding"
	"encoding/binary"
	"errors"
	"fmt"
)

const MessageSignature uint64 = 0x535458454f47454e

const (
	MessageTypeInitiatorNego uint32 = iota
	MessageTypeAcceptorNego
	MessageTypeInitiatorMetaData
	MessageTypeAcceptorMetaData
	MessageTypeChallenge
	MessageTypeAPRequest
	MessageTypeVerify
	MessageTypeAlert
)

const (
	messageHeaderLength  = 40
	negoHeaderLength     = 96
	exchangeHeaderLength = 64
	verifyHeaderLength   = 80
	alertHeaderLength    = 72
	extensionLength      = 12
	alertLength          = 12
	alertPulseLength     = 8

	ChecksumSchemeRFC3961 uint32 = 1
	ExtensionFlagCritical uint32 = 0x80000000
	AlertTypePulse        uint32 = 1
	AlertVerifyNoKey      uint32 = 1
)

var (
	ErrInvalidSignature          = errors.New("invalid NEGOEX message signature")
	ErrInvalidMessageType        = errors.New("invalid NEGOEX message type")
	ErrInvalidMessageSize        = errors.New("invalid NEGOEX message size")
	ErrUnsupportedVersion        = errors.New("unsupported NEGOEX protocol version")
	ErrUnsupportedExtension      = errors.New("unsupported critical NEGOEX extension")
	ErrUnsupportedChecksumScheme = errors.New("unsupported NEGOEX checksum scheme")
)

// AuthScheme identifies a NEGOEX authentication mechanism. Its byte order is
// the on-wire GUID byte order used by MS-NEGOEX.
type AuthScheme [16]byte

// ConversationID identifies one NEGOEX exchange.
type ConversationID [16]byte

// MessageHeader is common to every NEGOEX message.
type MessageHeader struct {
	Signature      uint64
	MessageType    uint32
	SequenceNum    uint32
	HeaderLength   uint32
	MessageLength  uint32
	ConversationID ConversationID
}

// Extension is a NEGOEX negotiation extension.
type Extension struct {
	Type  uint32
	Value []byte
}

// Checksum is the VERIFY_MESSAGE checksum descriptor.
type Checksum struct {
	HeaderLength uint32
	Scheme       uint32
	Type         uint32
	Value        []byte
}

// Alert is an entry in an ALERT_MESSAGE.
type Alert struct {
	Type  uint32
	Value []byte
}

// NegoMessage advertises authentication schemes and extensions.
type NegoMessage struct {
	Header          MessageHeader
	Random          [32]byte
	ProtocolVersion uint64
	AuthSchemes     []AuthScheme
	Extensions      []Extension
}

// ExchangeMessage carries metadata or an authentication mechanism token.
type ExchangeMessage struct {
	Header     MessageHeader
	AuthScheme AuthScheme
	Exchange   []byte
}

// VerifyMessage binds the conversation transcript to the selected mechanism.
type VerifyMessage struct {
	Header     MessageHeader
	AuthScheme AuthScheme
	Checksum   Checksum
	Offset     int
}

// AlertMessage carries protocol status and advisory alerts.
type AlertMessage struct {
	Header     MessageHeader
	AuthScheme AuthScheme
	ErrorCode  uint32
	Alerts     []Alert
}

// Message is a decoded NEGOEX message.
type Message interface {
	encoding.BinaryMarshaler
	messageHeader() MessageHeader
}

func (m *NegoMessage) messageHeader() MessageHeader     { return m.Header }
func (m *ExchangeMessage) messageHeader() MessageHeader { return m.Header }
func (m *VerifyMessage) messageHeader() MessageHeader   { return m.Header }
func (m *AlertMessage) messageHeader() MessageHeader    { return m.Header }

// Marshal serializes a token containing one or more NEGOEX messages.
func Marshal(messages ...Message) ([]byte, error) {
	var token []byte
	for _, message := range messages {
		if message == nil {
			return nil, errors.New("cannot marshal a nil NEGOEX message")
		}
		encoded, err := message.MarshalBinary()
		if err != nil {
			return nil, err
		}
		token = append(token, encoded...)
	}
	return token, nil
}

// Unmarshal parses all concatenated messages in a NEGOEX token.
func Unmarshal(token []byte) ([]Message, error) {
	var messages []Message
	for offset := 0; offset < len(token); {
		if len(token)-offset < messageHeaderLength {
			return nil, ErrInvalidMessageSize
		}
		messageLength := int(binary.LittleEndian.Uint32(token[offset+20 : offset+24]))
		if messageLength < messageHeaderLength || messageLength > len(token)-offset {
			return nil, ErrInvalidMessageSize
		}
		message, err := unmarshalMessage(token[offset : offset+messageLength])
		if err != nil {
			return nil, err
		}
		if verify, ok := message.(*VerifyMessage); ok {
			verify.Offset = offset
		}
		messages = append(messages, message)
		offset += messageLength
	}
	return messages, nil
}

func unmarshalMessage(data []byte) (Message, error) {
	header, err := unmarshalHeader(data)
	if err != nil {
		return nil, err
	}
	switch header.MessageType {
	case MessageTypeInitiatorNego, MessageTypeAcceptorNego:
		return unmarshalNego(header, data)
	case MessageTypeInitiatorMetaData, MessageTypeAcceptorMetaData, MessageTypeChallenge, MessageTypeAPRequest:
		return unmarshalExchange(header, data)
	case MessageTypeVerify:
		return unmarshalVerify(header, data)
	case MessageTypeAlert:
		return unmarshalAlert(header, data)
	default:
		return nil, ErrInvalidMessageType
	}
}

func unmarshalHeader(data []byte) (MessageHeader, error) {
	var header MessageHeader
	if len(data) < messageHeaderLength {
		return header, ErrInvalidMessageSize
	}
	header.Signature = binary.LittleEndian.Uint64(data[0:8])
	header.MessageType = binary.LittleEndian.Uint32(data[8:12])
	header.SequenceNum = binary.LittleEndian.Uint32(data[12:16])
	header.HeaderLength = binary.LittleEndian.Uint32(data[16:20])
	header.MessageLength = binary.LittleEndian.Uint32(data[20:24])
	copy(header.ConversationID[:], data[24:40])
	if header.Signature != MessageSignature {
		return header, ErrInvalidSignature
	}
	if header.MessageLength != uint32(len(data)) || header.HeaderLength < messageHeaderLength || header.HeaderLength > header.MessageLength {
		return header, ErrInvalidMessageSize
	}
	return header, nil
}

func marshalHeader(header MessageHeader, messageType, headerLength, messageLength uint32) []byte {
	header.Signature = MessageSignature
	header.MessageType = messageType
	header.HeaderLength = headerLength
	header.MessageLength = messageLength
	data := make([]byte, headerLength)
	binary.LittleEndian.PutUint64(data[0:8], header.Signature)
	binary.LittleEndian.PutUint32(data[8:12], header.MessageType)
	binary.LittleEndian.PutUint32(data[12:16], header.SequenceNum)
	binary.LittleEndian.PutUint32(data[16:20], header.HeaderLength)
	binary.LittleEndian.PutUint32(data[20:24], header.MessageLength)
	copy(data[24:40], header.ConversationID[:])
	return data
}

func checkHeaderLength(header MessageHeader, expected uint32) error {
	if header.HeaderLength != expected {
		return fmt.Errorf("%w: got header length %d, want %d", ErrInvalidMessageSize, header.HeaderLength, expected)
	}
	return nil
}
