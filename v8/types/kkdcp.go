package types

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/jcmturner/gofork/encoding/asn1"
)

const kkdcpLengthPrefixSize = 4

// KDCProxyMessage implements the KDC-PROXY-MESSAGE type from MS-KKDCP.
type KDCProxyMessage struct {
	KerbMessage   []byte `asn1:"explicit,tag:0"`
	TargetDomain  string `asn1:"optional,generalstring,explicit,tag:1"`
	DCLocatorHint int32  `asn1:"optional,explicit,tag:2"`
}

func kkdcpUint32(name string, length int) (uint32, error) {
	if length < 0 || uint64(length) > math.MaxUint32 { // #nosec G115 -- nonnegative branch bounded above.
		return 0, fmt.Errorf("%s length %d exceeds uint32", name, length)
	}
	return uint32(length), nil // #nosec G115 -- bounded by MaxUint32 above.
}

func kkdcpUint64(name string, length int) (uint64, error) {
	if length < 0 {
		return 0, fmt.Errorf("%s length %d cannot be negative", name, length)
	}
	return uint64(length), nil
}

// NewKDCProxyMessage wraps a Kerberos message with its network-order length.
func NewKDCProxyMessage(message []byte, targetDomain string, dcLocatorHint int32) (KDCProxyMessage, error) {
	if uint64(len(message)) > math.MaxUint32 {
		//nolint:staticcheck // Preserve the exact error text returned to callers.
		return KDCProxyMessage{}, fmt.Errorf("Kerberos message length %d exceeds uint32", len(message))
	}
	framed := make([]byte, kkdcpLengthPrefixSize+len(message))
	messageLength, err := kkdcpUint32("Kerberos message", len(message))
	if err != nil {
		return KDCProxyMessage{}, err
	}
	binary.BigEndian.PutUint32(framed, messageLength)
	copy(framed[kkdcpLengthPrefixSize:], message)
	return KDCProxyMessage{KerbMessage: framed, TargetDomain: targetDomain, DCLocatorHint: dcLocatorHint}, nil
}

// Marshal encodes the KDC-PROXY-MESSAGE using DER.
func (m KDCProxyMessage) Marshal() ([]byte, error) {
	b, err := asn1.Marshal(m)
	if err != nil {
		return b, fmt.Errorf("encode KDC-PROXY-MESSAGE: %w", err)
	}
	return b, nil
}

// Unmarshal decodes a DER-encoded KDC-PROXY-MESSAGE.
func (m *KDCProxyMessage) Unmarshal(b []byte) error {
	rest, err := asn1.Unmarshal(b, m)
	if err != nil {
		return fmt.Errorf("decode KDC-PROXY-MESSAGE: %w", err)
	}
	if len(rest) != 0 {
		return fmt.Errorf("KDC-PROXY-MESSAGE contains %d trailing bytes", len(rest))
	}
	return nil
}

// KerberosMessage validates and removes the four-byte message-length prefix.
func (m KDCProxyMessage) KerberosMessage() ([]byte, error) {
	if len(m.KerbMessage) < kkdcpLengthPrefixSize {
		return nil, errors.New("KKDCP Kerberos message is shorter than its length prefix")
	}
	length := binary.BigEndian.Uint32(m.KerbMessage[:kkdcpLengthPrefixSize])
	payload := m.KerbMessage[kkdcpLengthPrefixSize:]
	payloadLength, err := kkdcpUint64("KKDCP payload", len(payload))
	if err != nil {
		return nil, err
	}
	if uint64(length) != payloadLength {
		return nil, fmt.Errorf("KKDCP Kerberos message length %d does not match payload length %d", length, payloadLength)
	}
	return append([]byte(nil), payload...), nil
}
