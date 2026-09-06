package types

import (
	"encoding/binary"
	"fmt"
	"math"

	"github.com/jcmturner/gofork/encoding/asn1"
)

// KDCProxyMessage implements the KDC-PROXY-MESSAGE type from MS-KKDCP.
type KDCProxyMessage struct {
	KerbMessage   []byte `asn1:"explicit,tag:0"`
	TargetDomain  string `asn1:"optional,generalstring,explicit,tag:1"`
	DCLocatorHint int32  `asn1:"optional,explicit,tag:2"`
}

// NewKDCProxyMessage wraps a Kerberos message with its network-order length.
func NewKDCProxyMessage(message []byte, targetDomain string, dcLocatorHint int32) (KDCProxyMessage, error) {
	if uint64(len(message)) > math.MaxUint32 {
		return KDCProxyMessage{}, fmt.Errorf("Kerberos message length %d exceeds uint32", len(message))
	}
	framed := make([]byte, 4+len(message))
	binary.BigEndian.PutUint32(framed, uint32(len(message)))
	copy(framed[4:], message)
	return KDCProxyMessage{KerbMessage: framed, TargetDomain: targetDomain, DCLocatorHint: dcLocatorHint}, nil
}

// Marshal encodes the KDC-PROXY-MESSAGE using DER.
func (m KDCProxyMessage) Marshal() ([]byte, error) {
	return asn1.Marshal(m)
}

// Unmarshal decodes a DER-encoded KDC-PROXY-MESSAGE.
func (m *KDCProxyMessage) Unmarshal(b []byte) error {
	rest, err := asn1.Unmarshal(b, m)
	if err != nil {
		return err
	}
	if len(rest) != 0 {
		return fmt.Errorf("KDC-PROXY-MESSAGE contains %d trailing bytes", len(rest))
	}
	return nil
}

// KerberosMessage validates and removes the four-byte message-length prefix.
func (m KDCProxyMessage) KerberosMessage() ([]byte, error) {
	if len(m.KerbMessage) < 4 {
		return nil, fmt.Errorf("KKDCP Kerberos message is shorter than its length prefix")
	}
	length := binary.BigEndian.Uint32(m.KerbMessage[:4])
	if uint64(length) != uint64(len(m.KerbMessage)-4) {
		return nil, fmt.Errorf("KKDCP Kerberos message length %d does not match payload length %d", length, len(m.KerbMessage)-4)
	}
	return append([]byte(nil), m.KerbMessage[4:]...), nil
}
