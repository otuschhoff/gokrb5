package kadmin

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"

	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

const (
	uint16Bytes         = 2
	passwordPolicyBytes = 30
)

// Request message for changing password.
type Request struct {
	APREQ   messages.APReq
	KRBPriv messages.KRBPriv
}

// Reply message for a password change.
type Reply struct {
	MessageLength  int
	Version        int
	APREPLength    int
	APREP          messages.APRep
	KRBPriv        messages.KRBPriv
	KRBError       messages.KRBError
	IsKRBError     bool
	ResultCode     uint16
	Result         string
	PasswordPolicy *PasswordPolicy
}

// PasswordPolicy is the policy information returned by Active Directory in a
// 30-byte kpasswd result payload. ExpireIn and MinAge are in 100-nanosecond ticks.
type PasswordPolicy struct {
	Version    uint16
	MinLength  uint32
	History    uint32
	Properties uint32
	ExpireIn   uint64
	MinAge     uint64
}

func kadminUint16(name string, length int) (uint16, error) {
	if length < 0 || length > int(^uint16(0)) {
		return 0, fmt.Errorf("%s length %d exceeds uint16 range", name, length)
	}
	return uint16(length), nil
}

// Marshal a Request into a byte slice.
func (m *Request) Marshal() ([]byte, error) {
	var b []byte
	var err error
	b = []byte{255, 128} // protocol version number: contains the hex constant 0xff80 (big-endian integer).
	ab, e := m.APREQ.Marshal()
	if e != nil {
		err = fmt.Errorf("error marshaling AP_REQ: %w", e)
		return b, err
	}
	if len(ab) > math.MaxUint16 {
		err = errors.New("length of AP_REQ greater then max Uint16 size")
		return b, err
	}
	al := make([]byte, uint16Bytes)
	apReqLength, err := kadminUint16("AP_REQ", len(ab))
	if err != nil {
		return b, err
	}
	binary.BigEndian.PutUint16(al, apReqLength)
	b = append(b, al...)
	b = append(b, ab...)
	pb, e := m.KRBPriv.Marshal()
	if e != nil {
		err = fmt.Errorf("error marshaling KRB_Priv: %w", e)
		return b, err
	}
	b = append(b, pb...)
	frameLength := len(b) + uint16Bytes
	if frameLength > math.MaxUint16 {
		err = errors.New("length of message greater then max Uint16 size")
		return b, err
	}
	messageLength, err := kadminUint16("message", frameLength)
	if err != nil {
		return b, err
	}
	ml := make([]byte, uint16Bytes, frameLength)
	binary.BigEndian.PutUint16(ml, messageLength)
	b = append(ml, b...)
	return b, err
}

// Unmarshal decodes a framed kpasswd reply. On error, the receiver is unchanged.
func (m *Reply) Unmarshal(b []byte) error {
	const headerSize = 6
	if len(b) < headerSize {
		return errors.New("kadmin reply is shorter than the 6-byte header")
	}
	var reply Reply
	reply.MessageLength = int(binary.BigEndian.Uint16(b[0:2]))
	if reply.MessageLength < headerSize || reply.MessageLength > len(b) {
		return fmt.Errorf("kadmin reply has invalid message length %d for %d bytes", reply.MessageLength, len(b))
	}
	reply.Version = int(binary.BigEndian.Uint16(b[2:4]))
	if reply.Version != 1 {
		return fmt.Errorf("kadmin reply has incorrect protocol version number: %d", reply.Version)
	}
	apRepLength := int(binary.BigEndian.Uint16(b[4:6]))
	reply.APREPLength = apRepLength
	payload := b[headerSize:reply.MessageLength]
	if apRepLength > len(payload) {
		return fmt.Errorf("kadmin reply AP_REP length %d exceeds message payload", apRepLength)
	}
	if err := reply.unmarshalMessages(payload[:apRepLength], payload[apRepLength:]); err != nil {
		return err
	}
	*m = reply
	return nil
}

// Decrypt decodes the result in a protected reply or returns the server's KRBError.
func (m *Reply) Decrypt(key types.EncryptionKey) error {
	if m.IsKRBError {
		return m.KRBError
	}
	if err := m.KRBPriv.DecryptEncPart(key); err != nil {
		return fmt.Errorf("decrypt kpasswd KRB-PRIV: %w", err)
	}
	return m.decodeResult(m.KRBPriv.DecryptedEncPart.UserData)
}

func (m *Reply) unmarshalMessages(apRep, payload []byte) error {
	if len(apRep) == 0 {
		m.IsKRBError = true
		if err := m.KRBError.Unmarshal(payload); err != nil {
			return fmt.Errorf("decode kpasswd KRB-ERROR: %w", err)
		}
		return m.decodeResult(m.KRBError.EData)
	}
	if err := m.APREP.Unmarshal(apRep); err != nil {
		return fmt.Errorf("decode kpasswd AP-REP: %w", err)
	}
	if err := m.KRBPriv.Unmarshal(payload); err != nil {
		return fmt.Errorf("decode kpasswd KRB-PRIV: %w", err)
	}
	return nil
}

func (m *Reply) decodeResult(b []byte) error {
	var err error
	m.ResultCode, m.Result, m.PasswordPolicy, err = parseResponse(b)
	if err != nil {
		return fmt.Errorf("decode kpasswd result: %w", err)
	}
	return nil
}

func parseResponse(b []byte) (uint16, string, *PasswordPolicy, error) {
	if len(b) < uint16Bytes {
		return 0, "", nil, errors.New("kadmin response is shorter than the result code")
	}
	resultCode := binary.BigEndian.Uint16(b[:uint16Bytes])
	result := b[uint16Bytes:]
	if len(result) >= passwordPolicyBytes {
		policyOffset := len(result) - passwordPolicyBytes
		policyData := result[policyOffset:]
		if policyData[0] == 0 && policyData[1] == 0 {
			policy := &PasswordPolicy{
				Version:    binary.BigEndian.Uint16(policyData[0:2]),
				MinLength:  binary.BigEndian.Uint32(policyData[2:6]),
				History:    binary.BigEndian.Uint32(policyData[6:10]),
				Properties: binary.BigEndian.Uint32(policyData[10:14]),
				ExpireIn:   binary.BigEndian.Uint64(policyData[14:22]),
				MinAge:     binary.BigEndian.Uint64(policyData[22:30]),
			}
			return resultCode, string(result[:policyOffset]), policy, nil
		}
	}
	return resultCode, string(result), nil, nil
}
