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
	verisonHex = "ff80"
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

// Marshal a Request into a byte slice.
func (m *Request) Marshal() (b []byte, err error) {
	b = []byte{255, 128} // protocol version number: contains the hex constant 0xff80 (big-endian integer).
	ab, e := m.APREQ.Marshal()
	if e != nil {
		err = fmt.Errorf("error marshaling AP_REQ: %v", e)
		return
	}
	if len(ab) > math.MaxUint16 {
		err = errors.New("length of AP_REQ greater then max Uint16 size")
		return
	}
	al := make([]byte, 2)
	binary.BigEndian.PutUint16(al, uint16(len(ab)))
	b = append(b, al...)
	b = append(b, ab...)
	pb, e := m.KRBPriv.Marshal()
	if e != nil {
		err = fmt.Errorf("error marshaling KRB_Priv: %v", e)
		return
	}
	b = append(b, pb...)
	if len(b)+2 > math.MaxUint16 {
		err = errors.New("length of message greater then max Uint16 size")
		return
	}
	ml := make([]byte, 2)
	binary.BigEndian.PutUint16(ml, uint16(len(b)+2))
	b = append(ml, b...)
	return
}

// Unmarshal a byte slice into a Reply.
func (m *Reply) Unmarshal(b []byte) error {
	if len(b) < 6 {
		return errors.New("kadmin reply is shorter than the 6-byte header")
	}
	m.MessageLength = int(binary.BigEndian.Uint16(b[0:2]))
	if m.MessageLength < 6 || m.MessageLength > len(b) {
		return fmt.Errorf("kadmin reply has invalid message length %d for %d bytes", m.MessageLength, len(b))
	}
	m.Version = int(binary.BigEndian.Uint16(b[2:4]))
	if m.Version != 1 {
		return fmt.Errorf("kadmin reply has incorrect protocol version number: %d", m.Version)
	}
	m.APREPLength = int(binary.BigEndian.Uint16(b[4:6]))
	if m.APREPLength > m.MessageLength-6 {
		return fmt.Errorf("kadmin reply AP_REP length %d exceeds message payload", m.APREPLength)
	}
	if m.APREPLength != 0 {
		err := m.APREP.Unmarshal(b[6 : 6+m.APREPLength])
		if err != nil {
			return err
		}
		err = m.KRBPriv.Unmarshal(b[6+m.APREPLength : m.MessageLength])
		if err != nil {
			return err
		}
	} else {
		m.IsKRBError = true
		if err := m.KRBError.Unmarshal(b[6:m.MessageLength]); err != nil {
			return err
		}
		var parseErr error
		m.ResultCode, m.Result, m.PasswordPolicy, parseErr = parseResponse(m.KRBError.EData)
		if parseErr != nil {
			return parseErr
		}
	}
	return nil
}

func parseResponse(b []byte) (uint16, string, *PasswordPolicy, error) {
	if len(b) < 2 {
		return 0, "", nil, errors.New("kadmin response is shorter than the result code")
	}
	resultCode := binary.BigEndian.Uint16(b[:2])
	result := b[2:]
	if len(result) >= 30 {
		policyOffset := len(result) - 30
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

// Decrypt the encrypted part of the KRBError within the change password Reply.
func (m *Reply) Decrypt(key types.EncryptionKey) error {
	if m.IsKRBError {
		return m.KRBError
	}
	err := m.KRBPriv.DecryptEncPart(key)
	if err != nil {
		return err
	}
	m.ResultCode, m.Result, m.PasswordPolicy, err = parseResponse(m.KRBPriv.DecryptedEncPart.UserData)
	return err
}
