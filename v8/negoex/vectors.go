package negoex

import (
	"encoding/binary"
	"fmt"
	"math"
)

func (m *NegoMessage) MarshalBinary() ([]byte, error) {
	if len(m.AuthSchemes) > math.MaxUint16 || len(m.Extensions) > math.MaxUint16 {
		return nil, ErrInvalidMessageSize
	}
	payloadLength := uint64(len(m.AuthSchemes)) * uint64(len(AuthScheme{}))
	for _, extension := range m.Extensions {
		if uint64(len(extension.Value)) > math.MaxUint32 {
			return nil, ErrInvalidMessageSize
		}
		payloadLength += uint64(extensionLength) + uint64(len(extension.Value))
	}
	if payloadLength > math.MaxUint32-negoHeaderLength || payloadLength > uint64(int(^uint(0)>>1)-negoHeaderLength) {
		return nil, ErrInvalidMessageSize
	}
	data := marshalHeader(m.Header, m.Header.MessageType, negoHeaderLength, uint32(negoHeaderLength+int(payloadLength)))
	copy(data[40:72], m.Random[:])
	binary.LittleEndian.PutUint64(data[72:80], m.ProtocolVersion)
	authOffset := len(data)
	data = append(data, make([]byte, len(m.AuthSchemes)*len(AuthScheme{}))...)
	for index := range m.AuthSchemes {
		copy(data[authOffset+index*16:], m.AuthSchemes[index][:])
	}
	extensionsOffset := len(data)
	data = append(data, make([]byte, len(m.Extensions)*extensionLength)...)
	for index, extension := range m.Extensions {
		descriptor := extensionsOffset + index*extensionLength
		binary.LittleEndian.PutUint32(data[descriptor:descriptor+4], extension.Type)
		binary.LittleEndian.PutUint32(data[descriptor+4:descriptor+8], uint32(len(data)))
		binary.LittleEndian.PutUint32(data[descriptor+8:descriptor+12], uint32(len(extension.Value)))
		data = append(data, extension.Value...)
	}
	if len(m.AuthSchemes) == 0 {
		authOffset = 0
	}
	if len(m.Extensions) == 0 {
		extensionsOffset = 0
	}
	putCountVector(data[80:86], authOffset, len(m.AuthSchemes))
	putCountVector(data[86:92], extensionsOffset, len(m.Extensions))
	return data, nil
}

func unmarshalNego(header MessageHeader, data []byte) (*NegoMessage, error) {
	if err := checkHeaderLength(header, negoHeaderLength); err != nil {
		return nil, err
	}
	message := &NegoMessage{Header: header}
	copy(message.Random[:], data[40:72])
	message.ProtocolVersion = binary.LittleEndian.Uint64(data[72:80])
	if message.ProtocolVersion != 0 {
		return nil, ErrUnsupportedVersion
	}
	authData, authCount, err := countVector(data, 80, len(AuthScheme{}))
	if err != nil {
		return nil, err
	}
	message.AuthSchemes = make([]AuthScheme, authCount)
	for index := range message.AuthSchemes {
		copy(message.AuthSchemes[index][:], authData[index*16:(index+1)*16])
	}
	extensionData, extensionCount, err := countVector(data, 86, extensionLength)
	if err != nil {
		return nil, err
	}
	message.Extensions = make([]Extension, extensionCount)
	for index := range message.Extensions {
		descriptor := extensionData[index*extensionLength : (index+1)*extensionLength]
		message.Extensions[index].Type = binary.LittleEndian.Uint32(descriptor[0:4])
		if message.Extensions[index].Type&ExtensionFlagCritical != 0 {
			return nil, ErrUnsupportedExtension
		}
		value, err := byteVector(data, descriptor, 4)
		if err != nil {
			return nil, err
		}
		message.Extensions[index].Value = append([]byte(nil), value...)
	}
	return message, nil
}

func (m *ExchangeMessage) MarshalBinary() ([]byte, error) {
	if uint64(len(m.Exchange)) > math.MaxUint32-exchangeHeaderLength || len(m.Exchange) > int(^uint(0)>>1)-exchangeHeaderLength {
		return nil, ErrInvalidMessageSize
	}
	if m.Header.MessageType < MessageTypeInitiatorMetaData || m.Header.MessageType > MessageTypeAPRequest {
		return nil, ErrInvalidMessageType
	}
	data := marshalHeader(m.Header, m.Header.MessageType, exchangeHeaderLength, uint32(exchangeHeaderLength+len(m.Exchange)))
	copy(data[40:56], m.AuthScheme[:])
	putByteVector(data[56:64], exchangeHeaderLength, len(m.Exchange))
	return append(data, m.Exchange...), nil
}

func unmarshalExchange(header MessageHeader, data []byte) (*ExchangeMessage, error) {
	if err := checkHeaderLength(header, exchangeHeaderLength); err != nil {
		return nil, err
	}
	message := &ExchangeMessage{Header: header}
	copy(message.AuthScheme[:], data[40:56])
	value, err := byteVector(data, data[56:64], 0)
	if err != nil {
		return nil, err
	}
	message.Exchange = append([]byte(nil), value...)
	return message, nil
}

func (m *VerifyMessage) MarshalBinary() ([]byte, error) {
	if uint64(len(m.Checksum.Value)) > math.MaxUint32-verifyHeaderLength || len(m.Checksum.Value) > int(^uint(0)>>1)-verifyHeaderLength {
		return nil, ErrInvalidMessageSize
	}
	if m.Checksum.Scheme != 0 && m.Checksum.Scheme != ChecksumSchemeRFC3961 {
		return nil, ErrUnsupportedChecksumScheme
	}
	data := marshalHeader(m.Header, MessageTypeVerify, verifyHeaderLength, uint32(verifyHeaderLength+len(m.Checksum.Value)))
	copy(data[40:56], m.AuthScheme[:])
	binary.LittleEndian.PutUint32(data[56:60], 20)
	binary.LittleEndian.PutUint32(data[60:64], ChecksumSchemeRFC3961)
	binary.LittleEndian.PutUint32(data[64:68], m.Checksum.Type)
	putByteVector(data[68:76], verifyHeaderLength, len(m.Checksum.Value))
	return append(data, m.Checksum.Value...), nil
}

func unmarshalVerify(header MessageHeader, data []byte) (*VerifyMessage, error) {
	if err := checkHeaderLength(header, verifyHeaderLength); err != nil {
		return nil, err
	}
	message := &VerifyMessage{Header: header}
	copy(message.AuthScheme[:], data[40:56])
	message.Checksum.HeaderLength = binary.LittleEndian.Uint32(data[56:60])
	message.Checksum.Scheme = binary.LittleEndian.Uint32(data[60:64])
	message.Checksum.Type = binary.LittleEndian.Uint32(data[64:68])
	if message.Checksum.HeaderLength != 20 {
		return nil, ErrInvalidMessageSize
	}
	if message.Checksum.Scheme != ChecksumSchemeRFC3961 {
		return nil, ErrUnsupportedChecksumScheme
	}
	value, err := byteVector(data, data[68:76], 0)
	if err != nil {
		return nil, err
	}
	message.Checksum.Value = append([]byte(nil), value...)
	return message, nil
}

func (m *AlertMessage) MarshalBinary() ([]byte, error) {
	if len(m.Alerts) > math.MaxUint16 {
		return nil, ErrInvalidMessageSize
	}
	payloadLength := uint64(len(m.Alerts)) * uint64(alertLength)
	for _, alert := range m.Alerts {
		if uint64(len(alert.Value)) > math.MaxUint32 {
			return nil, ErrInvalidMessageSize
		}
		payloadLength += uint64(len(alert.Value))
	}
	if payloadLength > math.MaxUint32-alertHeaderLength || payloadLength > uint64(int(^uint(0)>>1)-alertHeaderLength) {
		return nil, ErrInvalidMessageSize
	}
	data := marshalHeader(m.Header, MessageTypeAlert, alertHeaderLength, uint32(alertHeaderLength+int(payloadLength)))
	copy(data[40:56], m.AuthScheme[:])
	binary.LittleEndian.PutUint32(data[56:60], m.ErrorCode)
	alertsOffset := len(data)
	data = append(data, make([]byte, len(m.Alerts)*alertLength)...)
	for index, alert := range m.Alerts {
		descriptor := alertsOffset + index*alertLength
		binary.LittleEndian.PutUint32(data[descriptor:descriptor+4], alert.Type)
		putByteVector(data[descriptor+4:descriptor+12], len(data), len(alert.Value))
		data = append(data, alert.Value...)
	}
	if len(m.Alerts) == 0 {
		alertsOffset = 0
	}
	putCountVector(data[60:66], alertsOffset, len(m.Alerts))
	return data, nil
}

func unmarshalAlert(header MessageHeader, data []byte) (*AlertMessage, error) {
	if err := checkHeaderLength(header, alertHeaderLength); err != nil {
		return nil, err
	}
	message := &AlertMessage{Header: header, ErrorCode: binary.LittleEndian.Uint32(data[56:60])}
	copy(message.AuthScheme[:], data[40:56])
	alertData, alertCount, err := countVector(data, 60, alertLength)
	if err != nil {
		return nil, err
	}
	message.Alerts = make([]Alert, alertCount)
	for index := range message.Alerts {
		descriptor := alertData[index*alertLength : (index+1)*alertLength]
		message.Alerts[index].Type = binary.LittleEndian.Uint32(descriptor[0:4])
		value, err := byteVector(data, descriptor, 4)
		if err != nil {
			return nil, err
		}
		message.Alerts[index].Value = append([]byte(nil), value...)
	}
	return message, nil
}

// VerifyNoKeyAlert constructs the ALERT_TYPE_PULSE value used when a peer's
// VERIFY cannot yet be checked because no verification key is available.
func VerifyNoKeyAlert() Alert {
	value := make([]byte, alertPulseLength)
	binary.LittleEndian.PutUint32(value[0:4], alertPulseLength)
	binary.LittleEndian.PutUint32(value[4:8], AlertVerifyNoKey)
	return Alert{Type: AlertTypePulse, Value: value}
}

// IsVerifyNoKey reports whether an alert is a VERIFY_NO_KEY pulse.
func (a Alert) IsVerifyNoKey() bool {
	return a.Type == AlertTypePulse && len(a.Value) >= alertPulseLength &&
		binary.LittleEndian.Uint32(a.Value[0:4]) == alertPulseLength &&
		binary.LittleEndian.Uint32(a.Value[4:8]) == AlertVerifyNoKey
}

func putCountVector(destination []byte, offset, count int) {
	binary.LittleEndian.PutUint32(destination[0:4], uint32(offset))
	binary.LittleEndian.PutUint16(destination[4:6], uint16(count))
}

func putByteVector(destination []byte, offset, length int) {
	binary.LittleEndian.PutUint32(destination[0:4], uint32(offset))
	binary.LittleEndian.PutUint32(destination[4:8], uint32(length))
}

func countVector(message []byte, descriptorOffset, width int) ([]byte, int, error) {
	if descriptorOffset < 0 || descriptorOffset+6 > len(message) || width <= 0 {
		return nil, 0, ErrInvalidMessageSize
	}
	offset := uint64(binary.LittleEndian.Uint32(message[descriptorOffset : descriptorOffset+4]))
	count := uint64(binary.LittleEndian.Uint16(message[descriptorOffset+4 : descriptorOffset+6]))
	length := count * uint64(width)
	if offset > uint64(len(message)) || length > uint64(len(message))-offset {
		return nil, 0, ErrInvalidMessageSize
	}
	return message[offset : offset+length], int(count), nil
}

func byteVector(message, descriptor []byte, descriptorOffset int) ([]byte, error) {
	if descriptorOffset < 0 || descriptorOffset+8 > len(descriptor) {
		return nil, ErrInvalidMessageSize
	}
	offset := uint64(binary.LittleEndian.Uint32(descriptor[descriptorOffset : descriptorOffset+4]))
	length := uint64(binary.LittleEndian.Uint32(descriptor[descriptorOffset+4 : descriptorOffset+8]))
	if offset > uint64(len(message)) || length > uint64(len(message))-offset {
		return nil, fmt.Errorf("%w: vector offset %d length %d", ErrInvalidMessageSize, offset, length)
	}
	return message[offset : offset+length], nil
}
