package negoex

import (
	"encoding/binary"
	"fmt"
	"math"
)

const (
	authSchemeVectorOffset = 80
	extensionVectorOffset  = 86
	alertVectorOffset      = 60
	countVectorLength      = 6
	descriptorValueOffset  = 4
	checksumHeaderLength   = 20
)

// MarshalBinary marshals the NegoMessage message to bytes.
func (m *NegoMessage) MarshalBinary() ([]byte, error) {
	messageLength, err := negoMessageLength(m)
	if err != nil {
		return nil, err
	}
	data := marshalHeader(m.Header, m.Header.MessageType, negoHeaderLength, messageLength)
	copy(data[40:72], m.Random[:])
	binary.LittleEndian.PutUint64(data[72:80], m.ProtocolVersion)
	authOffset := len(data)
	data = append(data, make([]byte, len(m.AuthSchemes)*len(AuthScheme{}))...)
	for index := range m.AuthSchemes {
		copy(data[authOffset+index*16:], m.AuthSchemes[index][:])
	}
	extensionsOffset := len(data)
	data, err = appendNegotiationExtensions(data, m.Extensions, extensionsOffset)
	if err != nil {
		return nil, err
	}
	if len(m.AuthSchemes) == 0 {
		authOffset = 0
	}
	if len(m.Extensions) == 0 {
		extensionsOffset = 0
	}
	authVector := data[authSchemeVectorOffset:extensionVectorOffset]
	if err := putCountVector(authVector, authOffset, len(m.AuthSchemes)); err != nil {
		return nil, err
	}
	extensionVector := data[extensionVectorOffset : extensionVectorOffset+countVectorLength]
	if err := putCountVector(extensionVector, extensionsOffset, len(m.Extensions)); err != nil {
		return nil, err
	}
	return data, nil
}

func negoMessageLength(m *NegoMessage) (uint32, error) {
	if len(m.AuthSchemes) > math.MaxUint16 || len(m.Extensions) > math.MaxUint16 {
		return 0, ErrInvalidMessageSize
	}
	payloadLength := uint64(len(m.AuthSchemes)) * uint64(len(AuthScheme{}))
	for _, extension := range m.Extensions {
		if uint64(len(extension.Value)) > math.MaxUint32 {
			return 0, ErrInvalidMessageSize
		}
		payloadLength += uint64(extensionLength) + uint64(len(extension.Value))
	}
	if payloadLength > math.MaxUint32-negoHeaderLength || payloadLength > uint64(int(^uint(0)>>1)-negoHeaderLength) {
		return 0, ErrInvalidMessageSize
	}
	return negoexUint32FromInt(negoHeaderLength + int(payloadLength))
}

func appendNegotiationExtensions(data []byte, extensions []Extension, offset int) ([]byte, error) {
	data = append(data, make([]byte, len(extensions)*extensionLength)...)
	for index, extension := range extensions {
		descriptor := offset + index*extensionLength
		binary.LittleEndian.PutUint32(data[descriptor:descriptor+4], extension.Type)
		valueOffset, err := negoexUint32FromInt(len(data))
		if err != nil {
			return nil, err
		}
		valueLength, err := negoexUint32FromInt(len(extension.Value))
		if err != nil {
			return nil, err
		}
		binary.LittleEndian.PutUint32(data[descriptor+4:descriptor+8], valueOffset)
		binary.LittleEndian.PutUint32(data[descriptor+8:descriptor+12], valueLength)
		data = append(data, extension.Value...)
	}
	return data, nil
}

func unmarshalNego(header MessageHeader, data []byte) (*NegoMessage, error) {
	if err := checkHeaderLength(header, negoHeaderLength); err != nil {
		return nil, err
	}
	var message NegoMessage
	message.Header = header
	copy(message.Random[:], data[40:72])
	message.ProtocolVersion = binary.LittleEndian.Uint64(data[72:80])
	if message.ProtocolVersion != 0 {
		return nil, ErrUnsupportedVersion
	}
	authData, authCount, err := countVector(data, authSchemeVectorOffset, len(AuthScheme{}))
	if err != nil {
		return nil, err
	}
	message.AuthSchemes = make([]AuthScheme, authCount)
	for index := range message.AuthSchemes {
		copy(message.AuthSchemes[index][:], authData[index*16:(index+1)*16])
	}
	extensionData, extensionCount, err := countVector(data, extensionVectorOffset, extensionLength)
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
		value, err := byteVector(data, descriptor, descriptorValueOffset)
		if err != nil {
			return nil, err
		}
		message.Extensions[index].Value = append([]byte(nil), value...)
	}
	return &message, nil
}

// MarshalBinary marshals the ExchangeMessage message to bytes.
func (m *ExchangeMessage) MarshalBinary() ([]byte, error) {
	if uint64(len(m.Exchange)) > math.MaxUint32-exchangeHeaderLength ||
		len(m.Exchange) > math.MaxInt-exchangeHeaderLength {
		return nil, ErrInvalidMessageSize
	}
	if m.Header.MessageType < MessageTypeInitiatorMetaData || m.Header.MessageType > MessageTypeAPRequest {
		return nil, ErrInvalidMessageType
	}
	messageLength, err := negoexUint32FromInt(exchangeHeaderLength + len(m.Exchange))
	if err != nil {
		return nil, err
	}
	data := marshalHeader(m.Header, m.Header.MessageType, exchangeHeaderLength, messageLength)
	copy(data[40:56], m.AuthScheme[:])
	if err := putByteVector(data[56:64], exchangeHeaderLength, len(m.Exchange)); err != nil {
		return nil, err
	}
	return append(data, m.Exchange...), nil
}

func unmarshalExchange(header MessageHeader, data []byte) (*ExchangeMessage, error) {
	if err := checkHeaderLength(header, exchangeHeaderLength); err != nil {
		return nil, err
	}
	var message ExchangeMessage
	message.Header = header
	copy(message.AuthScheme[:], data[40:56])
	value, err := byteVector(data, data[56:64], 0)
	if err != nil {
		return nil, err
	}
	message.Exchange = append([]byte(nil), value...)
	return &message, nil
}

// MarshalBinary marshals the VerifyMessage message to bytes.
func (m *VerifyMessage) MarshalBinary() ([]byte, error) {
	if uint64(len(m.Checksum.Value)) > math.MaxUint32-verifyHeaderLength ||
		len(m.Checksum.Value) > math.MaxInt-verifyHeaderLength {
		return nil, ErrInvalidMessageSize
	}
	if m.Checksum.Scheme != 0 && m.Checksum.Scheme != ChecksumSchemeRFC3961 {
		return nil, ErrUnsupportedChecksumScheme
	}
	messageLength, err := negoexUint32FromInt(verifyHeaderLength + len(m.Checksum.Value))
	if err != nil {
		return nil, err
	}
	data := marshalHeader(m.Header, MessageTypeVerify, verifyHeaderLength, messageLength)
	copy(data[40:56], m.AuthScheme[:])
	binary.LittleEndian.PutUint32(data[56:60], checksumHeaderLength)
	binary.LittleEndian.PutUint32(data[60:64], ChecksumSchemeRFC3961)
	binary.LittleEndian.PutUint32(data[64:68], m.Checksum.Type)
	if err := putByteVector(data[68:76], verifyHeaderLength, len(m.Checksum.Value)); err != nil {
		return nil, err
	}
	return append(data, m.Checksum.Value...), nil
}

func unmarshalVerify(header MessageHeader, data []byte) (*VerifyMessage, error) {
	if err := checkHeaderLength(header, verifyHeaderLength); err != nil {
		return nil, err
	}
	var message VerifyMessage
	message.Header = header
	copy(message.AuthScheme[:], data[40:56])
	message.Checksum.HeaderLength = binary.LittleEndian.Uint32(data[56:60])
	message.Checksum.Scheme = binary.LittleEndian.Uint32(data[60:64])
	message.Checksum.Type = binary.LittleEndian.Uint32(data[64:68])
	if message.Checksum.HeaderLength != checksumHeaderLength {
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
	return &message, nil
}

// MarshalBinary marshals the AlertMessage message to bytes.
func (m *AlertMessage) MarshalBinary() ([]byte, error) {
	messageLength, err := alertMessageLength(m.Alerts)
	if err != nil {
		return nil, err
	}
	data := marshalHeader(m.Header, MessageTypeAlert, alertHeaderLength, messageLength)
	copy(data[40:56], m.AuthScheme[:])
	binary.LittleEndian.PutUint32(data[56:60], m.ErrorCode)
	alertsOffset := len(data)
	data = append(data, make([]byte, len(m.Alerts)*alertLength)...)
	for index, alert := range m.Alerts {
		descriptor := alertsOffset + index*alertLength
		binary.LittleEndian.PutUint32(data[descriptor:descriptor+4], alert.Type)
		if err := putByteVector(data[descriptor+4:descriptor+12], len(data), len(alert.Value)); err != nil {
			return nil, err
		}
		data = append(data, alert.Value...)
	}
	if len(m.Alerts) == 0 {
		alertsOffset = 0
	}
	alertVector := data[alertVectorOffset : alertVectorOffset+countVectorLength]
	if err := putCountVector(alertVector, alertsOffset, len(m.Alerts)); err != nil {
		return nil, err
	}
	return data, nil
}

func alertMessageLength(alerts []Alert) (uint32, error) {
	if len(alerts) > math.MaxUint16 {
		return 0, ErrInvalidMessageSize
	}
	payloadLength := uint64(len(alerts)) * alertLength
	for _, alert := range alerts {
		if uint64(len(alert.Value)) > math.MaxUint32 {
			return 0, ErrInvalidMessageSize
		}
		payloadLength += uint64(len(alert.Value))
	}
	if payloadLength > math.MaxUint32-alertHeaderLength ||
		payloadLength > uint64(math.MaxInt-alertHeaderLength) {
		return 0, ErrInvalidMessageSize
	}
	return negoexUint32FromInt(alertHeaderLength + int(payloadLength))
}

func unmarshalAlert(header MessageHeader, data []byte) (*AlertMessage, error) {
	if err := checkHeaderLength(header, alertHeaderLength); err != nil {
		return nil, err
	}
	var message AlertMessage
	message.Header = header
	message.ErrorCode = binary.LittleEndian.Uint32(data[56:60])
	copy(message.AuthScheme[:], data[40:56])
	alertData, alertCount, err := countVector(data, alertVectorOffset, alertLength)
	if err != nil {
		return nil, err
	}
	message.Alerts = make([]Alert, alertCount)
	for index := range message.Alerts {
		descriptor := alertData[index*alertLength : (index+1)*alertLength]
		message.Alerts[index].Type = binary.LittleEndian.Uint32(descriptor[0:4])
		value, err := byteVector(data, descriptor, descriptorValueOffset)
		if err != nil {
			return nil, err
		}
		message.Alerts[index].Value = append([]byte(nil), value...)
	}
	return &message, nil
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

func putCountVector(destination []byte, offset, count int) error {
	offset32, err := negoexUint32FromInt(offset)
	if err != nil {
		return err
	}
	count16, err := negoexUint16FromInt(count)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(destination[0:4], offset32)
	binary.LittleEndian.PutUint16(destination[4:6], count16)
	return nil
}

func putByteVector(destination []byte, offset, length int) error {
	offset32, err := negoexUint32FromInt(offset)
	if err != nil {
		return err
	}
	length32, err := negoexUint32FromInt(length)
	if err != nil {
		return err
	}
	binary.LittleEndian.PutUint32(destination[0:4], offset32)
	binary.LittleEndian.PutUint32(destination[4:8], length32)
	return nil
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
	start, err := negoexIntFromUint64(offset)
	if err != nil {
		return nil, 0, err
	}
	stop, err := negoexIntFromUint64(offset + length)
	if err != nil {
		return nil, 0, err
	}
	countInt, err := negoexIntFromUint64(count)
	if err != nil {
		return nil, 0, err
	}
	return message[start:stop], countInt, nil
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
	start, err := negoexIntFromUint64(offset)
	if err != nil {
		return nil, err
	}
	stop, err := negoexIntFromUint64(offset + length)
	if err != nil {
		return nil, err
	}
	return message[start:stop], nil
}
