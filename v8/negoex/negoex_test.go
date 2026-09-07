package negoex

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func testHeader(messageType, sequence uint32) MessageHeader {
	return MessageHeader{
		MessageType: messageType,
		SequenceNum: sequence,
		ConversationID: ConversationID{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		},
	}
}

func testScheme() AuthScheme {
	return AuthScheme{0x0d, 0x53, 0x3d, 0x30, 0x8c, 0x7e, 0x4d, 0x4f, 0x9e, 0x4a, 0x9f, 0x1e, 0x5b, 0x2c, 0x4a, 0x6f}
}

func TestMessageHeaderRoundTrip(t *testing.T) {
	message := &ExchangeMessage{
		Header:     testHeader(MessageTypeAPRequest, 7),
		AuthScheme: testScheme(),
		Exchange:   []byte{1, 2, 3},
	}
	data, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint64(data[0:8]); got != MessageSignature {
		t.Fatalf("signature = %#x", got)
	}
	if got := binary.LittleEndian.Uint32(data[16:20]); got != exchangeHeaderLength {
		t.Fatalf("header length = %d", got)
	}
	if got := binary.LittleEndian.Uint32(data[20:24]); got != uint32(len(data)) {
		t.Fatalf("message length = %d, encoded length = %d", got, len(data))
	}
	decoded, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded[0].(*ExchangeMessage)
	if !reflect.DeepEqual(got.Exchange, message.Exchange) || got.Header.SequenceNum != 7 || got.AuthScheme != message.AuthScheme {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestNegoMessageVectors(t *testing.T) {
	message := &NegoMessage{
		Header:      testHeader(MessageTypeInitiatorNego, 0),
		AuthSchemes: []AuthScheme{testScheme(), {1, 2, 3}},
		Extensions:  []Extension{{Type: 12, Value: []byte("extension")}},
	}
	for index := range message.Random {
		message.Random[index] = byte(index)
	}
	data, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(data[80:84]); got != negoHeaderLength {
		t.Fatalf("auth scheme offset = %d", got)
	}
	if got := binary.LittleEndian.Uint16(data[84:86]); got != 2 {
		t.Fatalf("auth scheme count = %d", got)
	}
	decoded, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	got := decoded[0].(*NegoMessage)
	if !reflect.DeepEqual(got.AuthSchemes, message.AuthSchemes) || !reflect.DeepEqual(got.Extensions, message.Extensions) || got.Random != message.Random {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestMSExampleInitiatorNegoFixture(t *testing.T) {
	fixture, err := hex.DecodeString(
		"4e45474f4558545300000000000000006000000070000000" +
			"3691b812168cbad4f67c3b24f06935c7f11e9e4567892283" +
			"8ae1f2232fdbdb12dcbe229f8c3f58694de60a4f5a828ef4" +
			"000000000000000060000000010000000000000000000000" +
			"5c33530deaf90d4db2ec4ae3786ec308")
	if err != nil {
		t.Fatal(err)
	}
	messages, err := Unmarshal(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 1 {
		t.Fatalf("decoded %d messages", len(messages))
	}
	nego := messages[0].(*NegoMessage)
	if len(nego.AuthSchemes) != 1 || nego.AuthSchemes[0] != (AuthScheme{0x5c, 0x33, 0x53, 0x0d, 0xea, 0xf9, 0x0d, 0x4d, 0xb2, 0xec, 0x4a, 0xe3, 0x78, 0x6e, 0xc3, 0x08}) {
		t.Fatalf("auth schemes = %x", nego.AuthSchemes)
	}
	encoded, err := nego.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(encoded, fixture) {
		t.Fatalf("fixture did not re-encode byte-exactly\ngot  %x\nwant %x", encoded, fixture)
	}
}

func TestVerifyAndAlertRoundTrip(t *testing.T) {
	verify := &VerifyMessage{
		Header:     testHeader(MessageTypeVerify, 3),
		AuthScheme: testScheme(),
		Checksum:   Checksum{Type: 16, Value: []byte("checksum")},
	}
	alert := &AlertMessage{
		Header:     testHeader(MessageTypeAlert, 4),
		AuthScheme: testScheme(),
		Alerts:     []Alert{VerifyNoKeyAlert()},
	}
	token, err := Marshal(verify, alert)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := Unmarshal(token)
	if err != nil {
		t.Fatal(err)
	}
	if len(messages) != 2 {
		t.Fatalf("decoded %d messages", len(messages))
	}
	gotVerify := messages[0].(*VerifyMessage)
	if gotVerify.Offset != 0 || gotVerify.Checksum.Scheme != ChecksumSchemeRFC3961 || !reflect.DeepEqual(gotVerify.Checksum.Value, verify.Checksum.Value) {
		t.Fatalf("verify mismatch: %#v", gotVerify)
	}
	gotAlert := messages[1].(*AlertMessage)
	if len(gotAlert.Alerts) != 1 || !gotAlert.Alerts[0].IsVerifyNoKey() {
		t.Fatalf("alert mismatch: %#v", gotAlert)
	}
}

func TestDecoderRejectsOutOfRangeVectors(t *testing.T) {
	message := &ExchangeMessage{Header: testHeader(MessageTypeChallenge, 1), Exchange: []byte{1}}
	data, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(data[56:60], ^uint32(0))
	if _, err := Unmarshal(data); !errors.Is(err, ErrInvalidMessageSize) {
		t.Fatalf("error = %v", err)
	}

	data, err = message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(data[60:64], ^uint32(0))
	if _, err := Unmarshal(data); !errors.Is(err, ErrInvalidMessageSize) {
		t.Fatalf("error = %v", err)
	}
}

func TestDecoderRejectsCriticalExtension(t *testing.T) {
	message := &NegoMessage{
		Header:     testHeader(MessageTypeInitiatorNego, 0),
		Extensions: []Extension{{Type: ExtensionFlagCritical | 1}},
	}
	data, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Unmarshal(data); !errors.Is(err, ErrUnsupportedExtension) {
		t.Fatalf("error = %v", err)
	}
}

func TestDecoderRejectsMalformedHeaders(t *testing.T) {
	message := &ExchangeMessage{Header: testHeader(MessageTypeAPRequest, 0)}
	data, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func([]byte)
		want   error
	}{
		{"signature", func(data []byte) { data[0] ^= 1 }, ErrInvalidSignature},
		{"header length", func(data []byte) { binary.LittleEndian.PutUint32(data[16:20], 39) }, ErrInvalidMessageSize},
		{"message length", func(data []byte) { binary.LittleEndian.PutUint32(data[20:24], 65) }, ErrInvalidMessageSize},
		{"message type", func(data []byte) { binary.LittleEndian.PutUint32(data[8:12], 99) }, ErrInvalidMessageType},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			malformed := append([]byte(nil), data...)
			test.mutate(malformed)
			if _, err := Unmarshal(malformed); !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

type testContext struct {
	key             types.EncryptionKey
	available       bool
	verifyAvailable bool
}

func (c *testContext) Wrap(message []byte, confidential bool) ([]byte, error) {
	return append([]byte(nil), message...), nil
}
func (c *testContext) Unwrap(token []byte) ([]byte, bool, error) {
	return append([]byte(nil), token...), false, nil
}
func (c *testContext) GetMIC(message []byte) ([]byte, error) {
	return append([]byte(nil), message...), nil
}
func (c *testContext) VerifyMIC(message, token []byte) error {
	if !reflect.DeepEqual(message, token) {
		return errors.New("bad MIC")
	}
	return nil
}
func (c *testContext) NegoExKey() (types.EncryptionKey, bool) { return c.key, c.available }
func (c *testContext) NegoExVerifyKey() (types.EncryptionKey, bool) {
	return c.key, c.verifyAvailable
}

type testSchemeMechanism struct {
	id      AuthScheme
	context *testContext
}

type testPKU2UMechanism struct {
	*testSchemeMechanism
	metadata []byte
}

func (*testPKU2UMechanism) OID() asn1.ObjectIdentifier { return gssapi.OIDPKU2U.OID() }

func (m *testPKU2UMechanism) InitSecContext(target string, input []byte, _ ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	return m.testSchemeMechanism.InitSecContext(target, input)
}

func (m *testPKU2UMechanism) AcceptSecContext(input []byte, _ ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	return m.testSchemeMechanism.AcceptSecContext(input)
}

func (m *testPKU2UMechanism) QueryMetadata(target string, initiator bool) ([]byte, error) {
	if target != "host/server" || !initiator {
		return nil, errors.New("unexpected metadata query")
	}
	return append([]byte(nil), m.metadata...), nil
}

func (m *testPKU2UMechanism) ExchangeMetadata(metadata []byte, initiator bool) error {
	if !reflect.DeepEqual(metadata, m.metadata) || initiator {
		return errors.New("unexpected metadata exchange")
	}
	return nil
}

func (m *testSchemeMechanism) AuthScheme() AuthScheme { return m.id }
func (m *testSchemeMechanism) InitSecContext(_ string, input []byte) ([]byte, gssapi.Context, bool, error) {
	switch string(input) {
	case "":
		return []byte("request-1"), m.context, false, nil
	case "challenge":
		return []byte("request-2"), m.context, true, nil
	default:
		return nil, m.context, false, errors.New("unexpected initiator input")
	}
}
func (m *testSchemeMechanism) AcceptSecContext(input []byte) ([]byte, gssapi.Context, bool, error) {
	switch string(input) {
	case "request-1":
		return []byte("challenge"), m.context, false, nil
	case "request-2":
		return nil, m.context, true, nil
	default:
		return nil, m.context, false, errors.New("unexpected acceptor input")
	}
}

func newTestScheme(id AuthScheme) *testSchemeMechanism {
	return &testSchemeMechanism{
		id: id,
		context: &testContext{available: true, key: types.EncryptionKey{
			KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KeyValue: []byte("0123456789abcdef0123456789abcdef"),
		}, verifyAvailable: true},
	}
}

func TestPKU2USchemeDelegatesMechanism(t *testing.T) {
	mechanism := &testPKU2UMechanism{testSchemeMechanism: newTestScheme(PKU2UAuthScheme), metadata: []byte("metadata")}
	scheme := NewPKU2UScheme(mechanism)
	if scheme.AuthScheme() != PKU2UAuthScheme {
		t.Fatalf("auth scheme = %v", scheme.AuthScheme())
	}
	if output, _, done, err := scheme.InitSecContext("host/server", nil); err != nil || done || string(output) != "request-1" {
		t.Fatalf("initiator output = %q, done=%v, err=%v", output, done, err)
	}
	if output, _, done, err := scheme.AcceptSecContext([]byte("request-1")); err != nil || done || string(output) != "challenge" {
		t.Fatalf("acceptor output = %q, done=%v, err=%v", output, done, err)
	}
	if metadata, err := scheme.QueryMetadata("host/server", true); err != nil || string(metadata) != "metadata" {
		t.Fatalf("query metadata = %q, %v", metadata, err)
	}
	if err := scheme.ExchangeMetadata([]byte("metadata"), false); err != nil {
		t.Fatal(err)
	}
}

func TestConversationEndToEnd(t *testing.T) {
	schemeID := testScheme()
	initiator, err := NewInitiator("host/server", newTestScheme(schemeID))
	if err != nil {
		t.Fatal(err)
	}
	acceptor, err := NewAcceptor(newTestScheme(schemeID))
	if err != nil {
		t.Fatal(err)
	}

	initiatorToken, done, err := initiator.Step(nil)
	if err != nil || done {
		t.Fatalf("initial initiator step: done=%v err=%v", done, err)
	}
	acceptorToken, done, err := acceptor.Step(initiatorToken)
	if err != nil || done {
		t.Fatalf("initial acceptor step: done=%v err=%v", done, err)
	}
	initiatorToken, done, err = initiator.Step(acceptorToken)
	if err != nil || !done {
		t.Fatalf("final initiator step: done=%v err=%v", done, err)
	}
	acceptorToken, done, err = acceptor.Step(initiatorToken)
	if err != nil || !done || len(acceptorToken) != 0 {
		t.Fatalf("final acceptor step: output=%x done=%v err=%v", acceptorToken, done, err)
	}
	if initiator.SelectedScheme() != schemeID || acceptor.SelectedScheme() != schemeID {
		t.Fatal("conversation selected the wrong scheme")
	}
}

func TestMechanismEndToEndAndGuards(t *testing.T) {
	schemeID := testScheme()
	initiator := New(newTestScheme(schemeID), newTestScheme(schemeID))
	acceptor := New(newTestScheme(schemeID))
	if !initiator.OID().Equal(gssapi.OIDNegoEx.OID()) {
		t.Fatalf("mechanism OID = %v", initiator.OID())
	}

	initiatorToken, initiatorContext, done, err := initiator.InitSecContext("host/server", nil)
	if err != nil || done || initiatorContext == nil {
		t.Fatalf("initial initiator = context %v, done %v, err %v", initiatorContext, done, err)
	}
	acceptorToken, acceptorContext, done, err := acceptor.AcceptSecContext(initiatorToken)
	if err != nil || done || acceptorContext == nil {
		t.Fatalf("initial acceptor = context %v, done %v, err %v", acceptorContext, done, err)
	}
	initiatorToken, initiatorContext, done, err = initiator.InitSecContext("host/server", acceptorToken)
	if err != nil || !done || initiatorContext == nil {
		t.Fatalf("final initiator = context %v, done %v, err %v", initiatorContext, done, err)
	}
	acceptorToken, acceptorContext, done, err = acceptor.AcceptSecContext(initiatorToken)
	if err != nil || !done || len(acceptorToken) != 0 || acceptorContext == nil {
		t.Fatalf("final acceptor = output %x, context %v, done %v, err %v", acceptorToken, acceptorContext, done, err)
	}
	if _, _, _, err := initiator.InitSecContext("other/target", nil); err == nil || !strings.Contains(err.Error(), "target changed") {
		t.Fatalf("target change error = %v", err)
	}
	if _, _, _, err := New().InitSecContext("host/server", nil); !errors.Is(err, ErrNoAvailableSchemes) {
		t.Fatalf("empty initiator error = %v", err)
	}
	if _, _, _, err := New().AcceptSecContext([]byte{1}); !errors.Is(err, ErrNoAvailableSchemes) {
		t.Fatalf("empty acceptor error = %v", err)
	}
}

func TestAlertErrorContract(t *testing.T) {
	err := AlertError{Status: ntstatus.STATUS_ACCOUNT_DISABLED}
	if !strings.Contains(err.Error(), "NEGOEX alert") {
		t.Fatalf("alert error = %q", err.Error())
	}
	status, ok := err.NTStatus()
	if !ok || status != ntstatus.STATUS_ACCOUNT_DISABLED {
		t.Fatalf("alert status = %v, %v", status, ok)
	}
}

func TestConversationRejectsTamperedTranscript(t *testing.T) {
	schemeID := testScheme()
	initiator, _ := NewInitiator("host/server", newTestScheme(schemeID))
	acceptor, _ := NewAcceptor(newTestScheme(schemeID))
	token, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	// Change the NEGO random field without affecting mechanism processing.
	token[40] ^= 1
	if _, _, err := acceptor.Step(token); !errors.Is(err, ErrInvalidChecksum) {
		t.Fatalf("error = %v", err)
	}
}

func TestConversationRetriesVerifyAfterNoKeyAlert(t *testing.T) {
	schemeID := testScheme()
	initiatorScheme := newTestScheme(schemeID)
	acceptorScheme := newTestScheme(schemeID)
	acceptorScheme.context.verifyAvailable = false
	initiator, _ := NewInitiator("host/server", initiatorScheme)
	acceptor, _ := NewAcceptor(acceptorScheme)

	initiatorToken, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptorToken, _, err := acceptor.Step(initiatorToken)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := Unmarshal(acceptorToken)
	if err != nil {
		t.Fatal(err)
	}
	if !hasVerifyNoKeyAlert(messages, schemeID) {
		t.Fatal("acceptor did not request a VERIFY retry")
	}

	initiatorToken, _, err = initiator.Step(acceptorToken)
	if err != nil {
		t.Fatal(err)
	}
	messages, err = Unmarshal(initiatorToken)
	if err != nil {
		t.Fatal(err)
	}
	if findVerify(messages, schemeID) == nil {
		t.Fatal("initiator did not retransmit VERIFY")
	}

	acceptorScheme.context.verifyAvailable = true
	_, done, err := acceptor.Step(initiatorToken)
	if err != nil || !done {
		t.Fatalf("acceptor retry step: done=%v err=%v", done, err)
	}
}

func TestConversationRejectsCompletedMechanismWithoutVerifyKey(t *testing.T) {
	scheme := newTestScheme(testScheme())
	scheme.context.available = false
	initiator, _ := NewInitiator("host/server", scheme)
	acceptor, _ := NewAcceptor(newTestScheme(testScheme()))

	initiatorToken, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptorToken, _, err := acceptor.Step(initiatorToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := initiator.Step(acceptorToken); !errors.Is(err, ErrNoVerifyKey) {
		t.Fatalf("error = %v", err)
	}
}

func TestConversationSequenceNumbers(t *testing.T) {
	initiator, _ := NewInitiator("host/server", newTestScheme(testScheme()))
	acceptor, _ := NewAcceptor(newTestScheme(testScheme()))
	token, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(token[12:16], 1)
	if _, _, err := acceptor.Step(token); !errors.Is(err, ErrMessageOutOfSequence) {
		t.Fatalf("error = %v", err)
	}
}

func TestAcceptorSchemePreferenceOrder(t *testing.T) {
	first := AuthScheme{1}
	second := AuthScheme{2}
	initiator, _ := NewInitiator("host/server", newTestScheme(first), newTestScheme(second))
	acceptor, _ := NewAcceptor(newTestScheme(second), newTestScheme(first))
	token, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	response, _, err := acceptor.Step(token)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := Unmarshal(response)
	if err != nil {
		t.Fatal(err)
	}
	nego := findNego(messages, MessageTypeAcceptorNego)
	if nego == nil || !reflect.DeepEqual(nego.AuthSchemes, []AuthScheme{second, first}) {
		t.Fatalf("acceptor schemes = %v", nego.AuthSchemes)
	}
	if acceptor.SelectedScheme() != second {
		t.Fatalf("selected scheme = %v", acceptor.SelectedScheme())
	}
}

type rejectEmptyScheme struct {
	*testSchemeMechanism
	acceptCalls int
}

func (m *rejectEmptyScheme) AcceptSecContext(input []byte) ([]byte, gssapi.Context, bool, error) {
	m.acceptCalls++
	if len(input) == 0 {
		return nil, nil, false, errors.New("empty mechanism token")
	}
	return m.testSchemeMechanism.AcceptSecContext(input)
}

func TestAcceptorIgnoresUnsupportedOptimisticToken(t *testing.T) {
	firstID := AuthScheme{1}
	selectedID := AuthScheme{2}
	initiator, _ := NewInitiator("host/server", newTestScheme(firstID), newTestScheme(selectedID))
	selected := &rejectEmptyScheme{testSchemeMechanism: newTestScheme(selectedID)}
	acceptor, _ := NewAcceptor(selected)

	initiatorToken, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	acceptorToken, done, err := acceptor.Step(initiatorToken)
	if err != nil || done {
		t.Fatalf("acceptor step: done=%v err=%v", done, err)
	}
	if selected.acceptCalls != 0 {
		t.Fatalf("selected mechanism was called %d times", selected.acceptCalls)
	}
	messages, err := Unmarshal(acceptorToken)
	if err != nil {
		t.Fatal(err)
	}
	if findExchange(messages, MessageTypeChallenge, selectedID) != nil {
		t.Fatal("acceptor emitted a challenge without an AP request")
	}
}

type testMetadataScheme struct {
	*testSchemeMechanism
	queryErr      error
	exchangeErr   error
	exchangeCalls int
}

func (m *testMetadataScheme) QueryMetadata(string, bool) ([]byte, error) {
	return []byte("metadata"), m.queryErr
}

func (m *testMetadataScheme) ExchangeMetadata([]byte, bool) error {
	m.exchangeCalls++
	return m.exchangeErr
}

func TestMetadataFailurePrunesScheme(t *testing.T) {
	failedID := AuthScheme{1}
	selectedID := AuthScheme{2}
	failed := &testMetadataScheme{testSchemeMechanism: newTestScheme(failedID), queryErr: errors.New("unavailable")}
	initiator, _ := NewInitiator("host/server", failed, newTestScheme(selectedID))

	token, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := Unmarshal(token)
	if err != nil {
		t.Fatal(err)
	}
	nego := findNego(messages, MessageTypeInitiatorNego)
	if nego == nil || !reflect.DeepEqual(nego.AuthSchemes, []AuthScheme{selectedID}) {
		t.Fatalf("advertised schemes = %v", nego.AuthSchemes)
	}
}

func TestMetadataExchangeFailurePrunesScheme(t *testing.T) {
	failedID := AuthScheme{1}
	selectedID := AuthScheme{2}
	failed := &testMetadataScheme{testSchemeMechanism: newTestScheme(failedID), exchangeErr: errors.New("rejected")}
	acceptor, _ := NewAcceptor(failed, newTestScheme(selectedID))
	metadata := &ExchangeMessage{
		Header:     testHeader(MessageTypeInitiatorMetaData, 1),
		AuthScheme: failedID,
		Exchange:   []byte("metadata"),
	}
	nego := &NegoMessage{
		Header:      testHeader(MessageTypeInitiatorNego, 0),
		AuthSchemes: []AuthScheme{failedID, selectedID},
	}
	token, err := Marshal(nego, metadata)
	if err != nil {
		t.Fatal(err)
	}

	response, _, err := acceptor.Step(token)
	if err != nil {
		t.Fatal(err)
	}
	messages, err := Unmarshal(response)
	if err != nil {
		t.Fatal(err)
	}
	responseNego := findNego(messages, MessageTypeAcceptorNego)
	if responseNego == nil || !reflect.DeepEqual(responseNego.AuthSchemes, []AuthScheme{selectedID}) {
		t.Fatalf("advertised schemes = %v", responseNego.AuthSchemes)
	}
}

func TestConversationProcessesEveryMetadataMessage(t *testing.T) {
	schemeID := testScheme()
	scheme := &testMetadataScheme{testSchemeMechanism: newTestScheme(schemeID)}
	acceptor, _ := NewAcceptor(scheme)
	nego := &NegoMessage{Header: testHeader(MessageTypeInitiatorNego, 0), AuthSchemes: []AuthScheme{schemeID}}
	first := &ExchangeMessage{Header: testHeader(MessageTypeInitiatorMetaData, 1), AuthScheme: schemeID, Exchange: []byte("first")}
	second := &ExchangeMessage{Header: testHeader(MessageTypeInitiatorMetaData, 2), AuthScheme: schemeID, Exchange: []byte("second")}
	token, err := Marshal(nego, first, second)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := acceptor.Step(token); err != nil {
		t.Fatal(err)
	}
	if scheme.exchangeCalls != 2 {
		t.Fatalf("ExchangeMetadata called %d times", scheme.exchangeCalls)
	}
}

func TestConversationMapsAlertNTStatus(t *testing.T) {
	schemeID := testScheme()
	acceptor, _ := NewAcceptor(newTestScheme(schemeID))
	nego := &NegoMessage{Header: testHeader(MessageTypeInitiatorNego, 0), AuthSchemes: []AuthScheme{schemeID}}
	alert := &AlertMessage{
		Header: testHeader(MessageTypeAlert, 1), AuthScheme: schemeID,
		ErrorCode: uint32(ntstatus.STATUS_ACCOUNT_DISABLED),
	}
	token, err := Marshal(nego, alert)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = acceptor.Step(token)
	var alertErr AlertError
	if !errors.As(err, &alertErr) || alertErr.Status != ntstatus.STATUS_ACCOUNT_DISABLED {
		t.Fatalf("error = %v", err)
	}
}

func TestAlertVerifyNoKey(t *testing.T) {
	alert := VerifyNoKeyAlert()
	if !alert.IsVerifyNoKey() {
		t.Fatal("constructed pulse is not recognized")
	}
	alert.Value[4] = 2
	if alert.IsVerifyNoKey() {
		t.Fatal("wrong pulse reason was accepted")
	}
}

func TestVerifyChecksumOverConversation(t *testing.T) {
	key := types.EncryptionKey{KeyType: etypeID.AES128_CTS_HMAC_SHA1_96, KeyValue: []byte("0123456789abcdef")}
	checksum, err := MakeChecksum(key, 23, []byte("transcript"))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksum(key, 23, []byte("transcript"), checksum); err != nil {
		t.Fatal(err)
	}
	if err := VerifyChecksum(key, 23, []byte("tampered"), checksum); !errors.Is(err, ErrInvalidChecksum) {
		t.Fatalf("error = %v", err)
	}
}
