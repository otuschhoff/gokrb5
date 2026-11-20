package negoex

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func mustNewInitiator(t *testing.T, target string, schemes ...Scheme) *Conversation {
	t.Helper()
	conversation, err := NewInitiator(target, schemes...)
	if err != nil {
		t.Fatal(err)
	}
	return conversation
}

func mustNewAcceptor(t *testing.T, schemes ...Scheme) *Conversation {
	t.Helper()
	conversation, err := NewAcceptor(schemes...)
	if err != nil {
		t.Fatal(err)
	}
	return conversation
}

func mustNEGOEXUint32(t *testing.T, value int) uint32 {
	t.Helper()
	result, err := negoexUint32FromInt(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func requireWrappedError(t *testing.T, err, cause error, prefix string) {
	t.Helper()
	if err == nil || !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), prefix) {
		t.Fatalf("want error prefixed by %q and wrapping %v, got %v", prefix, cause, err)
	}
}

func TestNEGOEXConversionBounds(t *testing.T) {
	tests := []struct {
		name string
		call func() error
	}{
		{name: "negative uint32", call: func() error { _, err := negoexUint32FromInt(-1); return err }},
		{name: "negative uint16", call: func() error { _, err := negoexUint16FromInt(-1); return err }},
		{name: "uint16 overflow", call: func() error { _, err := negoexUint16FromInt(math.MaxUint16 + 1); return err }},
		{name: "platform int overflow", call: func() error {
			maxPlatformInt := maxInt()
			value := uint64(maxPlatformInt) // #nosec G115 -- maxInt is nonnegative.
			_, err := negoexIntFromUint64(value + 1)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.call(); !errors.Is(err, ErrInvalidMessageSize) {
				t.Fatalf("conversion error = %v, want ErrInvalidMessageSize", err)
			}
		})
	}
}

func testHeader(messageType, sequence uint32) MessageHeader {
	return MessageHeader{
		Signature:     0,
		MessageType:   messageType,
		SequenceNum:   sequence,
		HeaderLength:  0,
		MessageLength: 0,
		ConversationID: ConversationID{
			0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
			0x10, 0x32, 0x54, 0x76, 0x98, 0xba, 0xdc, 0xfe,
		},
	}
}

func testScheme() AuthScheme {
	return AuthScheme{0x0d, 0x53, 0x3d, 0x30, 0x8c, 0x7e, 0x4d, 0x4f, 0x9e, 0x4a, 0x9f, 0x1e, 0x5b, 0x2c, 0x4a, 0x6f}
}

func mustUnmarshalTestMessages(t *testing.T, data []byte) []Message {
	t.Helper()
	messages, err := Unmarshal(data)
	if err != nil {
		t.Fatal(err)
	}
	return messages
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
	if got := binary.LittleEndian.Uint32(data[20:24]); got != mustNEGOEXUint32(t, len(data)) {
		t.Fatalf("message length = %d, encoded length = %d", got, len(data))
	}
	decoded := mustUnmarshalTestMessages(t, data)
	if len(decoded) != 1 {
		t.Fatalf("decoded message count = %d, want 1", len(decoded))
	}
	got, ok := decoded[0].(*ExchangeMessage)
	if !ok {
		t.Fatalf("unexpected type %T", decoded[0])
	}
	if !reflect.DeepEqual(got.Exchange, message.Exchange) ||
		got.Header.SequenceNum != 7 || got.AuthScheme != message.AuthScheme {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestNegoMessageVectors(t *testing.T) {
	message := &NegoMessage{
		Header:          testHeader(MessageTypeInitiatorNego, 0),
		Random:          [32]byte{},
		ProtocolVersion: 0,
		AuthSchemes:     []AuthScheme{testScheme(), {1, 2, 3}},
		Extensions:      []Extension{{Type: 12, Value: []byte("extension")}},
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
	decoded := mustUnmarshalTestMessages(t, data)
	if len(decoded) != 1 {
		t.Fatalf("decoded message count = %d, want 1", len(decoded))
	}
	got, ok := decoded[0].(*NegoMessage)
	if !ok {
		t.Fatalf("unexpected type %T", decoded[0])
	}
	if !reflect.DeepEqual(got.AuthSchemes, message.AuthSchemes) ||
		!reflect.DeepEqual(got.Extensions, message.Extensions) || got.Random != message.Random {
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
	nego, ok := messages[0].(*NegoMessage)
	if !ok {
		t.Fatalf("unexpected type %T", messages[0])
	}
	wantScheme := AuthScheme{
		0x5c, 0x33, 0x53, 0x0d, 0xea, 0xf9, 0x0d, 0x4d,
		0xb2, 0xec, 0x4a, 0xe3, 0x78, 0x6e, 0xc3, 0x08,
	}
	if len(nego.AuthSchemes) != 1 || nego.AuthSchemes[0] != wantScheme {
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
		Checksum:   Checksum{HeaderLength: 0, Scheme: 0, Type: 16, Value: []byte("checksum")},
		Offset:     0,
	}
	alert := &AlertMessage{
		Header:     testHeader(MessageTypeAlert, 4),
		AuthScheme: testScheme(),
		ErrorCode:  0,
		Alerts:     []Alert{VerifyNoKeyAlert()},
	}
	token, err := Marshal(verify, alert)
	if err != nil {
		t.Fatal(err)
	}
	messages := mustUnmarshalTestMessages(t, token)
	if len(messages) != 2 {
		t.Fatalf("decoded %d messages", len(messages))
	}
	gotVerify, ok := messages[0].(*VerifyMessage)
	if !ok {
		t.Fatalf("unexpected type %T", messages[0])
	}
	if gotVerify.Offset != 0 || gotVerify.Checksum.Scheme != ChecksumSchemeRFC3961 ||
		!reflect.DeepEqual(gotVerify.Checksum.Value, verify.Checksum.Value) {
		t.Fatalf("verify mismatch: %#v", gotVerify)
	}
	gotAlert, ok := messages[1].(*AlertMessage)
	if !ok {
		t.Fatalf("unexpected type %T", messages[1])
	}
	if len(gotAlert.Alerts) != 1 || !gotAlert.Alerts[0].IsVerifyNoKey() {
		t.Fatalf("alert mismatch: %#v", gotAlert)
	}
}

func TestDecoderRejectsOutOfRangeVectors(t *testing.T) {
	message := &ExchangeMessage{
		Header:     testHeader(MessageTypeChallenge, 1),
		AuthScheme: AuthScheme{},
		Exchange:   []byte{1},
	}
	data, err := message.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	binary.LittleEndian.PutUint32(data[56:60], ^uint32(0))
	if _, ierr := Unmarshal(data); !errors.Is(ierr, ErrInvalidMessageSize) {
		t.Fatalf("error = %v", ierr)
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
		Header:          testHeader(MessageTypeInitiatorNego, 0),
		Random:          [32]byte{},
		ProtocolVersion: 0,
		AuthSchemes:     nil,
		Extensions:      []Extension{{Type: ExtensionFlagCritical | 1, Value: nil}},
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
	message := &ExchangeMessage{
		Header:     testHeader(MessageTypeAPRequest, 0),
		AuthScheme: AuthScheme{},
		Exchange:   nil,
	}
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

func (c *testContext) Wrap(message []byte, _ bool) ([]byte, error) {
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
	id               AuthScheme
	context          *testContext
	initErr          error
	acceptErr        error
	acceptErrorToken []byte
}

type testPKU2UMechanism struct {
	*testSchemeMechanism
	metadata    []byte
	metadataErr error
}

func (*testPKU2UMechanism) OID() asn1.ObjectIdentifier { return gssapi.OIDPKU2U.OID() }

//nolint:ireturn // gssapi.Mechanism requires a gssapi.Context result.
func (m *testPKU2UMechanism) InitSecContext(
	target string,
	input []byte,
	_ ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	return m.testSchemeMechanism.InitSecContext(target, input)
}

//nolint:ireturn // gssapi.Mechanism requires a gssapi.Context result.
func (m *testPKU2UMechanism) AcceptSecContext(
	input []byte,
	_ ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	return m.testSchemeMechanism.AcceptSecContext(input)
}

func (m *testPKU2UMechanism) QueryMetadata(target string, initiator bool) ([]byte, error) {
	if target != "host/server" || !initiator {
		return nil, errors.New("unexpected metadata query")
	}
	return append([]byte(nil), m.metadata...), m.metadataErr
}

func (m *testPKU2UMechanism) ExchangeMetadata(metadata []byte, initiator bool) error {
	if !reflect.DeepEqual(metadata, m.metadata) || initiator {
		return errors.New("unexpected metadata exchange")
	}
	return m.metadataErr
}

func (m *testSchemeMechanism) AuthScheme() AuthScheme { return m.id }

//nolint:ireturn // Scheme requires a gssapi.Context result.
func (m *testSchemeMechanism) InitSecContext(_ string, input []byte) ([]byte, gssapi.Context, bool, error) {
	switch string(input) {
	case "":
		return []byte("request-1"), m.context, false, m.initErr
	case "challenge":
		return []byte("request-2"), m.context, true, m.initErr
	default:
		return nil, m.context, false, errors.New("unexpected initiator input")
	}
}

//nolint:ireturn // Scheme requires a gssapi.Context result.
func (m *testSchemeMechanism) AcceptSecContext(input []byte) ([]byte, gssapi.Context, bool, error) {
	if m.acceptErr != nil {
		return m.acceptErrorToken, nil, false, m.acceptErr
	}
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
	var scheme testSchemeMechanism
	scheme.id = id
	scheme.context = &testContext{
		available: true,
		key: types.EncryptionKey{
			KeyType:  etypeID.AES256_CTS_HMAC_SHA1_96,
			KeyValue: []byte("0123456789abcdef0123456789abcdef"),
		},
		verifyAvailable: true,
	}
	return &scheme
}

func TestPKU2USchemeDelegatesMechanism(t *testing.T) {
	mechanism := &testPKU2UMechanism{
		testSchemeMechanism: newTestScheme(PKU2UAuthScheme),
		metadata:            []byte("metadata"),
		metadataErr:         nil,
	}
	scheme := NewPKU2UScheme(mechanism)
	if scheme.AuthScheme() != PKU2UAuthScheme {
		t.Fatalf("auth scheme = %v", scheme.AuthScheme())
	}
	output, _, done, err := scheme.InitSecContext("host/server", nil)
	if err != nil || done || string(output) != "request-1" {
		t.Fatalf("initiator output = %q, done=%v, err=%v", output, done, err)
	}
	output, _, done, err = scheme.AcceptSecContext([]byte("request-1"))
	if err != nil || done || string(output) != "challenge" {
		t.Fatalf("acceptor output = %q, done=%v, err=%v", output, done, err)
	}
	checkPKU2UMetadataDelegation(t, scheme)
}

func checkPKU2UMetadataDelegation(t *testing.T, scheme MetadataScheme) {
	t.Helper()
	if metadata, err := scheme.QueryMetadata("host/server", true); err != nil || string(metadata) != "metadata" {
		t.Fatalf("query metadata = %q, %v", metadata, err)
	}
	if err := scheme.ExchangeMetadata([]byte("metadata"), false); err != nil {
		t.Fatal(err)
	}
}

func TestNilConversationAccessors(t *testing.T) {
	var conversation *Conversation

	if conversation.Context() != nil {
		t.Fatal("nil conversation returned a context")
	}
	if got := conversation.SelectedScheme(); got != (AuthScheme{}) {
		t.Fatalf("selected scheme = %v, want zero", got)
	}
	output, done, err := conversation.Step(nil)
	if output != nil || done || !errors.Is(err, ErrInvalidConversationState) {
		t.Fatalf("nil conversation step = %x, %v, %v", output, done, err)
	}
}

func TestConversationEndToEnd(t *testing.T) {
	schemeID := testScheme()
	initiator := mustNewInitiator(t, "host/server", newTestScheme(schemeID))
	acceptor := mustNewAcceptor(t, newTestScheme(schemeID))
	challenge := startTestConversation(t, initiator, acceptor)
	initiatorToken, done, err := initiator.Step(challenge)
	if err != nil || !done {
		t.Fatalf("final initiator step: done=%v err=%v", done, err)
	}
	acceptorToken, done, err := acceptor.Step(initiatorToken)
	if err != nil || !done || len(acceptorToken) != 0 {
		t.Fatalf("final acceptor step: output=%x done=%v err=%v", acceptorToken, done, err)
	}
	if initiator.SelectedScheme() != schemeID || acceptor.SelectedScheme() != schemeID {
		t.Fatal("conversation selected the wrong scheme")
	}
}

func startTestConversation(t *testing.T, initiator, acceptor *Conversation) []byte {
	t.Helper()
	initiatorToken, done, err := initiator.Step(nil)
	if err != nil || done {
		t.Fatalf("initial initiator step: done=%v err=%v", done, err)
	}
	acceptorToken, done, err := acceptor.Step(initiatorToken)
	if err != nil || done {
		t.Fatalf("initial acceptor step: done=%v err=%v", done, err)
	}
	return acceptorToken
}

func TestMechanismEndToEndAndGuards(t *testing.T) {
	schemeID := testScheme()
	initiator := New(newTestScheme(schemeID), newTestScheme(schemeID))
	acceptor := New(newTestScheme(schemeID))
	if !initiator.OID().Equal(gssapi.OIDNegoEx.OID()) {
		t.Fatalf("mechanism OID = %v", initiator.OID())
	}
	challenge := startTestMechanism(t, initiator, acceptor)
	finishTestMechanism(t, initiator, acceptor, challenge)

	_, _, _, err := initiator.InitSecContext("other/target", nil)
	if err == nil || !strings.Contains(err.Error(), "target changed") {
		t.Fatalf("target change error = %v", err)
	}
	if _, _, _, err := New().InitSecContext("host/server", nil); !errors.Is(err, ErrNoAvailableSchemes) {
		t.Fatalf("empty initiator error = %v", err)
	}
	if _, _, _, err := New().AcceptSecContext([]byte{1}); !errors.Is(err, ErrNoAvailableSchemes) {
		t.Fatalf("empty acceptor error = %v", err)
	}
}

func startTestMechanism(t *testing.T, initiator, acceptor *Mechanism) []byte {
	t.Helper()
	initiatorToken, initiatorContext, done, err := initiator.InitSecContext("host/server", nil)
	if err != nil || done || initiatorContext == nil {
		t.Fatalf("initial initiator = context %v, done %v, err %v", initiatorContext, done, err)
	}
	acceptorToken, acceptorContext, done, err := acceptor.AcceptSecContext(initiatorToken)
	if err != nil || done || acceptorContext == nil {
		t.Fatalf("initial acceptor = context %v, done %v, err %v", acceptorContext, done, err)
	}
	return acceptorToken
}

func finishTestMechanism(t *testing.T, initiator, acceptor *Mechanism, challenge []byte) {
	t.Helper()
	initiatorToken, initiatorContext, done, err := initiator.InitSecContext("host/server", challenge)
	if err != nil || !done || initiatorContext == nil {
		t.Fatalf("final initiator = context %v, done %v, err %v", initiatorContext, done, err)
	}
	acceptorToken, acceptorContext, done, err := acceptor.AcceptSecContext(initiatorToken)
	if err != nil || !done || len(acceptorToken) != 0 || acceptorContext == nil {
		t.Fatalf("final acceptor = output %x, context %v, done %v, err %v", acceptorToken, acceptorContext, done, err)
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
	initiator := mustNewInitiator(t, "host/server", newTestScheme(schemeID))
	acceptor := mustNewAcceptor(t, newTestScheme(schemeID))
	token, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) <= 40 {
		t.Fatalf("initiator token length = %d", len(token))
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
	initiator := mustNewInitiator(t, "host/server", initiatorScheme)
	acceptor := mustNewAcceptor(t, acceptorScheme)

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
	initiator := mustNewInitiator(t, "host/server", scheme)
	acceptor := mustNewAcceptor(t, newTestScheme(testScheme()))

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
	initiator := mustNewInitiator(t, "host/server", newTestScheme(testScheme()))
	acceptor := mustNewAcceptor(t, newTestScheme(testScheme()))
	token, _, err := initiator.Step(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) < 16 {
		t.Fatalf("initiator token length = %d", len(token))
	}
	binary.LittleEndian.PutUint32(token[12:16], 1)
	if _, _, err := acceptor.Step(token); !errors.Is(err, ErrMessageOutOfSequence) {
		t.Fatalf("error = %v", err)
	}
}

func TestAcceptorSchemePreferenceOrder(t *testing.T) {
	first := AuthScheme{1}
	second := AuthScheme{2}
	initiator := mustNewInitiator(t, "host/server", newTestScheme(first), newTestScheme(second))
	acceptor := mustNewAcceptor(t, newTestScheme(second), newTestScheme(first))
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

//nolint:ireturn // Scheme requires a gssapi.Context result.
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
	initiator := mustNewInitiator(t, "host/server", newTestScheme(firstID), newTestScheme(selectedID))
	selected := &rejectEmptyScheme{testSchemeMechanism: newTestScheme(selectedID), acceptCalls: 0}
	acceptor := mustNewAcceptor(t, selected)

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
	failed := &testMetadataScheme{
		testSchemeMechanism: newTestScheme(failedID),
		queryErr:            errors.New("unavailable"),
		exchangeErr:         nil,
		exchangeCalls:       0,
	}
	initiator := mustNewInitiator(t, "host/server", failed, newTestScheme(selectedID))

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
	failed := &testMetadataScheme{
		testSchemeMechanism: newTestScheme(failedID),
		queryErr:            nil,
		exchangeErr:         errors.New("rejected"),
		exchangeCalls:       0,
	}
	acceptor := mustNewAcceptor(t, failed, newTestScheme(selectedID))
	metadata := &ExchangeMessage{
		Header:     testHeader(MessageTypeInitiatorMetaData, 1),
		AuthScheme: failedID,
		Exchange:   []byte("metadata"),
	}
	nego := &NegoMessage{
		Header:          testHeader(MessageTypeInitiatorNego, 0),
		Random:          [32]byte{},
		ProtocolVersion: 0,
		AuthSchemes:     []AuthScheme{failedID, selectedID},
		Extensions:      nil,
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
	scheme := &testMetadataScheme{
		testSchemeMechanism: newTestScheme(schemeID),
		queryErr:            nil,
		exchangeErr:         nil,
		exchangeCalls:       0,
	}
	acceptor := mustNewAcceptor(t, scheme)
	nego := &NegoMessage{
		Header:          testHeader(MessageTypeInitiatorNego, 0),
		Random:          [32]byte{},
		ProtocolVersion: 0,
		AuthSchemes:     []AuthScheme{schemeID},
		Extensions:      nil,
	}
	first := &ExchangeMessage{
		Header:     testHeader(MessageTypeInitiatorMetaData, 1),
		AuthScheme: schemeID,
		Exchange:   []byte("first"),
	}
	second := &ExchangeMessage{
		Header:     testHeader(MessageTypeInitiatorMetaData, 2),
		AuthScheme: schemeID,
		Exchange:   []byte("second"),
	}
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
	acceptor := mustNewAcceptor(t, newTestScheme(schemeID))
	nego := &NegoMessage{
		Header:          testHeader(MessageTypeInitiatorNego, 0),
		Random:          [32]byte{},
		ProtocolVersion: 0,
		AuthSchemes:     []AuthScheme{schemeID},
		Extensions:      nil,
	}
	alert := &AlertMessage{
		Header:     testHeader(MessageTypeAlert, 1),
		AuthScheme: schemeID,
		ErrorCode:  uint32(ntstatus.STATUS_ACCOUNT_DISABLED),
		Alerts:     nil,
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
