package negoex

import (
	"crypto/rand"
	"errors"
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/gssapi"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
)

// NEGOEX conversation state errors.
var (
	// ErrInvalidConversation indicates a NEGOEX message with an unexpected conversation ID.
	ErrInvalidConversation = errors.New("invalid NEGOEX conversation ID")
	// ErrInvalidConversationState indicates an uninitialized NEGOEX conversation.
	ErrInvalidConversationState = errors.New("invalid NEGOEX conversation state")
	// ErrMessageOutOfSequence indicates a NEGOEX message arrived out of sequence.
	ErrMessageOutOfSequence = errors.New("NEGOEX message out of sequence")
	ErrNoAvailableSchemes   = errors.New("no mutually supported NEGOEX authentication schemes")
	ErrMissingNegoMessage   = errors.New("missing NEGOEX negotiate message")
	ErrMissingVerify        = errors.New("missing NEGOEX VERIFY message")
	ErrUnexpectedToken      = errors.New("unexpected NEGOEX input token")
)

// AlertError reports a non-success NTSTATUS received in an ALERT message.
type AlertError struct {
	Status ntstatus.Code
}

func (e AlertError) Error() string { return fmt.Sprintf("NEGOEX alert: %s", e.Status) }

// NTStatus exposes the Windows status carried by the peer.
func (e AlertError) NTStatus() (ntstatus.Code, bool) { return e.Status, true }

// Scheme is an authentication mechanism carried by NEGOEX.
type Scheme interface {
	AuthScheme() AuthScheme
	InitSecContext(target string, input []byte) (output []byte, context gssapi.Context, done bool, err error)
	AcceptSecContext(input []byte) (output []byte, context gssapi.Context, done bool, err error)
}

// MetadataScheme optionally participates in the NEGOEX metadata exchange.
type MetadataScheme interface {
	Scheme
	QueryMetadata(target string, initiator bool) ([]byte, error)
	ExchangeMetadata(metadata []byte, initiator bool) error
}

// Conversation contains the state shared across NEGOEX context-establishment
// calls. A Conversation must not be used concurrently.
type Conversation struct {
	initiator     bool
	target        string
	schemes       []Scheme
	selected      Scheme
	context       gssapi.Context
	conversation  ConversationID
	sequence      uint32
	step          uint32
	transcript    []byte
	mechanismDone bool
	sentVerify    bool
	peerVerified  bool
}

// NewInitiator creates an initiator conversation.
func NewInitiator(target string, schemes ...Scheme) (*Conversation, error) {
	conversation, err := newConversation(true, target, schemes)
	if err != nil {
		return nil, err
	}
	if _, err := rand.Read(conversation.conversation[:]); err != nil {
		return nil, fmt.Errorf("generate NEGOEX conversation ID: %w", err)
	}
	return conversation, nil
}

// NewAcceptor creates an acceptor conversation.
func NewAcceptor(schemes ...Scheme) (*Conversation, error) {
	return newConversation(false, "", schemes)
}

func newConversation(initiator bool, target string, schemes []Scheme) (*Conversation, error) {
	schemes = uniqueSchemes(schemes)
	if len(schemes) == 0 {
		return nil, ErrNoAvailableSchemes
	}
	return &Conversation{
		initiator:     initiator,
		target:        target,
		schemes:       schemes,
		selected:      nil,
		context:       nil,
		conversation:  ConversationID{},
		sequence:      0,
		step:          0,
		transcript:    nil,
		mechanismDone: false,
		sentVerify:    false,
		peerVerified:  false,
	}, nil
}

// Context returns the selected mechanism context, if one has been created.
//
//nolint:ireturn // The concrete context is supplied by the selected scheme.
func (c *Conversation) Context() gssapi.Context {
	if c == nil {
		return nil
	}
	return c.context
}

// SelectedScheme returns the selected authentication scheme, or zero before
// one has been selected.
func (c *Conversation) SelectedScheme() AuthScheme {
	if c == nil || c.selected == nil {
		return AuthScheme{}
	}
	return c.selected.AuthScheme()
}

// Step consumes one peer token and produces the next local token.
func (c *Conversation) Step(input []byte) ([]byte, bool, error) {
	if c == nil {
		return nil, false, ErrInvalidConversationState
	}
	if c.step == 0 && c.initiator {
		if len(input) != 0 {
			return nil, false, ErrUnexpectedToken
		}
		c.step++
		return c.initialInitiatorToken()
	}
	if len(input) == 0 {
		return nil, false, ErrUnexpectedToken
	}
	messages, err := Unmarshal(input)
	if err != nil {
		return nil, false, err
	}
	if err := c.validateIncoming(messages); err != nil {
		return nil, false, err
	}
	c.step++
	if c.step == 1 {
		return c.firstAcceptorStep(input, messages)
	}
	return c.continueStep(input, messages)
}

func (c *Conversation) initialInitiatorToken() ([]byte, bool, error) {
	var metadataByScheme map[AuthScheme][]byte
	c.schemes, metadataByScheme = querySchemeMetadata(c.schemes, c.target, true)
	if len(c.schemes) == 0 {
		return nil, false, ErrNoAvailableSchemes
	}
	nego := newNegoMessage(MessageTypeInitiatorNego, c.schemes)
	if _, err := rand.Read(nego.Random[:]); err != nil {
		return nil, false, fmt.Errorf("generate initiator NEGOEX random value: %w", err)
	}
	outgoing := c.appendMetadata([]Message{nego}, MessageTypeInitiatorMetaData, metadataByScheme)
	c.selected = c.schemes[0]
	mechanismToken, context, done, err := c.selected.InitSecContext(c.target, nil)
	if err != nil {
		return nil, false, fmt.Errorf("initialize NEGOEX mechanism: %w", err)
	}
	c.context, c.mechanismDone = context, done
	if len(mechanismToken) > 0 {
		outgoing = append(outgoing, newExchangeMessage(MessageTypeAPRequest, c.selected.AuthScheme(), mechanismToken))
	}
	return c.emit(outgoing, false)
}

func (c *Conversation) firstAcceptorStep(input []byte, messages []Message) ([]byte, bool, error) {
	metadataByScheme, err := c.selectAcceptorScheme(messages)
	if err != nil {
		return nil, false, err
	}
	if alertErr := incomingAlertError(messages, c.selected.AuthScheme()); alertErr != nil {
		return nil, false, alertErr
	}
	mechanismToken := c.acceptOptimisticRequest(messages)
	sendAlert, err := c.verifyIncoming(input, messages)
	if err != nil {
		return nil, false, err
	}
	c.transcript = append(c.transcript, input...)

	response := newNegoMessage(MessageTypeAcceptorNego, c.schemes)
	if _, err := rand.Read(response.Random[:]); err != nil {
		return nil, false, fmt.Errorf("generate acceptor NEGOEX random value: %w", err)
	}
	outgoing := c.appendMetadata([]Message{response}, MessageTypeAcceptorMetaData, metadataByScheme)
	if len(mechanismToken) > 0 {
		outgoing = append(outgoing, newExchangeMessage(MessageTypeChallenge, c.selected.AuthScheme(), mechanismToken))
	}
	return c.emit(outgoing, sendAlert)
}

func (c *Conversation) selectAcceptorScheme(messages []Message) (map[AuthScheme][]byte, error) {
	nego := findNego(messages, MessageTypeInitiatorNego)
	if nego == nil {
		return nil, ErrMissingNegoMessage
	}
	c.schemes = restrictSchemes(c.schemes, nego.AuthSchemes)
	if len(c.schemes) == 0 {
		return nil, ErrNoAvailableSchemes
	}
	c.processMetadata(messages, false)
	var metadataByScheme map[AuthScheme][]byte
	c.schemes, metadataByScheme = querySchemeMetadata(c.schemes, c.target, false)
	if len(c.schemes) == 0 {
		return nil, ErrNoAvailableSchemes
	}
	c.selected = c.schemes[0]
	return metadataByScheme, nil
}

func (c *Conversation) acceptOptimisticRequest(messages []Message) []byte {
	request := findExchange(messages, MessageTypeAPRequest, c.selected.AuthScheme())
	if request == nil {
		return nil
	}
	var mechanismToken []byte
	var err error
	mechanismToken, c.context, c.mechanismDone, err = c.selected.AcceptSecContext(request.Exchange)
	if err != nil && len(mechanismToken) == 0 {
		// An optimistic mechanism failure is recoverable. The initiator can
		// restart the selected mechanism after the acceptor negotiation.
		c.context, c.mechanismDone = nil, false
	}
	return mechanismToken
}

func (c *Conversation) appendMetadata(
	outgoing []Message,
	messageType uint32,
	metadataByScheme map[AuthScheme][]byte,
) []Message {
	for _, scheme := range c.schemes {
		metadata := metadataByScheme[scheme.AuthScheme()]
		if len(metadata) > 0 {
			outgoing = append(outgoing, newExchangeMessage(messageType, scheme.AuthScheme(), metadata))
		}
	}
	return outgoing
}

func (c *Conversation) continueStep(input []byte, messages []Message) ([]byte, bool, error) {
	if err := c.selectInitiatorScheme(messages); err != nil {
		return nil, false, err
	}
	if err := incomingAlertError(messages, c.selected.AuthScheme()); err != nil {
		return nil, false, err
	}

	messageType := MessageTypeAPRequest
	responseType := MessageTypeChallenge
	if c.initiator {
		messageType, responseType = MessageTypeChallenge, MessageTypeAPRequest
	}
	exchange := findExchange(messages, messageType, c.selected.AuthScheme())
	var mechanismInput []byte
	switch {
	case exchange != nil:
		mechanismInput = exchange.Exchange
	case c.mechanismDone:
		return c.finishContinuation(input, messages, responseType, nil)
	case !c.initiator || c.step != 2:
		return nil, false, ErrUnexpectedToken
	}
	mechanismToken, err := c.advanceMechanism(mechanismInput)
	if err != nil {
		return nil, false, err
	}
	return c.finishContinuation(input, messages, responseType, mechanismToken)
}

func (c *Conversation) selectInitiatorScheme(messages []Message) error {
	if !c.initiator || c.step != 2 {
		return nil
	}
	nego := findNego(messages, MessageTypeAcceptorNego)
	if nego == nil {
		return ErrMissingNegoMessage
	}
	common := intersectSchemes(nego.AuthSchemes, c.schemes)
	if len(common) == 0 {
		return ErrNoAvailableSchemes
	}
	previous := c.selected
	c.schemes = common
	c.processMetadata(messages, true)
	if len(c.schemes) == 0 {
		return ErrNoAvailableSchemes
	}
	c.selected = c.schemes[0]
	changed := previous == nil || previous.AuthScheme() != c.selected.AuthScheme()
	if changed || c.missingOptimisticResponse(messages) {
		c.context, c.mechanismDone = nil, false
	}
	return nil
}

func (c *Conversation) missingOptimisticResponse(messages []Message) bool {
	return findExchange(messages, MessageTypeChallenge, c.selected.AuthScheme()) == nil &&
		findVerify(messages, c.selected.AuthScheme()) == nil
}

func (c *Conversation) advanceMechanism(input []byte) ([]byte, error) {
	var mechanismToken []byte
	var context gssapi.Context
	var done bool
	var err error
	if c.initiator {
		mechanismToken, context, done, err = c.selected.InitSecContext(c.target, input)
	} else {
		mechanismToken, context, done, err = c.selected.AcceptSecContext(input)
	}
	if err != nil && len(mechanismToken) == 0 {
		return nil, fmt.Errorf("continue NEGOEX mechanism: %w", err)
	}
	if context != nil {
		c.context = context
	}
	c.mechanismDone = done
	return mechanismToken, nil
}

func (c *Conversation) finishContinuation(
	input []byte,
	messages []Message,
	responseType uint32,
	mechanismToken []byte,
) ([]byte, bool, error) {
	sendAlert, err := c.verifyIncoming(input, messages)
	if err != nil {
		return nil, false, err
	}
	if hasVerifyNoKeyAlert(messages, c.selected.AuthScheme()) {
		c.sentVerify = false
	}
	c.transcript = append(c.transcript, input...)
	var outgoing []Message
	if len(mechanismToken) > 0 {
		outgoing = append(outgoing, newExchangeMessage(responseType, c.selected.AuthScheme(), mechanismToken))
	}
	return c.emit(outgoing, sendAlert)
}

func (c *Conversation) emit(messages []Message, sendAlert bool) ([]byte, bool, error) {
	if sendAlert {
		messages = append(messages, &AlertMessage{
			Header:     outgoingMessageHeader(MessageTypeAlert, 0, ConversationID{}),
			AuthScheme: c.selected.AuthScheme(),
			ErrorCode:  0,
			Alerts:     []Alert{VerifyNoKeyAlert()},
		})
	}
	var output []byte
	for _, message := range messages {
		encoded, err := c.encodeOutgoing(message)
		if err != nil {
			return nil, false, err
		}
		output = append(output, encoded...)
	}
	output, err := c.appendVerify(output)
	if err != nil {
		return nil, false, err
	}
	if !c.mechanismDone {
		return output, false, nil
	}
	if !c.sentVerify {
		return nil, false, ErrNoVerifyKey
	}
	if !c.peerVerified && len(output) == 0 {
		return nil, false, ErrMissingVerify
	}
	return output, c.peerVerified, nil
}

func (c *Conversation) encodeOutgoing(message Message) ([]byte, error) {
	setMessageHeader(message, c.sequence, c.conversation)
	encoded, err := marshalMessage(message)
	if err != nil {
		return nil, err
	}
	c.sequence++
	c.transcript = append(c.transcript, encoded...)
	return encoded, nil
}

func (c *Conversation) appendVerify(output []byte) ([]byte, error) {
	if c.sentVerify || c.context == nil {
		return output, nil
	}
	key, ok := c.context.NegoExKey()
	if !ok {
		return output, nil
	}
	usage := uint32(keyusage.NEGOEX_ACCEPTOR_CHECKSUM)
	if c.initiator {
		usage = keyusage.NEGOEX_INITIATOR_CHECKSUM
	}
	checksum, err := MakeChecksum(key, usage, c.transcript)
	if err != nil {
		return nil, err
	}
	verify := &VerifyMessage{
		Header:     outgoingMessageHeader(MessageTypeVerify, 0, ConversationID{}),
		AuthScheme: c.selected.AuthScheme(),
		Checksum:   checksum,
		Offset:     0,
	}
	encoded, err := c.encodeOutgoing(verify)
	if err != nil {
		return nil, err
	}
	output = append(output, encoded...)
	c.sentVerify = true
	return output, nil
}

func (c *Conversation) validateIncoming(messages []Message) error {
	if len(messages) == 0 {
		return ErrUnexpectedToken
	}
	sequence := c.sequence
	conversation := c.conversation
	for index, message := range messages {
		header := message.messageHeader()
		if header.SequenceNum != sequence {
			return ErrMessageOutOfSequence
		}
		if c.step == 0 && !c.initiator && index == 0 {
			conversation = header.ConversationID
		} else if header.ConversationID != conversation {
			return ErrInvalidConversation
		}
		sequence++
	}
	c.conversation, c.sequence = conversation, sequence
	return nil
}

func (c *Conversation) verifyIncoming(input []byte, messages []Message) (bool, error) {
	verify := findVerify(messages, c.selected.AuthScheme())
	if verify == nil {
		return false, nil
	}
	if c.context == nil {
		return true, nil
	}
	key, ok := c.context.NegoExVerifyKey()
	if !ok {
		return true, nil
	}
	usage := uint32(keyusage.NEGOEX_INITIATOR_CHECKSUM)
	if c.initiator {
		usage = keyusage.NEGOEX_ACCEPTOR_CHECKSUM
	}
	covered := make([]byte, 0, len(c.transcript)+verify.Offset)
	covered = append(covered, c.transcript...)
	covered = append(covered, input[:verify.Offset]...)
	if err := VerifyChecksum(key, usage, covered, verify.Checksum); err != nil {
		return false, err
	}
	c.peerVerified = true
	return false, nil
}

func (c *Conversation) processMetadata(messages []Message, receivingAcceptorMetadata bool) {
	messageType := MessageTypeInitiatorMetaData
	if receivingAcceptorMetadata {
		messageType = MessageTypeAcceptorMetaData
	}
	retained := c.schemes[:0]
	for _, scheme := range c.schemes {
		if c.acceptsMetadata(scheme, messages, messageType) {
			retained = append(retained, scheme)
		}
	}
	c.schemes = retained
}

func (c *Conversation) acceptsMetadata(scheme Scheme, messages []Message, messageType uint32) bool {
	provider, ok := scheme.(MetadataScheme)
	if !ok {
		return true
	}
	for _, message := range messages {
		metadata, ok := message.(*ExchangeMessage)
		if !ok || metadata.Header.MessageType != messageType || metadata.AuthScheme != scheme.AuthScheme() {
			continue
		}
		if err := provider.ExchangeMetadata(metadata.Exchange, c.initiator); err != nil {
			return false
		}
	}
	return true
}

func querySchemeMetadata(schemes []Scheme, target string, initiator bool) ([]Scheme, map[AuthScheme][]byte) {
	retained := make([]Scheme, 0, len(schemes))
	metadata := make(map[AuthScheme][]byte)
	for _, scheme := range schemes {
		provider, ok := scheme.(MetadataScheme)
		if !ok {
			retained = append(retained, scheme)
			continue
		}
		value, err := provider.QueryMetadata(target, initiator)
		if err != nil {
			continue
		}
		retained = append(retained, scheme)
		metadata[scheme.AuthScheme()] = value
	}
	return retained, metadata
}

func uniqueSchemes(schemes []Scheme) []Scheme {
	result := make([]Scheme, 0, len(schemes))
	seen := make(map[AuthScheme]bool)
	for _, scheme := range schemes {
		if scheme == nil || seen[scheme.AuthScheme()] {
			continue
		}
		seen[scheme.AuthScheme()] = true
		result = append(result, scheme)
	}
	return result
}

func schemeIDs(schemes []Scheme) []AuthScheme {
	ids := make([]AuthScheme, len(schemes))
	for index, scheme := range schemes {
		ids[index] = scheme.AuthScheme()
	}
	return ids
}

func intersectSchemes(offered []AuthScheme, available []Scheme) []Scheme {
	byID := make(map[AuthScheme]Scheme, len(available))
	for _, scheme := range available {
		byID[scheme.AuthScheme()] = scheme
	}
	common := make([]Scheme, 0, len(available))
	for _, id := range offered {
		if scheme := byID[id]; scheme != nil {
			common = append(common, scheme)
			delete(byID, id)
		}
	}
	return common
}

func restrictSchemes(available []Scheme, offered []AuthScheme) []Scheme {
	offeredIDs := make(map[AuthScheme]bool, len(offered))
	for _, id := range offered {
		offeredIDs[id] = true
	}
	common := make([]Scheme, 0, len(available))
	for _, scheme := range available {
		if offeredIDs[scheme.AuthScheme()] {
			common = append(common, scheme)
		}
	}
	return common
}

func findNego(messages []Message, messageType uint32) *NegoMessage {
	for _, message := range messages {
		if candidate, ok := message.(*NegoMessage); ok && candidate.Header.MessageType == messageType {
			return candidate
		}
	}
	return nil
}

func findExchange(messages []Message, messageType uint32, scheme AuthScheme) *ExchangeMessage {
	for _, message := range messages {
		candidate, ok := message.(*ExchangeMessage)
		if ok && candidate.Header.MessageType == messageType && candidate.AuthScheme == scheme {
			return candidate
		}
	}
	return nil
}

func findVerify(messages []Message, scheme AuthScheme) *VerifyMessage {
	for _, message := range messages {
		if candidate, ok := message.(*VerifyMessage); ok && candidate.AuthScheme == scheme {
			return candidate
		}
	}
	return nil
}

func hasVerifyNoKeyAlert(messages []Message, scheme AuthScheme) bool {
	for _, message := range messages {
		candidate, ok := message.(*AlertMessage)
		if !ok || candidate.AuthScheme != scheme {
			continue
		}
		for _, alert := range candidate.Alerts {
			if alert.IsVerifyNoKey() {
				return true
			}
		}
	}
	return false
}

func incomingAlertError(messages []Message, scheme AuthScheme) error {
	for _, message := range messages {
		alert, ok := message.(*AlertMessage)
		if ok && alert.AuthScheme == scheme && alert.ErrorCode != 0 {
			return AlertError{Status: ntstatus.Code(alert.ErrorCode)}
		}
	}
	return nil
}

func newNegoMessage(messageType uint32, schemes []Scheme) *NegoMessage {
	return &NegoMessage{
		Header:          outgoingMessageHeader(messageType, 0, ConversationID{}),
		Random:          [32]byte{},
		ProtocolVersion: 0,
		AuthSchemes:     schemeIDs(schemes),
		Extensions:      nil,
	}
}

func newExchangeMessage(messageType uint32, scheme AuthScheme, exchange []byte) *ExchangeMessage {
	return &ExchangeMessage{
		Header:     outgoingMessageHeader(messageType, 0, ConversationID{}),
		AuthScheme: scheme,
		Exchange:   exchange,
	}
}

func outgoingMessageHeader(messageType, sequence uint32, conversation ConversationID) MessageHeader {
	// The message marshaler fills in the wire signature and lengths.
	return MessageHeader{
		Signature:      0,
		MessageType:    messageType,
		SequenceNum:    sequence,
		HeaderLength:   0,
		MessageLength:  0,
		ConversationID: conversation,
	}
}

func setMessageHeader(message Message, sequence uint32, conversation ConversationID) {
	header := outgoingMessageHeader(message.messageHeader().MessageType, sequence, conversation)
	switch typed := message.(type) {
	case *NegoMessage:
		typed.Header = header
	case *ExchangeMessage:
		typed.Header = header
	case *VerifyMessage:
		typed.Header = header
	case *AlertMessage:
		typed.Header = header
	}
}

// Mechanism is a stateful NEGOEX mechanism. Each direction supports one
// context-establishment conversation; create a new Mechanism for another.
type Mechanism struct {
	schemes   []Scheme
	initiator *Conversation
	acceptor  *Conversation
}

// New creates a NEGOEX mechanism with schemes in preference order.
func New(schemes ...Scheme) *Mechanism {
	return &Mechanism{schemes: uniqueSchemes(schemes), initiator: nil, acceptor: nil}
}

// OID returns the NEGOEX GSS mechanism OID.
func (m *Mechanism) OID() asn1.ObjectIdentifier { return gssapi.OIDNegoEx.OID() }

// InitSecContext advances the initiator conversation.
//
//nolint:ireturn // Implements gssapi.ContextMechanism.
func (m *Mechanism) InitSecContext(
	target string,
	input []byte,
	_ ...gssapi.MechanismOption,
) ([]byte, gssapi.Context, bool, error) {
	if m.initiator == nil {
		conversation, err := NewInitiator(target, m.schemes...)
		if err != nil {
			return nil, nil, false, err
		}
		m.initiator = conversation
	} else if target != m.initiator.target {
		return nil, nil, false, errors.New("NEGOEX target changed during context establishment")
	}
	output, done, err := m.initiator.Step(input)
	return output, m.initiator.Context(), done, err
}

// AcceptSecContext advances the acceptor conversation.
//
//nolint:ireturn // Implements gssapi.ContextMechanism.
func (m *Mechanism) AcceptSecContext(input []byte, _ ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
	if m.acceptor == nil {
		conversation, err := NewAcceptor(m.schemes...)
		if err != nil {
			return nil, nil, false, err
		}
		m.acceptor = conversation
	}
	output, done, err := m.acceptor.Step(input)
	return output, m.acceptor.Context(), done, err
}

var _ gssapi.ContextMechanism = (*Mechanism)(nil)
