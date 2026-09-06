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

var (
	ErrInvalidConversation  = errors.New("invalid NEGOEX conversation ID")
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
	conversation := &Conversation{initiator: true, target: target, schemes: uniqueSchemes(schemes)}
	if len(conversation.schemes) == 0 {
		return nil, ErrNoAvailableSchemes
	}
	if _, err := rand.Read(conversation.conversation[:]); err != nil {
		return nil, fmt.Errorf("generate NEGOEX conversation ID: %w", err)
	}
	return conversation, nil
}

// NewAcceptor creates an acceptor conversation.
func NewAcceptor(schemes ...Scheme) (*Conversation, error) {
	conversation := &Conversation{schemes: uniqueSchemes(schemes)}
	if len(conversation.schemes) == 0 {
		return nil, ErrNoAvailableSchemes
	}
	return conversation, nil
}

// Context returns the selected mechanism context, if one has been created.
func (c *Conversation) Context() gssapi.Context { return c.context }

// SelectedScheme returns the selected authentication scheme, or zero before
// one has been selected.
func (c *Conversation) SelectedScheme() AuthScheme {
	if c.selected == nil {
		return AuthScheme{}
	}
	return c.selected.AuthScheme()
}

// Step consumes one peer token and produces the next local token.
func (c *Conversation) Step(input []byte) ([]byte, bool, error) {
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
	nego := &NegoMessage{Header: MessageHeader{MessageType: MessageTypeInitiatorNego}, AuthSchemes: schemeIDs(c.schemes)}
	if _, err := rand.Read(nego.Random[:]); err != nil {
		return nil, false, err
	}
	var outgoing []Message
	outgoing = append(outgoing, nego)
	for _, scheme := range c.schemes {
		metadata := metadataByScheme[scheme.AuthScheme()]
		if len(metadata) > 0 {
			outgoing = append(outgoing, &ExchangeMessage{Header: MessageHeader{MessageType: MessageTypeInitiatorMetaData}, AuthScheme: scheme.AuthScheme(), Exchange: metadata})
		}
	}
	c.selected = c.schemes[0]
	mechanismToken, context, done, err := c.selected.InitSecContext(c.target, nil)
	if err != nil {
		return nil, false, err
	}
	c.context, c.mechanismDone = context, done
	if len(mechanismToken) > 0 {
		outgoing = append(outgoing, &ExchangeMessage{Header: MessageHeader{MessageType: MessageTypeAPRequest}, AuthScheme: c.selected.AuthScheme(), Exchange: mechanismToken})
	}
	return c.emit(outgoing, false)
}

func (c *Conversation) firstAcceptorStep(input []byte, messages []Message) ([]byte, bool, error) {
	nego := findNego(messages, MessageTypeInitiatorNego)
	if nego == nil {
		return nil, false, ErrMissingNegoMessage
	}
	c.schemes = restrictSchemes(c.schemes, nego.AuthSchemes)
	if len(c.schemes) == 0 {
		return nil, false, ErrNoAvailableSchemes
	}
	c.processMetadata(messages, false)
	var metadataByScheme map[AuthScheme][]byte
	c.schemes, metadataByScheme = querySchemeMetadata(c.schemes, c.target, false)
	if len(c.schemes) == 0 {
		return nil, false, ErrNoAvailableSchemes
	}
	c.selected = c.schemes[0]
	if err := incomingAlertError(messages, c.selected.AuthScheme()); err != nil {
		return nil, false, err
	}
	request := findExchange(messages, MessageTypeAPRequest, c.selected.AuthScheme())
	var mechanismToken []byte
	if request != nil {
		var err error
		mechanismToken, c.context, c.mechanismDone, err = c.selected.AcceptSecContext(request.Exchange)
		if err != nil && len(mechanismToken) == 0 {
			// An optimistic mechanism failure is recoverable. The initiator can
			// restart the selected mechanism after the acceptor negotiation.
			c.context, c.mechanismDone = nil, false
		}
	}
	sendAlert, err := c.verifyIncoming(input, messages)
	if err != nil {
		return nil, false, err
	}
	c.transcript = append(c.transcript, input...)

	response := &NegoMessage{Header: MessageHeader{MessageType: MessageTypeAcceptorNego}, AuthSchemes: schemeIDs(c.schemes)}
	if _, err := rand.Read(response.Random[:]); err != nil {
		return nil, false, err
	}
	var outgoing []Message
	outgoing = append(outgoing, response)
	for _, scheme := range c.schemes {
		metadata := metadataByScheme[scheme.AuthScheme()]
		if len(metadata) > 0 {
			outgoing = append(outgoing, &ExchangeMessage{Header: MessageHeader{MessageType: MessageTypeAcceptorMetaData}, AuthScheme: scheme.AuthScheme(), Exchange: metadata})
		}
	}
	if len(mechanismToken) > 0 {
		outgoing = append(outgoing, &ExchangeMessage{Header: MessageHeader{MessageType: MessageTypeChallenge}, AuthScheme: c.selected.AuthScheme(), Exchange: mechanismToken})
	}
	return c.emit(outgoing, sendAlert)
}

func (c *Conversation) continueStep(input []byte, messages []Message) ([]byte, bool, error) {
	if c.initiator && c.step == 2 {
		nego := findNego(messages, MessageTypeAcceptorNego)
		if nego == nil {
			return nil, false, ErrMissingNegoMessage
		}
		common := intersectSchemes(nego.AuthSchemes, c.schemes)
		if len(common) == 0 {
			return nil, false, ErrNoAvailableSchemes
		}
		previous := c.selected
		c.schemes = common
		c.processMetadata(messages, true)
		if len(c.schemes) == 0 {
			return nil, false, ErrNoAvailableSchemes
		}
		c.selected = c.schemes[0]
		if previous == nil || previous.AuthScheme() != c.selected.AuthScheme() ||
			(findExchange(messages, MessageTypeChallenge, c.selected.AuthScheme()) == nil && findVerify(messages, c.selected.AuthScheme()) == nil) {
			c.context, c.mechanismDone = nil, false
		}
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
	if exchange != nil {
		mechanismInput = exchange.Exchange
	} else if c.mechanismDone {
		sendAlert, err := c.verifyIncoming(input, messages)
		if err != nil {
			return nil, false, err
		}
		if hasVerifyNoKeyAlert(messages, c.selected.AuthScheme()) {
			c.sentVerify = false
		}
		c.transcript = append(c.transcript, input...)
		return c.emit(nil, sendAlert)
	} else if !(c.initiator && c.step == 2) {
		return nil, false, ErrUnexpectedToken
	}
	var mechanismToken []byte
	var context gssapi.Context
	var done bool
	var err error
	if c.initiator {
		mechanismToken, context, done, err = c.selected.InitSecContext(c.target, mechanismInput)
	} else {
		mechanismToken, context, done, err = c.selected.AcceptSecContext(mechanismInput)
	}
	if err != nil && len(mechanismToken) == 0 {
		return nil, false, err
	}
	if context != nil {
		c.context = context
	}
	c.mechanismDone = done
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
		outgoing = append(outgoing, &ExchangeMessage{Header: MessageHeader{MessageType: responseType}, AuthScheme: c.selected.AuthScheme(), Exchange: mechanismToken})
	}
	return c.emit(outgoing, sendAlert)
}

func (c *Conversation) emit(messages []Message, sendAlert bool) ([]byte, bool, error) {
	if sendAlert {
		messages = append(messages, &AlertMessage{
			Header: MessageHeader{MessageType: MessageTypeAlert}, AuthScheme: c.selected.AuthScheme(), Alerts: []Alert{VerifyNoKeyAlert()},
		})
	}
	var output []byte
	for _, message := range messages {
		setMessageHeader(message, c.sequence, c.conversation)
		encoded, err := message.MarshalBinary()
		if err != nil {
			return nil, false, err
		}
		c.sequence++
		c.transcript = append(c.transcript, encoded...)
		output = append(output, encoded...)
	}
	if !c.sentVerify {
		if c.context != nil {
			if key, ok := c.context.NegoExKey(); ok {
				usage := uint32(keyusage.NEGOEX_ACCEPTOR_CHECKSUM)
				if c.initiator {
					usage = keyusage.NEGOEX_INITIATOR_CHECKSUM
				}
				checksum, err := MakeChecksum(key, usage, c.transcript)
				if err != nil {
					return nil, false, err
				}
				verify := &VerifyMessage{Header: MessageHeader{MessageType: MessageTypeVerify}, AuthScheme: c.selected.AuthScheme(), Checksum: checksum}
				setMessageHeader(verify, c.sequence, c.conversation)
				encoded, err := verify.MarshalBinary()
				if err != nil {
					return nil, false, err
				}
				c.sequence++
				c.transcript = append(c.transcript, encoded...)
				output = append(output, encoded...)
				c.sentVerify = true
			}
		}
		if c.mechanismDone && !c.sentVerify {
			return nil, false, ErrNoVerifyKey
		}
	}
	done := c.mechanismDone && c.sentVerify && c.peerVerified
	if c.mechanismDone && c.sentVerify && !c.peerVerified && len(output) == 0 {
		return nil, false, ErrMissingVerify
	}
	return output, done, nil
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
	messageType := uint32(MessageTypeInitiatorMetaData)
	if receivingAcceptorMetadata {
		messageType = MessageTypeAcceptorMetaData
	}
	retained := c.schemes[:0]
	for _, scheme := range c.schemes {
		provider, handlesMetadata := scheme.(MetadataScheme)
		accepted := true
		if handlesMetadata {
			for _, message := range messages {
				metadata, ok := message.(*ExchangeMessage)
				if !ok || metadata.Header.MessageType != messageType || metadata.AuthScheme != scheme.AuthScheme() {
					continue
				}
				if err := provider.ExchangeMetadata(metadata.Exchange, c.initiator); err != nil {
					accepted = false
					break
				}
			}
		}
		if accepted {
			retained = append(retained, scheme)
		}
	}
	c.schemes = retained
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
		if candidate, ok := message.(*ExchangeMessage); ok && candidate.Header.MessageType == messageType && candidate.AuthScheme == scheme {
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

func setMessageHeader(message Message, sequence uint32, conversation ConversationID) {
	header := MessageHeader{MessageType: message.messageHeader().MessageType, SequenceNum: sequence, ConversationID: conversation}
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
	return &Mechanism{schemes: uniqueSchemes(schemes)}
}

// OID returns the NEGOEX GSS mechanism OID.
func (m *Mechanism) OID() asn1.ObjectIdentifier { return gssapi.OIDNegoEx.OID() }

// InitSecContext advances the initiator conversation.
func (m *Mechanism) InitSecContext(target string, input []byte, _ ...gssapi.MechanismOption) ([]byte, gssapi.Context, bool, error) {
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
