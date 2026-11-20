package gssapi

import (
	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/types"
)

// Context is an established GSS security context with per-message protection
// and access to the keys used by NEGOEX.
type Context interface {
	MessageProtector
	NegoExKeyProvider
}

// MessageProtector signs and optionally encrypts messages in an established context.
type MessageProtector interface {
	Wrap(message []byte, confidential bool) ([]byte, error)
	Unwrap(token []byte) (message []byte, confidential bool, err error)
	GetMIC(message []byte) ([]byte, error)
	VerifyMIC(message, token []byte) error
}

// NegoExKeyProvider supplies keys for local and peer NEGOEX VERIFY messages.
type NegoExKeyProvider interface {
	// NegoExKey protects locally generated NEGOEX VERIFY messages.
	NegoExKey() (types.EncryptionKey, bool)
	// NegoExVerifyKey verifies peer NEGOEX VERIFY messages.
	NegoExVerifyKey() (types.EncryptionKey, bool)
}

// MechanismOption is an implementation-defined context establishment option.
type MechanismOption any

// ContextMechanism is the step-oriented GSS mechanism contract used by
// negotiation mechanisms. It coexists with Mechanism for source compatibility
// with the original token-oriented API. Implementations may retain context
// establishment state, so calls for each direction must be serialized and a
// new instance used for each subsequent context.
type ContextMechanism interface {
	OID() asn1.ObjectIdentifier
	InitSecContext(
		target string, input []byte, options ...MechanismOption,
	) (output []byte, context Context, done bool, err error)
	AcceptSecContext(input []byte, options ...MechanismOption) (output []byte, context Context, done bool, err error)
}
