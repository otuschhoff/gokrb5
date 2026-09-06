// Package krberror provides error type and functions for gokrb5.
package krberror

import (
	"errors"
	"fmt"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
)

// Error type descriptions.
const (
	separator       = " < "
	EncodingError   = "Encoding_Error"
	NetworkingError = "Networking_Error"
	DecryptingError = "Decrypting_Error"
	EncryptingError = "Encrypting_Error"
	ChksumError     = "Checksum_Error"
	KRBMsgError     = "KRBMessage_Handling_Error"
	ConfigError     = "Configuration_Error"
	KDCError        = "KDC_Error"
)

var (
	// ErrDelegationNotPermitted indicates that S4U2proxy policy rejected delegation.
	ErrDelegationNotPermitted = errors.New("delegation not permitted")
	// ErrProtocolTransitionNotPermitted indicates that S4U2self policy rejected protocol transition.
	ErrProtocolTransitionNotPermitted = errors.New("protocol transition not permitted")
)

// PolicyError classifies an S4U policy failure while retaining the KDC error.
type PolicyError struct {
	Kind  error
	Cause error
}

func (e PolicyError) Error() string {
	return fmt.Sprintf("%s: %v", e.Kind, e.Cause)
}

// Unwrap returns the underlying KDC error.
func (e PolicyError) Unwrap() error { return e.Cause }

// Is matches the policy classification or any wrapped error.
func (e PolicyError) Is(target error) bool {
	return target == e.Kind || errors.Is(e.Cause, target)
}

// NTStatus returns an extended status carried by the KDC error.
func (e PolicyError) NTStatus() (ntstatus.Code, bool) {
	var provider interface {
		NTStatus() (ntstatus.Code, bool)
	}
	if errors.As(e.Cause, &provider) {
		return provider.NTStatus()
	}
	return 0, false
}

// NewPolicyError classifies an S4U policy failure.
func NewPolicyError(kind, cause error) error {
	return PolicyError{Kind: kind, Cause: cause}
}

// Krberror is an error type for gokrb5
type Krberror struct {
	RootCause string
	EText     []string
	cause     error
}

// Error function to implement the error interface.
func (e Krberror) Error() string {
	return fmt.Sprintf("[Root cause: %s] ", e.RootCause) + strings.Join(e.EText, separator)
}

// Unwrap returns the error which caused this Kerberos error.
func (e Krberror) Unwrap() error {
	return e.cause
}

// NTStatus returns an MS-KILE extended status exposed by the wrapped error.
func (e Krberror) NTStatus() (ntstatus.Code, bool) {
	var provider interface {
		NTStatus() (ntstatus.Code, bool)
	}
	if e.cause != nil && errors.As(e.cause, &provider) {
		return provider.NTStatus()
	}
	return 0, false
}

// Add another error statement to the error.
func (e *Krberror) Add(et string, s string) {
	e.EText = append([]string{fmt.Sprintf("%s: %s", et, s)}, e.EText...)
}

// New creates a new instance of Krberror.
func New(et, s string) Krberror {
	return Krberror{
		RootCause: et,
		EText:     []string{s},
	}
}

// Errorf appends to or creates a new Krberror.
func Errorf(err error, et, format string, a ...interface{}) Krberror {
	if e, ok := err.(Krberror); ok {
		e.Add(et, fmt.Sprintf(format, a...))
		return e
	}
	e := NewErrorf(et, format+": %s", append(a, err)...)
	e.cause = err
	return e
}

// NewErrorf creates a new Krberror from a formatted string.
func NewErrorf(et, format string, a ...interface{}) Krberror {
	var s string
	if len(a) > 0 {
		s = fmt.Sprintf("%s: %s", et, fmt.Sprintf(format, a...))
	} else {
		s = fmt.Sprintf("%s: %s", et, format)
	}
	return Krberror{
		RootCause: et,
		EText:     []string{s},
	}
}
