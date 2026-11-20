// Package gssapi implements the Generic Security Services Application Program
// Interface used for SPNEGO Kerberos authentication.
package gssapi

import (
	"context"
	"math/bits"

	"github.com/jcmturner/gofork/encoding/asn1"
)

// GSS-API OID names
const (
	// GSS-API OID names
	OIDKRB5         OIDName = "KRB5"         // MechType OID for Kerberos 5
	OIDMSLegacyKRB5 OIDName = "MSLegacyKRB5" // MechType OID for Kerberos 5
	OIDSPNEGO       OIDName = "SPNEGO"
	// OIDGSSIAKerb lets a client reach the target KDC via the server.
	OIDGSSIAKerb OIDName = "GSSIAKerb"
	OIDNegoEx    OIDName = "NEGOEX"
	OIDPKU2U     OIDName = "PKU2U"
)

// GSS-API status values
const (
	StatusBadBindings = 1 << iota
	StatusBadMech
	StatusBadName
	StatusBadNameType
	StatusBadStatus
	StatusBadSig
	StatusBadMIC
	StatusContextExpired
	StatusCredentialsExpired
	StatusDefectiveCredential
	StatusDefectiveToken
	StatusFailure
	StatusNoContext
	StatusNoCred
	StatusBadQOP
	StatusUnauthorized
	StatusUnavailable
	StatusDuplicateElement
	StatusNameNotMN
	StatusComplete
	StatusContinueNeeded
	StatusDuplicateToken
	StatusOldToken
	StatusUnseqToken
	StatusGapToken
)

// ContextToken is an interface for a GSS-API context token.
type ContextToken interface {
	Marshal() ([]byte, error)
	Unmarshal(b []byte) error
	Verify() (bool, Status)
	Context() context.Context
}

/*
CREDENTIAL MANAGEMENT

GSS_Acquire_cred             acquire credentials for use
GSS_Release_cred             release credentials after use
GSS_Inquire_cred             display information about credentials
GSS_Add_cred                 construct credentials incrementally
GSS_Inquire_cred_by_mech     display per-mechanism credential information

CONTEXT-LEVEL CALLS

GSS_Init_sec_context         initiate outbound security context
GSS_Accept_sec_context       accept inbound security context
GSS_Delete_sec_context       flush context when no longer needed
GSS_Process_context_token    process received control token on context
GSS_Context_time             indicate validity time remaining on context
GSS_Inquire_context          display information about context
GSS_Wrap_size_limit          determine GSS_Wrap token size limit
GSS_Export_sec_context       transfer context to other process
GSS_Import_sec_context       import transferred context

PER-MESSAGE CALLS

GSS_GetMIC                   apply integrity check, receive as token separate from message
GSS_VerifyMIC                validate integrity check token along with message
GSS_Wrap                     sign, optionally encrypt, encapsulate
GSS_Unwrap                   decapsulate, decrypt if needed, validate integrity check

SUPPORT CALLS

GSS_Display_status           translate status codes to printable form
GSS_Indicate_mechs           indicate mech_types supported on local system
GSS_Compare_name             compare two names for equality
GSS_Display_name             translate name to printable form
GSS_Import_name              convert printable name to normalized form
GSS_Release_name             free storage of normalized-form name
GSS_Release_buffer           free storage of general GSS-allocated object
GSS_Release_OID_set          free storage of OID set object
GSS_Create_empty_OID_set     create empty OID set
GSS_Add_OID_set_member       add member to OID set
GSS_Test_OID_set_member      test if OID is member of OID set
GSS_Inquire_names_for_mech   indicate name types supported by mechanism
GSS_Inquire_mechs_for_name   indicates mechanisms supporting name type
GSS_Canonicalize_name        translate name to per-mechanism form
GSS_Export_name              externalize per-mechanism name
GSS_Duplicate_name           duplicate name object
*/

// Mechanism is the GSS-API interface for authentication mechanisms.
type Mechanism interface {
	TokenContextMechanism
	TokenMessageProtector
}

// TokenContextMechanism acquires credentials and establishes contexts using
// the original token-oriented API.
type TokenContextMechanism interface {
	OID() asn1.ObjectIdentifier
	AcquireCred() error
	InitSecContext() (ContextToken, error)
	AcceptSecContext(ct ContextToken) (bool, context.Context, Status)
}

// TokenMessageProtector provides integrity and optional confidentiality using
// the original token-oriented API.
type TokenMessageProtector interface {
	MIC() MICToken
	VerifyMIC(mt MICToken) (bool, error)
	Wrap(msg []byte) WrapToken
	Unwrap(wt WrapToken) []byte
}

// OIDName is the type for defined GSS-API OIDs.
type OIDName string

// OID returns the OID for the provided OID name.
func (o OIDName) OID() asn1.ObjectIdentifier {
	switch o {
	case OIDSPNEGO:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	case OIDKRB5:
		return asn1.ObjectIdentifier{1, 2, 840, 113554, 1, 2, 2}
	case OIDMSLegacyKRB5:
		return asn1.ObjectIdentifier{1, 2, 840, 48018, 1, 2, 2}
	case OIDGSSIAKerb:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 5}
	case OIDNegoEx:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 30}
	case OIDPKU2U:
		return asn1.ObjectIdentifier{1, 3, 6, 1, 5, 2, 7}
	}
	return asn1.ObjectIdentifier{}
}

// Status is the GSS-API status and implements the error interface.
type Status struct {
	Code    int
	Message string
}

// Error returns the Status description.
func (s Status) Error() string {
	str := statusDescription(s.Code)
	if s.Message != "" {
		return str + ": " + s.Message
	}
	return str
}

func statusDescription(code int) string {
	// Descriptions follow the bit positions of the Status constants.
	descriptions := [...]string{
		"channel binding mismatch",                     // StatusBadBindings
		"unsupported mechanism requested",              // StatusBadMech
		"invalid name provided",                        // StatusBadName
		"name of unsupported type provided",            // StatusBadNameType
		"invalid input status selector",                // StatusBadStatus
		"token had invalid integrity check",            // StatusBadSig
		"preferred alias for GSS_S_BAD_SIG",            // StatusBadMIC
		"specified security context expired",           // StatusContextExpired
		"expired credentials detected",                 // StatusCredentialsExpired
		"defective credential detected",                // StatusDefectiveCredential
		"defective token detected",                     // StatusDefectiveToken
		"failure, unspecified at GSS-API level",        // StatusFailure
		"no valid security context specified",          // StatusNoContext
		"no valid credentials provided",                // StatusNoCred
		"unsupported QOP valu",                         // StatusBadQOP
		"operation unauthorized",                       // StatusUnauthorized
		"operation unavailable",                        // StatusUnavailable
		"duplicate credential element requested",       // StatusDuplicateElement
		"name contains multi-mechanism elements",       // StatusNameNotMN
		"normal completion",                            // StatusComplete
		"continuation call to routine required",        // StatusContinueNeeded
		"duplicate per-message token detected",         // StatusDuplicateToken
		"timed-out per-message token detected",         // StatusOldToken
		"reordered (early) per-message token detected", // StatusUnseqToken
		"skipped predecessor token(s) detected",        // StatusGapToken
	}
	if code <= 0 || code > StatusGapToken || code&(code-1) != 0 {
		return "unknown GSS-API error status"
	}
	return descriptions[bits.TrailingZeros(uint(code))]
}
