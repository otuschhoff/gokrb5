package pkinit

import (
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func TestDecodeKRBErrorWithDHParameters(t *testing.T) {
	var emptyParameters asn1.RawValue
	parameters := TDDHParameters{{Algorithm: OIDDHPublicNumber, Parameters: emptyParameters}}
	parameterDER, err := asn1.Marshal(parameters)
	require.NoError(t, err)
	typedDER, err := asn1.Marshal(types.TypedDataSequence{{DataType: patype.TD_DH_PARAMETERS, DataValue: parameterDER}})
	require.NoError(t, err)
	var response messages.KRBError
	response.ErrorCode = errorcode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED
	response.EData = typedDER
	decoded, ok := DecodeKRBError(response)
	require.True(t, ok)
	require.ErrorIs(t, decoded, ErrDHParametersNotAccepted)
	require.Equal(t, response, decoded.Response)
	require.Equal(t, parameters, decoded.DHParameters)
}

func TestDecodeKRBErrorIgnoresNonPKINITCode(t *testing.T) {
	var response messages.KRBError
	response.ErrorCode = errorcode.KDC_ERR_PREAUTH_REQUIRED
	_, ok := DecodeKRBError(response)
	require.False(t, ok)
}

func TestAllPKINITErrorKinds(t *testing.T) {
	tests := map[int32]error{
		errorcode.KDC_ERROR_CLIENT_NOT_TRUSTED:                ErrClientNotTrusted,
		errorcode.KDC_ERROR_KDC_NOT_TRUSTED:                   ErrKDCNotTrusted,
		errorcode.KDC_ERROR_INVALID_SIG:                       ErrInvalidSignature,
		errorcode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED:      ErrDHParametersNotAccepted,
		errorcode.KDC_ERR_CERTIFICATE_MISMATCH:                ErrCertificateMismatch,
		errorcode.KDC_ERR_CANT_VERIFY_CERTIFICATE:             ErrCannotVerifyCertificate,
		errorcode.KDC_ERR_INVALID_CERTIFICATE:                 ErrInvalidCertificate,
		errorcode.KDC_ERR_REVOKED_CERTIFICATE:                 ErrRevokedCertificate,
		errorcode.KDC_ERR_REVOCATION_STATUS_UNKNOWN:           ErrRevocationStatusUnknown,
		errorcode.KDC_ERR_REVOCATION_STATUS_UNAVAILABLE:       ErrRevocationStatusUnavailable,
		errorcode.KDC_ERR_CLIENT_NAME_MISMATCH:                ErrClientNameMismatch,
		errorcode.KDC_ERR_KDC_NAME_MISMATCH:                   ErrKDCNameMismatch,
		errorcode.KDC_ERR_INCONSISTENT_KEY_PURPOSE:            ErrInconsistentKeyPurpose,
		errorcode.KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED:         ErrCertificateDigestRejected,
		errorcode.KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED:        ErrPAChecksumRequired,
		errorcode.KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED:  ErrCMSDigestRejected,
		errorcode.KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED: ErrPublicKeyEncryptionUnsupported,
		errorcode.KDC_ERR_NO_ACCEPTABLE_KDF:                   ErrNoAcceptableKDF,
	}
	for code, want := range tests {
		var response messages.KRBError
		response.ErrorCode = code
		response.EData = []byte("malformed")
		decoded, ok := DecodeKRBError(response)
		require.True(t, ok)
		require.ErrorIs(t, decoded, want)
		require.Contains(t, decoded.Error(), want.Error())
	}
}
