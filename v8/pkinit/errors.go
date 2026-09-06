package pkinit

import (
	"errors"
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
)

var (
	ErrClientNotTrusted               = errors.New("PKINIT client certificate is not trusted")
	ErrKDCNotTrusted                  = errors.New("PKINIT KDC certificate is not trusted")
	ErrInvalidSignature               = errors.New("PKINIT signature is invalid")
	ErrDHParametersNotAccepted        = errors.New("PKINIT DH parameters are not accepted")
	ErrCertificateMismatch            = errors.New("PKINIT certificate mismatch")
	ErrCannotVerifyCertificate        = errors.New("PKINIT certificate cannot be verified")
	ErrInvalidCertificate             = errors.New("PKINIT certificate is invalid")
	ErrRevokedCertificate             = errors.New("PKINIT certificate is revoked")
	ErrRevocationStatusUnknown        = errors.New("PKINIT certificate revocation status is unknown")
	ErrRevocationStatusUnavailable    = errors.New("PKINIT certificate revocation status is unavailable")
	ErrClientNameMismatch             = errors.New("PKINIT client name mismatch")
	ErrKDCNameMismatch                = errors.New("PKINIT KDC name mismatch")
	ErrInconsistentKeyPurpose         = errors.New("PKINIT certificate key purpose is inconsistent")
	ErrCertificateDigestRejected      = errors.New("PKINIT certificate digest is not accepted")
	ErrPAChecksumRequired             = errors.New("PKINIT paChecksum is required")
	ErrCMSDigestRejected              = errors.New("PKINIT CMS digest is not accepted")
	ErrPublicKeyEncryptionUnsupported = errors.New("PKINIT public-key encryption is not supported")
	ErrNoAcceptableKDF                = errors.New("PKINIT KDF is not accepted")
)

// KRBError preserves a PKINIT KRB-ERROR and its decoded typed data.
type KRBError struct {
	Kind                error
	Response            messages.KRBError
	TrustedCertifiers   TDTrustedCertifiers
	InvalidCertificates TDInvalidCertificates
	DHParameters        TDDHParameters
	CMSDigestAlgorithms TDCMSDigestAlgorithms
	CertificateDigests  *TDCertDigestAlgorithms
	NTStatus            ntstatus.Code
	HasNTStatus         bool
}

func (err *KRBError) Error() string { return fmt.Sprintf("%v: %v", err.Kind, err.Response) }
func (err *KRBError) Unwrap() error { return err.Kind }

// DecodeKRBError maps a PKINIT KRB-ERROR and decodes any RFC typed data.
func DecodeKRBError(response messages.KRBError) (*KRBError, bool) {
	kind := pkinitErrorKind(response.ErrorCode)
	if kind == nil {
		return nil, false
	}
	result := &KRBError{Kind: kind, Response: response}
	result.NTStatus, result.HasNTStatus = response.NTStatus()
	if len(response.EData) == 0 {
		return result, true
	}
	var typedData types.TypedDataSequence
	if err := strictUnmarshal(response.EData, &typedData); err != nil {
		return result, true
	}
	for _, item := range typedData {
		switch item.DataType {
		case patype.TD_TRUSTED_CERTIFIERS:
			_ = strictUnmarshal(item.DataValue, &result.TrustedCertifiers)
		case patype.TD_INVALID_CERTIFICATES:
			_ = strictUnmarshal(item.DataValue, &result.InvalidCertificates)
		case patype.TD_DH_PARAMETERS:
			_ = strictUnmarshal(item.DataValue, &result.DHParameters)
		case patype.TD_CMS_DIGEST_ALGORITHMS:
			_ = strictUnmarshal(item.DataValue, &result.CMSDigestAlgorithms)
		case patype.TD_CERT_DIGEST_ALGORITHMS:
			var algorithms TDCertDigestAlgorithms
			if strictUnmarshal(item.DataValue, &algorithms) == nil {
				result.CertificateDigests = &algorithms
			}
		}
	}
	return result, true
}

func pkinitErrorKind(code int32) error {
	switch code {
	case errorcode.KDC_ERROR_CLIENT_NOT_TRUSTED:
		return ErrClientNotTrusted
	case errorcode.KDC_ERROR_KDC_NOT_TRUSTED:
		return ErrKDCNotTrusted
	case errorcode.KDC_ERROR_INVALID_SIG:
		return ErrInvalidSignature
	case errorcode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED:
		return ErrDHParametersNotAccepted
	case errorcode.KDC_ERR_CERTIFICATE_MISMATCH:
		return ErrCertificateMismatch
	case errorcode.KDC_ERR_CANT_VERIFY_CERTIFICATE:
		return ErrCannotVerifyCertificate
	case errorcode.KDC_ERR_INVALID_CERTIFICATE:
		return ErrInvalidCertificate
	case errorcode.KDC_ERR_REVOKED_CERTIFICATE:
		return ErrRevokedCertificate
	case errorcode.KDC_ERR_REVOCATION_STATUS_UNKNOWN:
		return ErrRevocationStatusUnknown
	case errorcode.KDC_ERR_REVOCATION_STATUS_UNAVAILABLE:
		return ErrRevocationStatusUnavailable
	case errorcode.KDC_ERR_CLIENT_NAME_MISMATCH:
		return ErrClientNameMismatch
	case errorcode.KDC_ERR_KDC_NAME_MISMATCH:
		return ErrKDCNameMismatch
	case errorcode.KDC_ERR_INCONSISTENT_KEY_PURPOSE:
		return ErrInconsistentKeyPurpose
	case errorcode.KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED:
		return ErrCertificateDigestRejected
	case errorcode.KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED:
		return ErrPAChecksumRequired
	case errorcode.KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED:
		return ErrCMSDigestRejected
	case errorcode.KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED:
		return ErrPublicKeyEncryptionUnsupported
	case errorcode.KDC_ERR_NO_ACCEPTABLE_KDF:
		return ErrNoAcceptableKDF
	default:
		return nil
	}
}
