package krbcli

import (
	"errors"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/messages"
)

// KDCError returns the KDC error embedded in err, if any.
func KDCError(err error) (messages.KRBError, bool) {
	var kdcErr messages.KRBError
	return kdcErr, errors.As(err, &kdcErr)
}

// ErrorText maps common library and KDC failures to MIT-compatible text.
func ErrorText(err error) string {
	if err == nil {
		return ""
	}
	if kdcErr, ok := KDCError(err); ok {
		switch kdcErr.ErrorCode {
		case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
			return "Client not found in Kerberos database"
		case errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN:
			return "Server not found in Kerberos database"
		case errorcode.KDC_ERR_KEY_EXPIRED:
			return "Password has expired"
		case errorcode.KDC_ERR_PREAUTH_FAILED, errorcode.KRB_AP_ERR_BAD_INTEGRITY:
			return "Password incorrect"
		case errorcode.KRB_AP_ERR_SKEW:
			return "Clock skew too great"
		case errorcode.KDC_ERR_ETYPE_NOSUPP:
			return "KDC has no support for encryption type"
		case errorcode.KDC_ERR_CLIENT_REVOKED:
			return "Clients credentials have been revoked"
		}
		if kdcErr.EText != "" {
			return kdcErr.EText
		}
	}
	text := err.Error()
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "failed sending") || strings.Contains(lower, "cannot find kdc") || strings.Contains(lower, "connection refused") || strings.Contains(lower, "i/o timeout"):
		return "Cannot contact any KDC for requested realm"
	case strings.Contains(lower, "incorrect password") || strings.Contains(lower, "integrity"):
		return "Password incorrect"
	}
	return text
}
