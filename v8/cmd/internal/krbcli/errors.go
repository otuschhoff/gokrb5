package krbcli

import (
	"errors"
	"fmt"
	"strings"

	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/ntstatus"
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
		text := ""
		switch kdcErr.ErrorCode {
		case errorcode.KDC_ERR_C_PRINCIPAL_UNKNOWN:
			text = "Client not found in Kerberos database"
		case errorcode.KDC_ERR_S_PRINCIPAL_UNKNOWN:
			text = "Server not found in Kerberos database"
		case errorcode.KDC_ERR_KEY_EXPIRED:
			text = "Password has expired"
		case errorcode.KDC_ERR_PREAUTH_FAILED, errorcode.KRB_AP_ERR_BAD_INTEGRITY:
			text = "Password incorrect"
		case errorcode.KRB_AP_ERR_SKEW:
			text = "Clock skew too great"
		case errorcode.KDC_ERR_ETYPE_NOSUPP:
			text = "KDC has no support for encryption type"
		case errorcode.KDC_ERR_CLIENT_REVOKED:
			text = "Clients credentials have been revoked"
		}
		if text == "" && kdcErr.EText != "" {
			text = kdcErr.EText
		}
		if text != "" {
			return appendNTStatus(text, err)
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
	return appendNTStatus(text, err)
}

func appendNTStatus(text string, err error) string {
	var provider interface {
		NTStatus() (ntstatus.Code, bool)
	}
	if errors.As(err, &provider) {
		if status, ok := provider.NTStatus(); ok {
			return fmt.Sprintf("%s: %s (0x%08X)", text, status, uint32(status))
		}
	}
	return text
}
