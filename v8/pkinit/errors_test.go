package pkinit

import (
	"errors"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/errorcode"
	"github.com/otuschhoff/gokrb5/v8/iana/patype"
	"github.com/otuschhoff/gokrb5/v8/messages"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/require"
)

func TestDecodeKRBErrorWithDHParameters(t *testing.T) {
	parameters := TDDHParameters{{Algorithm: OIDDHPublicNumber}}
	parameterDER, err := asn1.Marshal(parameters)
	require.NoError(t, err)
	typedDER, err := asn1.Marshal(types.TypedDataSequence{{DataType: patype.TD_DH_PARAMETERS, DataValue: parameterDER}})
	require.NoError(t, err)
	decoded, ok := DecodeKRBError(messages.KRBError{ErrorCode: errorcode.KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED, EData: typedDER})
	require.True(t, ok)
	require.True(t, errors.Is(decoded, ErrDHParametersNotAccepted))
	require.Equal(t, parameters, decoded.DHParameters)
}

func TestDecodeKRBErrorIgnoresNonPKINITCode(t *testing.T) {
	_, ok := DecodeKRBError(messages.KRBError{ErrorCode: errorcode.KDC_ERR_PREAUTH_REQUIRED})
	require.False(t, ok)
}
