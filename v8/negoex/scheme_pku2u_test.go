package negoex

import (
	"errors"
	"testing"
)

func TestPKU2USchemePreservesMechanismErrors(t *testing.T) {
	t.Parallel()

	cause := errors.New("injected PKU2U failure")
	mechanism := &testPKU2UMechanism{
		testSchemeMechanism: newTestScheme(PKU2UAuthScheme),
		metadata:            []byte("metadata"),
		metadataErr:         cause,
	}
	mechanism.initErr = cause
	mechanism.acceptErr = cause
	mechanism.acceptErrorToken = []byte("error token")
	scheme := NewPKU2UScheme(mechanism)

	t.Run("initiate", func(t *testing.T) {
		output, context, done, err := scheme.InitSecContext("host/server", []byte("challenge"))
		requireWrappedError(t, err, cause, "initialize PKU2U context:")
		if string(output) != "request-2" || context != mechanism.context || !done {
			t.Fatal("adapter discarded initiator results on error")
		}
	})
	t.Run("accept", func(t *testing.T) {
		output, _, _, err := scheme.AcceptSecContext([]byte("request-1"))
		requireWrappedError(t, err, cause, "accept PKU2U context:")
		if string(output) != string(mechanism.acceptErrorToken) {
			t.Fatal("adapter discarded acceptor error token")
		}
	})
	t.Run("query metadata", func(t *testing.T) {
		metadata, err := scheme.QueryMetadata("host/server", true)
		requireWrappedError(t, err, cause, "query PKU2U metadata:")
		if string(metadata) != string(mechanism.metadata) {
			t.Fatal("adapter discarded metadata on error")
		}
	})
	t.Run("exchange metadata", func(t *testing.T) {
		err := scheme.ExchangeMetadata(mechanism.metadata, false)
		requireWrappedError(t, err, cause, "exchange PKU2U metadata:")
	})
}
