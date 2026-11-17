package common_test

import (
	"errors"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/common"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/iana/etypeID"
)

type failedDerivation struct {
	etype.EType
	cause error
}

func (f failedDerivation) DeriveKey([]byte, []byte) ([]byte, error) { return nil, f.cause }

func TestGetHashRetainsDerivationError(t *testing.T) {
	base, err := crypto.GetEtype(etypeID.AES128_CTS_HMAC_SHA1_96)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("injected key derivation failure")
	_, err = common.GetHash(nil, nil, nil, failedDerivation{EType: base, cause: cause})
	if !errors.Is(err, cause) {
		t.Fatalf("GetHash error = %v", err)
	}
}
