package crypto_test

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/crypto/etype"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc3961"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc3962"
	"github.com/otuschhoff/gokrb5/v8/crypto/rfc8009"
)

type blockFailureProfile struct {
	etype.EType
	cause    error
	failCall int
	calls    int
}

func (p *blockFailureProfile) EncryptData(key, data []byte) ([]byte, []byte, error) {
	p.calls++
	if p.calls == p.failCall {
		return nil, nil, p.cause
	}
	return p.EType.EncryptData(key, data)
}

func TestRFC3961DeriveRandomErrorStages(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name        string
		context     string
		failCall    int
		wantPartial bool
	}{
		{name: "initial block", context: "encrypt initial derivation block:", failCall: 1, wantPartial: true},
		{name: "feedback block", context: "encrypt feedback derivation block:", failCall: 2, wantPartial: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cause := errors.New("injected encryption failure")
			profile := &blockFailureProfile{
				EType: crypto.Aes256CtsHmacSha96{}, cause: cause, failCall: tt.failCall, calls: 0,
			}
			key := make([]byte, profile.GetKeyByteSize())
			result, err := rfc3961.DeriveRandom(key, []byte("kerberos"), profile)
			checkRFCError(t, err, cause, tt.context)
			if profile.calls != tt.failCall {
				t.Fatalf("encryption calls = %d, want %d", profile.calls, tt.failCall)
			}
			if tt.wantPartial {
				if !bytes.Equal(result, make([]byte, profile.GetKeySeedBitLength()/8)) {
					t.Fatal("initial failure did not retain the zeroed result buffer")
				}
			} else if result != nil {
				t.Fatal("feedback failure returned a partial seed")
			}
		})
	}
}

type keyFailureProfile struct {
	etype.EType
	cause error
}

func (p keyFailureProfile) DeriveKey([]byte, []byte) ([]byte, error) { return []byte{}, p.cause }

type seedFailureProfile struct {
	etype.EType
	cause error
}

func (p seedFailureProfile) DeriveRandom([]byte, []byte) ([]byte, error) { return nil, p.cause }

func TestRFCKeyDerivationPreservesCause(t *testing.T) {
	t.Parallel()

	cause := errors.New("injected key derivation failure")
	sha1 := keyFailureProfile{EType: crypto.Aes128CtsHmacSha96{}, cause: cause}
	sha2 := keyFailureProfile{EType: crypto.Aes128CtsHmacSha256128{}, cause: cause}
	des3 := keyFailureProfile{EType: crypto.Des3CbcSha1Kd{}, cause: cause}

	t.Run("derive key seed", func(t *testing.T) {
		profile := seedFailureProfile{EType: sha1.EType, cause: cause}
		result, err := rfc3961.DeriveKey(nil, []byte("kerberos"), profile)
		checkRFCError(t, err, cause, "derive key seed:")
		if result != nil {
			t.Fatal("seed failure returned a key")
		}
	})
	t.Run("des3 string-to-key", func(t *testing.T) {
		result, err := rfc3961.DES3StringToKey("test-password", "salt", des3)
		checkRFCError(t, err, cause, "derive des3 protocol key:")
		checkEmptyKeyResult(t, result)
	})
	t.Run("rfc3961 prf", func(t *testing.T) {
		result, err := rfc3961.PseudoRandom(nil, []byte("input"), sha1)
		checkRFCError(t, err, cause, "derive prf key:")
		checkEmptyKeyResult(t, result)
	})
	t.Run("rfc3962 string-to-key", func(t *testing.T) {
		result, err := rfc3962.StringToKeyIter("test-password", "salt", 1, sha1)
		checkRFCError(t, err, cause, "derive protocol key:")
		checkEmptyKeyResult(t, result)
	})
	t.Run("rfc8009 string-to-key", func(t *testing.T) {
		result, err := rfc8009.StringToKeyIter("test-password", "salt", 1, sha2)
		checkRFCError(t, err, cause, "derive protocol key:")
		checkEmptyKeyResult(t, result)
	})
	t.Run("rfc8009 integrity", func(t *testing.T) {
		result, err := rfc8009.GetIntegityHash(nil, nil, nil, 1, sha2)
		checkRFCError(t, err, cause, "compute ciphertext integrity hash:")
		if result != nil {
			t.Fatal("integrity failure returned a hash")
		}
	})
}

func TestRFC3961PseudoRandomRetainsBlockFailure(t *testing.T) {
	t.Parallel()

	cause := errors.New("injected prf block failure")
	profile := &blockFailureProfile{
		EType: crypto.Aes128CtsHmacSha96{}, cause: cause, failCall: 1, calls: 0,
	}
	result, err := rfc3961.PseudoRandom(make([]byte, profile.GetKeyByteSize()), []byte("input"), profile)
	checkRFCError(t, err, cause, "encrypt prf block:")
	checkEmptyKeyResult(t, result)
}

func TestRFCAESCTSDecryptPreservesCause(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		profile etype.EType
		decrypt func([]byte, []byte, etype.EType) ([]byte, error)
	}{
		{name: "rfc3962", profile: crypto.Aes128CtsHmacSha96{}, decrypt: rfc3962.DecryptData},
		{name: "rfc8009", profile: crypto.Aes128CtsHmacSha256128{}, decrypt: rfc8009.DecryptData},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result, err := tt.decrypt(make([]byte, tt.profile.GetKeyByteSize()), nil, tt.profile)
			if result == nil || len(result) != 0 {
				t.Fatal("AES-CTS failure did not retain the empty, non-nil plaintext")
			}
			cause := errors.Unwrap(err)
			if err == nil || cause == nil || !strings.HasPrefix(err.Error(), "decrypt aes-cts data:") ||
				!strings.Contains(cause.Error(), "not large enough") {
				t.Fatalf("AES-CTS error = %v, want the cipher's short-input cause", err)
			}
		})
	}
}

type decryptFailureProfile struct {
	etype.EType
	cause error
}

func (p decryptFailureProfile) DecryptData([]byte, []byte) ([]byte, error) {
	return []byte("discarded partial plaintext"), p.cause
}

func TestRFCMessageDecryptRetainsCause(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		profile etype.EType
		decrypt func([]byte, []byte, uint32, etype.EType) ([]byte, error)
	}{
		{name: "rfc3962", profile: crypto.Aes128CtsHmacSha96{}, decrypt: rfc3962.DecryptMessage},
		{name: "rfc8009", profile: crypto.Aes128CtsHmacSha256128{}, decrypt: rfc8009.DecryptMessage},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			const usage = 1
			key := make([]byte, tt.profile.GetKeyByteSize())
			_, ciphertext, err := tt.profile.EncryptMessage(key, []byte("test plaintext"), usage)
			if err != nil {
				t.Fatal(err)
			}
			cause := errors.New("injected decrypt failure")
			profile := decryptFailureProfile{EType: tt.profile, cause: cause}
			plaintext, err := tt.decrypt(key, ciphertext, usage, profile)
			checkRFCError(t, err, cause, "decrypt message data:")
			if plaintext != nil {
				t.Fatal("decryption failure returned plaintext")
			}
		})
	}
}

func TestRFCS2KRetainsHexError(t *testing.T) {
	t.Parallel()

	_, aesSHA1Err := rfc3962.S2KparamsToItertions("0000000z")
	_, aesSHA2Err := rfc8009.S2KparamsToItertions("0000000z")
	for _, err := range []error{aesSHA1Err, aesSHA2Err} {
		if _, ok := errors.AsType[hex.InvalidByteError](err); !ok {
			t.Errorf("parameter error = %v, want typed hex decode cause", err)
		}
	}
}

func checkRFCError(t *testing.T, err, cause error, context string) {
	t.Helper()
	if err == nil || !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), context) {
		t.Fatalf("error = %v, want context %q with original cause %v", err, context, cause)
	}
}

func checkEmptyKeyResult(t *testing.T, result []byte) {
	t.Helper()
	if result == nil || len(result) != 0 {
		t.Fatal("error did not retain the empty, non-nil key result")
	}
}
