package types

import (
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/flags"
	"github.com/stretchr/testify/assert"
)

func TestNewKrbFlags(t *testing.T) {
	value := NewKrbFlags()
	assert.Equal(t, 32, value.BitLength)
	assert.Equal(t, []byte{0, 0, 0, 0}, value.Bytes)
}

func TestKerberosFlags_SetFlag(t *testing.T) {
	t.Parallel()
	b := []byte{byte(64), byte(0), byte(0), byte(16)}
	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	assert.Equal(t, b, f.Bytes, "Flag bytes not as expected")
}

func TestKerberosFlags_UnsetFlag(t *testing.T) {
	t.Parallel()
	b := []byte{byte(64), byte(0), byte(0), byte(0)}
	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	UnsetFlag(&f, flags.RenewableOK)
	assert.Equal(t, b, f.Bytes, "Flag bytes not as expected")
}

func TestKerberosFlags_IsFlagSet(t *testing.T) {
	t.Parallel()
	var f asn1.BitString
	SetFlag(&f, flags.Forwardable)
	SetFlag(&f, flags.RenewableOK)
	UnsetFlag(&f, flags.Proxiable)
	assert.True(t, IsFlagSet(&f, flags.Forwardable))
	assert.True(t, IsFlagSet(&f, flags.RenewableOK))
	assert.False(t, IsFlagSet(&f, flags.Proxiable))
}

func TestKerberosFlagsBulkAndBounds(t *testing.T) {
	var value asn1.BitString
	SetFlags(&value, []int{0, 7, 8, 31, -1, 32})
	assert.Equal(t, []byte{0x81, 0x80, 0x00, 0x01}, value.Bytes)
	for _, flag := range []int{0, 7, 8, 31} {
		assert.True(t, IsFlagSet(&value, flag), "flag %d", flag)
	}
	assert.False(t, IsFlagSet(&value, -1))
	assert.False(t, IsFlagSet(&value, 32))
	assert.False(t, IsFlagSet(nil, 0))

	UnsetFlags(&value, []int{0, 8, -1, 32})
	assert.Equal(t, []byte{0x01, 0x00, 0x00, 0x01}, value.Bytes)
	SetFlag(nil, 0)
	UnsetFlag(nil, 0)
}
