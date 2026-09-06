package types

import (
	"encoding/hex"
	"net"
	"testing"

	"github.com/jcmturner/gofork/encoding/asn1"
	"github.com/otuschhoff/gokrb5/v8/iana/addrtype"
	"github.com/stretchr/testify/assert"
)

func TestGetHostAddress(t *testing.T) {
	tests := []struct {
		str    string
		ipType int32
		hex    string
	}{
		{"192.168.1.100", addrtype.IPv4, "c0a80164"},
		{"127.0.0.1", addrtype.IPv4, "7f000001"},
		{"[fe80::1cf3:b43b:df29:d43e]", addrtype.IPv6, "fe800000000000001cf3b43bdf29d43e"},
	}
	for _, test := range tests {
		h, err := GetHostAddress(test.str + ":1234")
		if err != nil {
			t.Errorf("error getting host for %s: %v", test.str, err)
		}
		assert.Equal(t, test.ipType, h.AddrType, "wrong address type for %s", test.str)
		assert.Equal(t, test.hex, hex.EncodeToString(h.Address), "wrong address bytes for %s", test.str)
	}
}

func TestGetHostAddressRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"missing-port", "not-an-ip:88"} {
		if _, err := GetHostAddress(input); err == nil {
			t.Fatalf("GetHostAddress(%q) succeeded", input)
		}
	}
}

func TestHostAddressGetAddress(t *testing.T) {
	encoded, err := asn1.Marshal([]byte("host.example.org"))
	if err != nil {
		t.Fatal(err)
	}
	host := HostAddress{Address: encoded}
	got, err := host.GetAddress()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "host.example.org", got)
	host.Address = []byte{0x04, 0x02, 0x01}
	_, err = host.GetAddress()
	assert.Error(t, err)
}

func TestHostAddressesFromNetIPs(t *testing.T) {
	ipv4 := net.ParseIP("192.0.2.1")
	ipv6 := net.ParseIP("2001:db8::1")
	addresses := HostAddressesFromNetIPs([]net.IP{ipv4, ipv6, nil})
	if assert.Len(t, addresses, 3) {
		assert.Equal(t, addrtype.IPv4, addresses[0].AddrType)
		assert.Equal(t, net.IPv4(192, 0, 2, 1).To4(), net.IP(addresses[0].Address))
		assert.Equal(t, addrtype.IPv6, addresses[1].AddrType)
		assert.Equal(t, ipv6.To16(), net.IP(addresses[1].Address))
		assert.Equal(t, HostAddress{}, addresses[2])
	}
}

func TestHostAddressComparisons(t *testing.T) {
	first := HostAddressFromNetIP(net.ParseIP("192.0.2.1"))
	second := HostAddressFromNetIP(net.ParseIP("192.0.2.2"))
	firstCopy := HostAddress{AddrType: first.AddrType, Address: append([]byte(nil), first.Address...)}

	assert.True(t, first.Equal(firstCopy))
	assert.False(t, first.Equal(second))
	assert.True(t, HostAddressesContains([]HostAddress{first, second}, firstCopy))
	assert.False(t, HostAddressesContains([]HostAddress{second}, HostAddressFromNetIP(net.ParseIP("2001:db8::1"))))
	assert.True(t, HostAddressesEqual([]HostAddress{first, second}, []HostAddress{second, firstCopy}))
	assert.False(t, HostAddressesEqual([]HostAddress{first, second}, []HostAddress{firstCopy, firstCopy}))
	assert.False(t, HostAddressesEqual([]HostAddress{first}, []HostAddress{first, second}))

	addresses := HostAddresses{first, second}
	assert.True(t, addresses.Contains(firstCopy))
	assert.False(t, addresses.Contains(HostAddressFromNetIP(net.ParseIP("2001:db8::1"))))
	assert.True(t, addresses.Equal([]HostAddress{second, firstCopy}))
	assert.False(t, addresses.Equal([]HostAddress{first}))
}

func TestLocalHostAddressesReturnsValidIPs(t *testing.T) {
	addresses, err := LocalHostAddresses()
	if err != nil {
		t.Fatal(err)
	}
	for _, address := range addresses {
		ip := net.IP(address.Address)
		if address.AddrType != addrtype.IPv4 && address.AddrType != addrtype.IPv6 {
			t.Fatalf("unexpected address type %d", address.AddrType)
		}
		if ip.IsLoopback() || ip.To16() == nil {
			t.Fatalf("invalid local address %v", ip)
		}
	}
}
