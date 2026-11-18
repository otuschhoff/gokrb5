package credentials

import (
	"encoding/binary"
	"encoding/hex"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
)

func mustCCacheUint32(t *testing.T, name string, value int64) uint32 {
	t.Helper()
	if value < 0 || value > math.MaxUint32 {
		t.Fatalf("%s %d exceeds uint32 range", name, value)
	}
	return uint32(value) // #nosec G115 -- value is explicitly bounded to the complete uint32 range above.
}

// TestCCacheUnmarshalFullTruncationSweep unmarshals every strict prefix of each
// fixture: a prefix may only parse successfully when it ends exactly on a
// credential boundary, and no prefix may panic.
func TestCCacheUnmarshalFullTruncationSweep(t *testing.T) {
	for name, encoded := range ccacheFixtures() {
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			full := new(CCache)
			require.NoError(t, full.Unmarshal(data))
			want := len(full.Credentials)
			for length := 0; length < len(data); length++ {
				cache := new(CCache)
				if err := cache.Unmarshal(data[:length]); err == nil {
					assert.LessOrEqual(t, len(cache.Credentials), want,
						"prefix length %d parsed more credentials than the full cache", length)
				}
			}
		})
	}
}

// TestCCacheUnmarshalByteFlipSweep flips every byte of each fixture in turn;
// mutated caches must never panic, and any accepted version 3 or 4 cache must
// marshal again.
func TestCCacheUnmarshalByteFlipSweep(t *testing.T) {
	for name, encoded := range ccacheFixtures() {
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			for offset := range data {
				mutated := make([]byte, len(data))
				copy(mutated, data)
				mutated[offset] ^= 0xFF
				cache := new(CCache)
				if err := cache.Unmarshal(mutated); err != nil {
					continue
				}
				if cache.Version == 3 || cache.Version == 4 {
					if _, err := cache.Marshal(); err != nil {
						t.Fatalf("accepted cache with flipped byte %d does not marshal: %v", offset, err)
					}
				}
			}
		})
	}
}

// TestCCacheUnmarshalHeaderErrors covers the version header rejection branches.
func TestCCacheUnmarshalHeaderErrors(t *testing.T) {
	t.Run("shorter than version header", func(t *testing.T) {
		err := new(CCache).Unmarshal([]byte{5})
		require.EqualError(t, err, "credential cache is shorter than the 2-byte version header: 1")
	})
	t.Run("bad first byte", func(t *testing.T) {
		err := new(CCache).Unmarshal([]byte{4, 4})
		require.EqualError(t, err, "Invalid credential cache data. First byte does not equal 5")
	})
	t.Run("version out of range", func(t *testing.T) {
		err := new(CCache).Unmarshal([]byte{5, 5})
		require.EqualError(t, err, "Invalid credential cache data. Keytab version is not within 1 to 4")
	})
}

// TestCCacheV4HeaderFieldRejections covers malformed version 4 header fields.
func TestCCacheV4HeaderFieldRejections(t *testing.T) {
	v3, err := hex.DecodeString(testdata.CCACHE_V3)
	require.NoError(t, err)
	withHeader := func(header []byte) []byte {
		data := []byte{5, 4}
		data = append(data, header...)
		return append(data, v3[2:]...)
	}
	t.Run("header length exceeds input", func(t *testing.T) {
		err := new(CCache).Unmarshal(withHeader([]byte{0xFF, 0xFF, 0, 0}))
		require.EqualError(t, err, "credential cache header length 65535 exceeds remaining input")
	})
	t.Run("truncated field tag", func(t *testing.T) {
		err := new(CCache).Unmarshal(withHeader([]byte{0, 2, 0}))
		require.Error(t, err)
	})
	t.Run("truncated field length", func(t *testing.T) {
		err := new(CCache).Unmarshal(withHeader([]byte{0, 3, 0, 99, 0}))
		require.Error(t, err)
	})
	t.Run("field length exceeds header", func(t *testing.T) {
		err := new(CCache).Unmarshal(withHeader([]byte{0, 4, 0, 99, 0, 8, 'a'}))
		require.EqualError(t, err, "invalid credential cache header field length")
	})
	t.Run("invalid KDC offset header", func(t *testing.T) {
		err := new(CCache).Unmarshal(withHeader([]byte{0, 6, 0, 1, 0, 2, 'a', 'b'}))
		require.EqualError(t, err, "invalid credential cache KDC offset header")
	})
	t.Run("wrong version rejected", func(t *testing.T) {
		cache := &CCache{Version: 3}
		p := 0
		endian := binary.ByteOrder(binary.BigEndian)
		err := parseHeader(v3, &p, cache, &endian)
		require.EqualError(t, err, "Credentials cache version is not 4 so there is no header to parse.")
	})
}

// TestCCacheV1V2NativeByteOrder parses minimal version 1 and 2 caches, which
// use native byte order for integer representations.
func TestCCacheV1V2NativeByteOrder(t *testing.T) {
	var endian binary.ByteOrder = binary.BigEndian
	if isNativeEndianLittle() {
		endian = binary.LittleEndian
	}
	uint32Bytes := func(v uint32) []byte {
		b := make([]byte, 4)
		endian.PutUint32(b, v)
		return b
	}
	dataField := func(s string) []byte {
		return append(uint32Bytes(mustCCacheUint32(t, "string length", int64(len(s)))), s...)
	}
	principalV1 := func(realm string, components ...string) []byte {
		// Version 1 omits the name type and counts the realm as a component.
		b := uint32Bytes(mustCCacheUint32(t, "principal component count", int64(len(components))+1))
		b = append(b, dataField(realm)...)
		for _, c := range components {
			b = append(b, dataField(c)...)
		}
		return b
	}
	principalV2 := func(realm string, components ...string) []byte {
		b := append(uint32Bytes(uint32(nametype.KRB_NT_PRINCIPAL)), uint32Bytes(mustCCacheUint32(t, "principal component count", int64(len(components))))...)
		b = append(b, dataField(realm)...)
		for _, c := range components {
			b = append(b, dataField(c)...)
		}
		return b
	}
	t.Run("version 1", func(t *testing.T) {
		data := append([]byte{5, 1}, principalV1("TEST.GOKRB5", "testuser1")...)
		cache := new(CCache)
		require.NoError(t, cache.Unmarshal(data))
		assert.Equal(t, uint8(1), cache.Version)
		assert.Equal(t, "TEST.GOKRB5", cache.DefaultPrincipal.Realm)
		assert.Equal(t, []string{"testuser1"}, cache.DefaultPrincipal.PrincipalName.NameString)
		assert.Zero(t, cache.DefaultPrincipal.PrincipalName.NameType)
	})
	t.Run("version 2", func(t *testing.T) {
		data := append([]byte{5, 2}, principalV2("TEST.GOKRB5", "testuser1")...)
		cache := new(CCache)
		require.NoError(t, cache.Unmarshal(data))
		assert.Equal(t, uint8(2), cache.Version)
		assert.Equal(t, "TEST.GOKRB5", cache.DefaultPrincipal.Realm)
		assert.Equal(t, nametype.KRB_NT_PRINCIPAL, cache.DefaultPrincipal.PrincipalName.NameType)
	})
	t.Run("version 2 truncated", func(t *testing.T) {
		data := append([]byte{5, 2}, principalV2("TEST.GOKRB5", "testuser1")...)
		for length := 2; length < len(data); length++ {
			if err := new(CCache).Unmarshal(data[:length]); err == nil {
				t.Fatalf("version 2 prefix of length %d was accepted", length)
			}
		}
	})
}

// TestCCacheInvalidPrincipalComponentCount covers the component-count guard.
func TestCCacheInvalidPrincipalComponentCount(t *testing.T) {
	t.Run("negative count", func(t *testing.T) {
		data := []byte{5, 4, 0, 0}
		data = append(data, 0, 0, 0, 1)             // name type
		data = append(data, 0xFF, 0xFF, 0xFF, 0xFF) // component count -1
		err := new(CCache).Unmarshal(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid principal component count -1")
	})
	t.Run("count exceeds remaining input", func(t *testing.T) {
		data := []byte{5, 4, 0, 0}
		data = append(data, 0, 0, 0, 1) // name type
		data = append(data, 0, 0, 0, 9) // component count 9 with no data
		err := new(CCache).Unmarshal(data)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "invalid principal component count 9")
	})
}

// TestCCacheContains covers the match and miss paths of Contains.
func TestCCacheContains(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	require.NoError(t, err)
	cache := new(CCache)
	require.NoError(t, cache.Unmarshal(data))
	require.NotEmpty(t, cache.Credentials)
	target := cache.Credentials[0].Server.PrincipalName
	assert.True(t, cache.Contains(target))
	assert.False(t, cache.Contains(types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "no/such.service")))
	assert.False(t, new(CCache).Contains(target))
}

// TestCCacheHeaderFieldValid covers the header field validation branches.
func TestCCacheHeaderFieldValid(t *testing.T) {
	valid := headerField{tag: headerFieldTagKDCOffset, length: 8, value: make([]byte, 8)}
	assert.True(t, valid.valid())
	short := headerField{tag: headerFieldTagKDCOffset, length: 4, value: make([]byte, 4)}
	assert.False(t, short.valid())
	lengthValueMismatch := headerField{tag: headerFieldTagKDCOffset, length: 8, value: make([]byte, 4)}
	assert.False(t, lengthValueMismatch.valid())
	unknown := headerField{tag: 99}
	assert.False(t, unknown.valid())
}

// TestCCacheLoadCCacheErrors covers name resolution and read failures.
func TestCCacheLoadCCacheErrors(t *testing.T) {
	if _, err := LoadCCache(""); err == nil {
		t.Fatal("LoadCCache accepted an empty name")
	}
	if _, err := LoadCCache("FILE:/nonexistent-dir-gokrb5/ccache"); err == nil {
		t.Fatal("LoadCCache accepted a missing file")
	}
}

// TestResolveCCacheNameRejections covers name resolution rejection branches.
func TestResolveCCacheNameRejections(t *testing.T) {
	for name, input := range map[string]string{
		"empty":                  "",
		"empty after FILE strip": "FILE:",
		"unsupported type":       "API:cache",
		"unsupported parameter":  "/tmp/krb5cc_%{bogus}",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ResolveCCacheName(input); err == nil {
				t.Fatalf("ResolveCCacheName(%q) succeeded", input)
			}
		})
	}
	t.Run("parameters resolved", func(t *testing.T) {
		path, err := ResolveCCacheName("FILE:/tmp/krb5cc_%{uid}")
		require.NoError(t, err)
		assert.False(t, strings.Contains(path, "%{"))
	})
}

// TestCCacheMarshalRejections covers marshal-time state validation.
func TestCCacheMarshalRejections(t *testing.T) {
	validCredential := func() *Credential {
		return &Credential{
			Client:      Principal{Realm: "TEST.GOKRB5", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "testuser1")},
			Server:      Principal{Realm: "TEST.GOKRB5", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/TEST.GOKRB5")},
			Key:         types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)},
			AuthTime:    time.Unix(1700000000, 0),
			StartTime:   time.Unix(1700000000, 0),
			EndTime:     time.Unix(1700000000, 0),
			RenewTill:   time.Unix(1700000000, 0),
			TicketFlags: types.NewKrbFlags(),
			Ticket:      []byte{1, 2, 3},
		}
	}
	t.Run("unsupported version", func(t *testing.T) {
		for _, version := range []uint8{1, 2, 5} {
			cache := &CCache{Version: version}
			_, err := cache.Marshal()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "supports versions 3 and 4")
		}
	})
	t.Run("invalid KDC offset header", func(t *testing.T) {
		cache := &CCache{Version: 4}
		cache.Header.fields = append(cache.Header.fields, headerField{tag: headerFieldTagKDCOffset, value: make([]byte, 4)})
		_, err := cache.Marshal()
		require.EqualError(t, err, "invalid credential cache KDC offset header")
	})
	t.Run("nil credential", func(t *testing.T) {
		cache := &CCache{Version: 4, Credentials: []*Credential{nil}}
		_, err := cache.Marshal()
		require.EqualError(t, err, "credential 0 is nil")
	})
	t.Run("enctype outside uint16", func(t *testing.T) {
		for _, keyType := range []int32{-1, 65536} {
			cache := &CCache{Version: 4, Credentials: []*Credential{validCredential()}}
			cache.Credentials[0].Key.KeyType = keyType
			_, err := cache.Marshal()
			require.Error(t, err)
			assert.Contains(t, err.Error(), "enctype is outside uint16 range")
		}
	})
	t.Run("timestamp outside int32", func(t *testing.T) {
		cache := &CCache{Version: 4, Credentials: []*Credential{validCredential()}}
		cache.Credentials[0].EndTime = time.Unix(1<<31, 0)
		_, err := cache.Marshal()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "timestamp is outside int32 range")
	})
	t.Run("ticket flags not four bytes", func(t *testing.T) {
		cache := &CCache{Version: 4, Credentials: []*Credential{validCredential()}}
		cache.Credentials[0].TicketFlags.Bytes = []byte{1, 2, 3}
		_, err := cache.Marshal()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "ticket flags must contain 4 bytes")
	})
	t.Run("address type outside uint16", func(t *testing.T) {
		cache := &CCache{Version: 4, Credentials: []*Credential{validCredential()}}
		cache.Credentials[0].Addresses = []types.HostAddress{{AddrType: 65536, Address: []byte{1}}}
		_, err := cache.Marshal()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "address type is outside uint16 range")
	})
	t.Run("authdata type outside uint16", func(t *testing.T) {
		cache := &CCache{Version: 4, Credentials: []*Credential{validCredential()}}
		cache.Credentials[0].AuthData = []types.AuthorizationDataEntry{{ADType: -1, ADData: []byte{1}}}
		_, err := cache.Marshal()
		require.Error(t, err)
		assert.Contains(t, err.Error(), "authorization data type is outside uint16 range")
	})
}

// TestCCacheKDCTimeOffsetRoundTrip covers offset storage, update, and read.
func TestCCacheKDCTimeOffsetRoundTrip(t *testing.T) {
	cache := &CCache{Version: 4}
	if _, ok := cache.KDCTimeOffset(); ok {
		t.Fatal("offset reported without a header field")
	}
	cache.SetKDCTimeOffset(1500*time.Millisecond + 250*time.Microsecond)
	offset, ok := cache.KDCTimeOffset()
	require.True(t, ok)
	assert.Equal(t, 1500*time.Millisecond+250*time.Microsecond, offset)
	cache.SetKDCTimeOffset(-2 * time.Second)
	offset, ok = cache.KDCTimeOffset()
	require.True(t, ok)
	assert.Equal(t, -2*time.Second, offset)
	require.Len(t, cache.Header.fields, 1, "offset update must replace the existing field")
}

// TestDelegatedCredentialsCloning covers deep-copy and nil filtering.
func TestDelegatedCredentialsCloning(t *testing.T) {
	c := New("testuser1", "TEST.GOKRB5")
	c.delegated = []*Credential{
		nil,
		{
			Client:      Principal{Realm: "TEST.GOKRB5", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")},
			Server:      Principal{Realm: "TEST.GOKRB5", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "service")},
			Key:         types.EncryptionKey{KeyType: 18, KeyValue: []byte{1, 2}},
			TicketFlags: types.NewKrbFlags(),
			Addresses:   []types.HostAddress{{AddrType: 2, Address: []byte{127, 0, 0, 1}}},
			AuthData:    []types.AuthorizationDataEntry{{ADType: 1, ADData: []byte{9}}},
			Ticket:      []byte{5},
		},
	}
	cloned := c.DelegatedCredentials()
	require.Len(t, cloned, 1, "nil entries are filtered")
	cloned[0].Key.KeyValue[0] = 0xFF
	cloned[0].Addresses[0].Address[0] = 0xFF
	cloned[0].AuthData[0].ADData[0] = 0xFF
	cloned[0].Ticket[0] = 0xFF
	assert.Equal(t, byte(1), c.delegated[1].Key.KeyValue[0], "key material must be deep-copied")
	assert.Equal(t, byte(127), c.delegated[1].Addresses[0].Address[0])
	assert.Equal(t, byte(9), c.delegated[1].AuthData[0].ADData[0])
	assert.Equal(t, byte(5), c.delegated[1].Ticket[0])
}

// TestCredentialsMarshalUnregisteredAttribute covers the gob encode failure.
func TestCredentialsMarshalUnregisteredAttribute(t *testing.T) {
	c := New("testuser1", "TEST.GOKRB5")
	c.SetAttribute("channel", make(chan int))
	if _, err := c.Marshal(); err == nil {
		t.Fatal("marshal succeeded with an unregistered attribute type")
	}
}
