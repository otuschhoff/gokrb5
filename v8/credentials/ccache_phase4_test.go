package credentials

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/iana/nametype"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func ccacheFixtures() map[string]string {
	return map[string]string{
		"v4 password":       testdata.CCACHE_V4_KINIT_PASSWORD,
		"v4 service ticket": testdata.CCACHE_V4_WITH_SERVICE_TICKET,
		"v3":                testdata.CCACHE_V3,
	}
}

func TestCCacheMarshalByteExactFixtures(t *testing.T) {
	for name, encoded := range ccacheFixtures() {
		t.Run(name, func(t *testing.T) {
			data, err := hex.DecodeString(encoded)
			if err != nil {
				t.Fatal(err)
			}
			cache := new(CCache)
			if err := cache.Unmarshal(data); err != nil {
				t.Fatal(err)
			}
			marshaled, err := cache.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, data, marshaled)
		})
	}
}

func TestCCacheUnmarshalTruncatedInputsReturnError(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	lengths := make([]int, 0, 53)
	for length := 0; length < 52; length++ {
		lengths = append(lengths, length)
	}
	lengths = append(lengths, len(data)-1)
	for _, length := range lengths {
		cache := new(CCache)
		if err := cache.Unmarshal(data[:length]); err == nil {
			t.Fatalf("expected error for input length %d", length)
		}
	}
}

func TestCCacheUnmarshalResetsState(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	cache := new(CCache)
	if err := cache.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	want := len(cache.Credentials)
	if err := cache.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	assert.Len(t, cache.Credentials, want)
}

func TestCCacheUnknownHeaderTagPreserved(t *testing.T) {
	v3, err := hex.DecodeString(testdata.CCACHE_V3)
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{5, 4, 0, 7, 0, 99, 0, 3, 'a', 'b', 'c'}
	data = append(data, v3[2:]...)
	cache := new(CCache)
	if err := cache.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	if assert.Len(t, cache.Header.fields, 1) {
		assert.Equal(t, uint16(99), cache.Header.fields[0].tag)
		assert.Equal(t, []byte("abc"), cache.Header.fields[0].value)
	}
	marshaled, err := cache.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, data, marshaled)
}

func TestCCacheCapturedConfigEntry(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_TEST)
	if err != nil {
		t.Fatal(err)
	}
	cache := new(CCache)
	if err := cache.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	value, found := cache.GetConfig("fast_avail", "krbtgt/TEST.GOKRB5@TEST.GOKRB5")
	assert.True(t, found)
	assert.Equal(t, "yes", value)
	_, found = cache.GetConfig("fast_avail", "")
	assert.False(t, found)
	for _, key := range []string{"pa_type", "refresh_time", "start_realm"} {
		_, found = cache.GetConfig(key, "")
		assert.False(t, found, "unexpected global %s entry", key)
		_, found = cache.GetConfig(key, "krbtgt/TEST.GOKRB5@TEST.GOKRB5")
		assert.False(t, found, "unexpected TGT-associated %s entry", key)
	}
	assert.Len(t, cache.GetEntries(), 2)
}

func TestCCacheCapturedKinitPasswordHasNoConfigEntries(t *testing.T) {
	data, err := hex.DecodeString(testdata.CCACHE_V4_KINIT_PASSWORD)
	if err != nil {
		t.Fatal(err)
	}
	cache := new(CCache)
	if err := cache.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	assert.Len(t, cache.GetEntries(), 1)
	assert.Len(t, cache.Credentials, 1)
}

func TestCCacheConfigEntriesAndOffset(t *testing.T) {
	client := types.PrincipalName{NameType: nametype.KRB_NT_PRINCIPAL, NameString: []string{"user"}}
	cache := NewCCache(client, "EXAMPLE.ORG")
	cache.SetKDCTimeOffset(-1500*time.Millisecond - 25*time.Microsecond)
	offset, ok := cache.KDCTimeOffset()
	assert.True(t, ok)
	assert.Equal(t, -1500*time.Millisecond-25*time.Microsecond, offset)

	if err := cache.SetConfig("fast_avail", "", "yes"); err != nil {
		t.Fatal(err)
	}
	if err := cache.SetConfig("pa_type", "user@EXAMPLE.ORG", "2"); err != nil {
		t.Fatal(err)
	}
	if err := cache.SetConfig("fast_avail", "", "updated"); err != nil {
		t.Fatal(err)
	}
	value, found := cache.GetConfig("fast_avail", "")
	assert.True(t, found)
	assert.Equal(t, "updated", value)
	assert.Empty(t, cache.GetEntries())
	assert.Len(t, cache.Credentials, 2)
	assert.Error(t, cache.SetConfig("", "", "value"))

	data, err := cache.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reparsed := new(CCache)
	if err := reparsed.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, cache.DefaultPrincipal, reparsed.DefaultPrincipal)
	assert.Equal(t, cache.Credentials[0].Ticket, reparsed.Credentials[0].Ticket)
	assert.Equal(t, cache.Credentials[1].Ticket, reparsed.Credentials[1].Ticket)
	offset, ok = reparsed.KDCTimeOffset()
	assert.True(t, ok)
	assert.Equal(t, -1500*time.Millisecond-25*time.Microsecond, offset)
}

func TestCCacheCrossRealmTGTRecordsStartRealm(t *testing.T) {
	client := Principal{Realm: "CLIENT.EXAMPLE", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")}
	cache := NewCCache(client.PrincipalName, client.Realm)
	cache.AddCredential(&Credential{
		Client: client,
		Server: Principal{Realm: "CLIENT.EXAMPLE", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/SOURCE.EXAMPLE")},
	})

	value, found := cache.GetConfig("start_realm", "")
	assert.True(t, found)
	assert.Equal(t, "SOURCE.EXAMPLE", value)
	_, associated := cache.GetConfig("start_realm", "krbtgt/SOURCE.EXAMPLE@CLIENT.EXAMPLE")
	assert.False(t, associated)
	if assert.Len(t, cache.Credentials, 2) {
		assert.Equal(t, configRealm, cache.Credentials[0].Server.Realm, "MIT stores start_realm before the cross-realm TGT")
		assert.Equal(t, "CLIENT.EXAMPLE", cache.Credentials[1].Server.Realm)
	}
}

func TestCCacheSameRealmTGTOmitsStartRealm(t *testing.T) {
	client := Principal{Realm: "EXAMPLE.ORG", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user")}
	cache := NewCCache(client.PrincipalName, client.Realm)
	cache.AddCredential(&Credential{
		Client: client,
		Server: Principal{Realm: client.Realm, PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.ORG")},
	})

	_, found := cache.GetConfig("start_realm", "")
	assert.False(t, found)
}

func TestCCacheV3WritesRepeatedEnctype(t *testing.T) {
	cache := NewCCache(types.PrincipalName{NameType: 1, NameString: []string{"user"}}, "EXAMPLE.ORG")
	cache.Version = 3
	cache.Credentials = []*Credential{{
		Client:      clonePrincipal(cache.DefaultPrincipal),
		Server:      Principal{Realm: "EXAMPLE.ORG", PrincipalName: types.PrincipalName{NameType: 2, NameString: []string{"krbtgt", "EXAMPLE.ORG"}}},
		Key:         types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)},
		AuthTime:    time.Unix(1, 0),
		StartTime:   time.Unix(2, 0),
		EndTime:     time.Unix(3, 0),
		RenewTill:   time.Unix(4, 0),
		TicketFlags: types.NewKrbFlags(),
	}}
	data, err := cache.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	needle := []byte{0, 18, 0, 18, 0, 0, 0, 32}
	assert.True(t, bytes.Contains(data, needle))
	reparsed := new(CCache)
	if err := reparsed.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, cache.Credentials[0].Key, reparsed.Credentials[0].Key)
	index := bytes.Index(data, needle)
	if index < 0 {
		t.Fatal("version 3 key header not found")
	}
	data[index+3]++
	assert.Error(t, reparsed.Unmarshal(data))
}

func TestCCacheMarshalWritesZeroTimeAsUnixEpoch(t *testing.T) {
	cache := NewCCache(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"), "EXAMPLE.ORG")
	cache.Credentials = []*Credential{{
		Client:      clonePrincipal(cache.DefaultPrincipal),
		Server:      Principal{Realm: "EXAMPLE.ORG", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_INST, "krbtgt/EXAMPLE.ORG")},
		Key:         types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)},
		EndTime:     time.Unix(3, 0),
		TicketFlags: types.NewKrbFlags(),
	}}

	data, err := cache.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reparsed := new(CCache)
	if err := reparsed.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	credential := reparsed.Credentials[0]
	assert.Equal(t, int64(0), credential.AuthTime.Unix())
	assert.Equal(t, int64(0), credential.StartTime.Unix())
	assert.Equal(t, int64(0), credential.RenewTill.Unix())
}

func TestCCacheAddressAndAuthDataRoundTrip(t *testing.T) {
	cache := NewCCache(types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "user"), "EXAMPLE.ORG")
	credential := &Credential{
		Client:       clonePrincipal(cache.DefaultPrincipal),
		Server:       Principal{Realm: "EXAMPLE.ORG", PrincipalName: types.NewPrincipalName(nametype.KRB_NT_SRV_HST, "host/server.example.org")},
		Key:          types.EncryptionKey{KeyType: 18, KeyValue: bytes.Repeat([]byte{1}, 32)},
		AuthTime:     time.Unix(1, 0),
		StartTime:    time.Unix(2, 0),
		EndTime:      time.Unix(3, 0),
		RenewTill:    time.Unix(4, 0),
		TicketFlags:  types.NewKrbFlags(),
		Addresses:    []types.HostAddress{{AddrType: 2, Address: []byte{127, 0, 0, 1}}},
		AuthData:     []types.AuthorizationDataEntry{{ADType: 1, ADData: []byte("authorization-data")}},
		Ticket:       []byte("ticket"),
		SecondTicket: []byte("second-ticket"),
	}
	cache.AddCredential(credential)

	encoded, err := cache.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	decoded := new(CCache)
	if err := decoded.Unmarshal(encoded); err != nil {
		t.Fatal(err)
	}
	if assert.Len(t, decoded.Credentials, 1) {
		assert.Equal(t, credential.Addresses, decoded.Credentials[0].Addresses)
		assert.Equal(t, credential.AuthData, decoded.Credentials[0].AuthData)
		assert.Equal(t, credential.Ticket, decoded.Credentials[0].Ticket)
		assert.Equal(t, credential.SecondTicket, decoded.Credentials[0].SecondTicket)
	}
}

func TestCCacheAddressAndAuthDataRejectMalformedLengths(t *testing.T) {
	tests := []struct {
		name string
		read func([]byte, *int, binary.ByteOrder) error
	}{
		{name: "address", read: func(data []byte, offset *int, order binary.ByteOrder) error {
			_, err := readAddress(data, offset, order)
			return err
		}},
		{name: "authorization data", read: func(data []byte, offset *int, order binary.ByteOrder) error {
			_, err := readAuthDataEntry(data, offset, order)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			for _, data := range [][]byte{
				{0},
				{0, 1, 0, 0, 0, 2, 1},
				{0, 1, 0xff, 0xff, 0xff, 0xff},
			} {
				offset := 0
				if err := test.read(data, &offset, binary.BigEndian); err == nil {
					t.Fatalf("malformed field %x was accepted", data)
				}
			}
		})
	}
}

func TestCCacheMarshalRejectsInvalidState(t *testing.T) {
	cache := NewCCache(types.PrincipalName{NameString: []string{"user"}}, "EXAMPLE.ORG")
	cache.Version = 2
	_, err := cache.Marshal()
	assert.Error(t, err)
	cache.Version = 4
	cache.Credentials = append(cache.Credentials, nil)
	_, err = cache.Marshal()
	assert.Error(t, err)
}

func TestCCacheWriteFileAtomicAndMode0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cache")
	cache := NewCCache(types.PrincipalName{NameType: 1, NameString: []string{"user"}}, "EXAMPLE.ORG")
	if err := cache.WriteFile("FILE:" + path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	assert.Equal(t, path, cache.Path)
	loaded, err := LoadCCache("FILE:" + path)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, path, loaded.Path)
	assert.Equal(t, cache.DefaultPrincipal, loaded.DefaultPrincipal)

	original := []byte("existing cache remains intact")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	cache.Credentials = append(cache.Credentials, nil)
	assert.Error(t, cache.WriteFile(path))
	written, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, original, written)
}

func TestDefaultCCacheNameResolution(t *testing.T) {
	previous, present := os.LookupEnv("KRB5CCNAME")
	t.Cleanup(func() {
		if present {
			_ = os.Setenv("KRB5CCNAME", previous)
		} else {
			_ = os.Unsetenv("KRB5CCNAME")
		}
	})
	cfg := config.New()
	cfg.LibDefaults.DefaultCCacheName = "FILE:" + filepath.Join(t.TempDir(), "config-%{uid}-%{euid}-%{username}-%{TEMP}")
	if err := os.Setenv("KRB5CCNAME", ""); err != nil {
		t.Fatal(err)
	}
	path, err := DefaultCCacheName(cfg)
	if err != nil {
		t.Fatal(err)
	}
	assert.NotContains(t, path, "%{")
	if err := os.Setenv("KRB5CCNAME", "FILE:/tmp/environment-cache"); err != nil {
		t.Fatal(err)
	}
	path, err = DefaultCCacheName(cfg)
	assert.NoError(t, err)
	assert.Equal(t, "/tmp/environment-cache", path)
	if err := os.Setenv("KRB5CCNAME", "DIR:/tmp/cache"); err != nil {
		t.Fatal(err)
	}
	_, err = DefaultCCacheName(cfg)
	assert.Error(t, err)
}

func FuzzCCacheUnmarshal(f *testing.F) {
	for _, encoded := range ccacheFixtures() {
		data, err := hex.DecodeString(encoded)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cache := new(CCache)
		if err := cache.Unmarshal(data); err != nil {
			return
		}
		if cache.Version < 3 {
			return
		}
		marshaled, err := cache.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		reparsed := new(CCache)
		if err := reparsed.Unmarshal(marshaled); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(cache, reparsed) {
			t.Fatal("semantic ccache round trip changed parsed data")
		}
	})
}

func TestKDCTimeOffsetWireEncoding(t *testing.T) {
	cache := NewCCache(types.PrincipalName{NameType: 1, NameString: []string{"user"}}, "EXAMPLE.ORG")
	cache.SetKDCTimeOffset(6*time.Second + 25*time.Microsecond)
	if assert.Len(t, cache.Header.fields, 1) {
		assert.Equal(t, int32(6), int32(binary.BigEndian.Uint32(cache.Header.fields[0].value[:4])))
		assert.Equal(t, int32(25), int32(binary.BigEndian.Uint32(cache.Header.fields[0].value[4:])))
	}
}
