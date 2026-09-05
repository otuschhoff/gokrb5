package keytab

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshalAllFixtures(t *testing.T) {
	type expectedEntry struct {
		principal string
		kvno      uint32
		etype     int32
		timestamp int64
		key       string
	}
	tests := map[string]struct {
		hex      string
		version  uint8
		expected []expectedEntry
	}{
		"all etypes": {testdata.KEYTAB_KTUTIL_ALL_ETYPES, 2, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 1, 17, 1700000000, "698c4df8e9f60e7eea5a21bf4526ad25"},
			{"testuser1@TEST.GOKRB5", 1, 18, 1700000000, "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"},
			{"testuser1@TEST.GOKRB5", 1, 19, 1700000000, "2eb8501967a7886e1f0c63ac9be8c4a0"},
			{"testuser1@TEST.GOKRB5", 1, 20, 1700000000, "8ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee"},
			{"testuser1@TEST.GOKRB5", 1, 23, 1700000000, "084768c373663b3bef1f6385883cf7ff"},
			{"testuser1@TEST.GOKRB5", 1, 16, 1700000000, "4580fb91760dabe6f808c22c26494f644cb35d61d32c79e3"},
		}},
		"kvno 300": {testdata.KEYTAB_KTUTIL_KVNO_300, 2, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 300, 18, 1700000000, "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"},
		}},
		"unordered kvnos": {testdata.KEYTAB_KTUTIL_MULTI_KVNO_UNORDERED, 2, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 3, 18, 1700000200, "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"},
			{"testuser1@TEST.GOKRB5", 4, 18, 1700000100, "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"},
		}},
		"multiple principals": {testdata.KEYTAB_KTUTIL_MULTI_PRINCIPAL, 2, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 1, 18, 1700000000, "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"},
			{"HTTP/host.test.gokrb5@TEST.GOKRB5", 2, 17, 1700000000, "356ad121be81a9dc2887f714f2da50e8"},
			{"host/host.other.example@OTHER.EXAMPLE", 3, 23, 1700000000, "084768c373663b3bef1f6385883cf7ff"},
		}},
		"middle hole": {testdata.KEYTAB_KADMIN_KTREMOVE_HOLES, 2, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 1, 17, 1700000000, "698c4df8e9f60e7eea5a21bf4526ad25"},
			{"testuser1@TEST.GOKRB5", 1, 19, 1700000000, "2eb8501967a7886e1f0c63ac9be8c4a0"},
			{"testuser1@TEST.GOKRB5", 1, 20, 1700000000, "8ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee"},
			{"testuser1@TEST.GOKRB5", 1, 23, 1700000000, "084768c373663b3bef1f6385883cf7ff"},
			{"testuser1@TEST.GOKRB5", 1, 16, 1700000000, "4580fb91760dabe6f808c22c26494f644cb35d61d32c79e3"},
		}},
		"hole at eof": {testdata.KEYTAB_KADMIN_KTREMOVE_HOLE_AT_EOF, 2, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 1, 17, 1700000000, "698c4df8e9f60e7eea5a21bf4526ad25"},
			{"testuser1@TEST.GOKRB5", 1, 18, 1700000000, "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"},
			{"testuser1@TEST.GOKRB5", 1, 19, 1700000000, "2eb8501967a7886e1f0c63ac9be8c4a0"},
			{"testuser1@TEST.GOKRB5", 1, 20, 1700000000, "8ad66f209bb07daa186f8a229830f5ba06a3a2a33638f4ec66e1d29324e417ee"},
			{"testuser1@TEST.GOKRB5", 1, 23, 1700000000, "084768c373663b3bef1f6385883cf7ff"},
		}},
		"v1 little endian": {testdata.KEYTAB_V1_LITTLE_ENDIAN, 1, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 5, 17, 1700000000, "000102030405060708090a0b0c0d0e0f"},
		}},
		"v1 big endian": {testdata.KEYTAB_V1_BIG_ENDIAN, 1, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 5, 17, 1700000000, "000102030405060708090a0b0c0d0e0f"},
		}},
		"explicit AD salt": {testdata.KEYTAB_AD_HOST_SALT, 2, []expectedEntry{
			{"host/host.test.gokrb5@TEST.GOKRB5", 1, 18, 1700000000, "07b6b34bb7a9a1ed7cd964f21c09f7afcf77757dddd29e8e5ab4de2f2a8ea92e"},
		}},
		"enterprise principal": {testdata.KEYTAB_ENTERPRISE_PRINCIPAL, 2, []expectedEntry{
			{`user\@corp.example@TEST.GOKRB5`, 1, 18, 1700000000, "3e1ba322d0872633a3c1c5ea9ea65dd8517d8e8b5ed199cd55e82056cfc81412"},
		}},
		"without kvno32": {testdata.KEYTAB_NO_KVNO32_TRAILER, 2, []expectedEntry{
			{"testuser1@TEST.GOKRB5", 44, 18, 1700000000, "bbdc430aab7e2d4622a0b6951481453b0962e9db8e2f168942ad175cda6d9de9"},
		}},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			b, err := hex.DecodeString(test.hex)
			if err != nil {
				t.Fatal(err)
			}
			kt := New()
			if err := kt.Unmarshal(b); err != nil {
				t.Fatalf("could not unmarshal fixture: %v", err)
			}
			assert.Equal(t, test.version, kt.version)
			if assert.Len(t, kt.Entries, len(test.expected)) {
				for i, expected := range test.expected {
					entry := kt.Entries[i]
					assert.Equal(t, expected.principal, entry.Principal.String())
					assert.Equal(t, expected.kvno, entry.KVNO)
					assert.Equal(t, expected.etype, entry.Key.KeyType)
					assert.Equal(t, time.Unix(expected.timestamp, 0), entry.Timestamp)
					assert.Equal(t, expected.key, hex.EncodeToString(entry.Key.KeyValue))
				}
			}
		})
	}
}

func TestUnmarshal(t *testing.T) {
	t.Parallel()
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := New()
	err := kt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	assert.Equal(t, uint8(2), kt.version, "Keytab version not as expected")
	assert.Equal(t, uint32(1), kt.Entries[0].KVNO, "KVNO not as expected")
	assert.Equal(t, time.Unix(1505669592, 0), kt.Entries[0].Timestamp, "Timestamp not as expected")
	assert.Equal(t, int32(17), kt.Entries[0].Key.KeyType, "Key's EType not as expected")
	assert.Equal(t, "698c4df8e9f60e7eea5a21bf4526ad25", hex.EncodeToString(kt.Entries[0].Key.KeyValue), "Key material not as expected")
	assert.Equal(t, int32(1), kt.Entries[0].Principal.NameType, "Name type of principal not as expected")
	assert.Equal(t, "TEST.GOKRB5", kt.Entries[0].Principal.Realm, "Realm of principal not as expected")
	assert.Equal(t, "testuser1", kt.Entries[0].Principal.Components[0], "Component in principal not as expected")
}

func TestMarshal(t *testing.T) {
	t.Parallel()
	b, _ := hex.DecodeString(testdata.KEYTAB_TESTUSER1_TEST_GOKRB5)
	kt := New()
	err := kt.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error parsing keytab data: %v\n", err)
	}
	mb, err := kt.Marshal()
	if err != nil {
		t.Fatalf("Error marshaling: %v", err)
	}
	assert.Equal(t, b, mb, "Marshaled bytes not the same as input bytes")
	err = kt.Unmarshal(mb)
	if err != nil {
		t.Fatalf("Error parsing marshaled bytes: %v", err)
	}
}

func TestMarshalByteExactVsKtutil(t *testing.T) {
	for name, fixture := range map[string]string{
		"all etypes": testdata.KEYTAB_KTUTIL_ALL_ETYPES,
		"kvno 300":   testdata.KEYTAB_KTUTIL_KVNO_300,
	} {
		t.Run(name, func(t *testing.T) {
			b, err := hex.DecodeString(fixture)
			if err != nil {
				t.Fatal(err)
			}
			kt := New()
			if err := kt.Unmarshal(b); err != nil {
				t.Fatal(err)
			}
			marshaled, err := kt.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, b, marshaled)
		})
	}
}

func TestUnmarshalV1RoundTrip(t *testing.T) {
	for name, fixture := range map[string]string{
		"little endian": testdata.KEYTAB_V1_LITTLE_ENDIAN,
		"big endian":    testdata.KEYTAB_V1_BIG_ENDIAN,
	} {
		t.Run(name, func(t *testing.T) {
			b, err := hex.DecodeString(fixture)
			if err != nil {
				t.Fatal(err)
			}
			kt := New()
			if err := kt.Unmarshal(b); err != nil {
				t.Fatal(err)
			}
			assert.False(t, kt.Entries[0].kvno32Present)

			marshaled, err := kt.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, b, marshaled)
		})
	}
}

func TestUnmarshalV1KVNO32(t *testing.T) {
	for name, test := range map[string]struct {
		fixture string
		endian  binary.ByteOrder
	}{
		"little endian": {testdata.KEYTAB_V1_LITTLE_ENDIAN, binary.LittleEndian},
		"big endian":    {testdata.KEYTAB_V1_BIG_ENDIAN, binary.BigEndian},
	} {
		t.Run(name, func(t *testing.T) {
			b, err := hex.DecodeString(test.fixture)
			if err != nil {
				t.Fatal(err)
			}
			kvno := uint32(300)
			b[36] = byte(kvno)
			recordLength := test.endian.Uint32(b[2:6])
			test.endian.PutUint32(b[2:6], recordLength+4)
			trailer := make([]byte, 4)
			test.endian.PutUint32(trailer, kvno)
			b = append(b, trailer...)

			kt := New()
			if err := kt.Unmarshal(b); err != nil {
				t.Fatal(err)
			}
			assert.True(t, kt.Entries[0].kvno32Present)
			assert.Equal(t, uint32(300), kt.Entries[0].KVNO)

			marshaled, err := kt.Marshal()
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, b, marshaled)
		})
	}
}

func TestUnmarshalKVNO32Presence(t *testing.T) {
	withTrailer, err := hex.DecodeString(testdata.KEYTAB_KTUTIL_KVNO_300)
	if err != nil {
		t.Fatal(err)
	}
	withoutTrailer, err := hex.DecodeString(testdata.KEYTAB_NO_KVNO32_TRAILER)
	if err != nil {
		t.Fatal(err)
	}

	kt := New()
	if err := kt.Unmarshal(withTrailer); err != nil {
		t.Fatal(err)
	}
	assert.True(t, kt.Entries[0].kvno32Present)
	assert.Equal(t, uint32(300), kt.Entries[0].KVNO)

	if err := kt.Unmarshal(withoutTrailer); err != nil {
		t.Fatal(err)
	}
	assert.False(t, kt.Entries[0].kvno32Present)
	assert.Equal(t, uint32(44), kt.Entries[0].KVNO)

	withZeroFill := append(withoutTrailer, 0, 0, 0, 0)
	binary.BigEndian.PutUint32(withZeroFill[2:6], binary.BigEndian.Uint32(withZeroFill[2:6])+4)
	if err := kt.Unmarshal(withZeroFill); err != nil {
		t.Fatal(err)
	}
	assert.False(t, kt.Entries[0].kvno32Present)
	assert.Equal(t, uint32(44), kt.Entries[0].KVNO)
}

func TestUnmarshalResetsEntries(t *testing.T) {
	b, err := hex.DecodeString(testdata.KEYTAB_KTUTIL_KVNO_300)
	if err != nil {
		t.Fatal(err)
	}
	kt := New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	assert.Len(t, kt.Entries, 1)
	if err := kt.Unmarshal([]byte{5, 2, 0, 0, 0, 2, 0, 1}); err == nil {
		t.Fatal("expected malformed keytab error")
	}
	assert.Empty(t, kt.Entries)
}

func TestUnmarshalTruncatedPrincipalReturnsError(t *testing.T) {
	kt := New()
	err := kt.Unmarshal([]byte{5, 2, 0, 0, 0, 2, 0, 1})
	if err == nil || !strings.Contains(err.Error(), "invalid principal") {
		t.Fatalf("expected invalid principal error, got %v", err)
	}
	assert.Empty(t, kt.Entries)
}

func TestUnmarshalRejectsInvalidComponentCount(t *testing.T) {
	for name, test := range map[string]struct {
		version uint8
		count   int16
		endian  binary.ByteOrder
	}{
		"v2 zero":     {2, 0, binary.BigEndian},
		"v2 negative": {2, -1, binary.BigEndian},
		"v1 realm only": {1, 1, func() binary.ByteOrder {
			if isNativeEndianLittle() {
				return binary.LittleEndian
			}
			return binary.BigEndian
		}()},
	} {
		t.Run(name, func(t *testing.T) {
			b := []byte{5, test.version, 0, 0, 0, 2, 0, 0}
			test.endian.PutUint32(b[2:6], 2)
			test.endian.PutUint16(b[6:8], uint16(test.count))
			err := New().Unmarshal(b)
			if err == nil || !strings.Contains(err.Error(), "component count") {
				t.Fatalf("expected component count error, got %v", err)
			}
		})
	}
}

func TestUnmarshalHoles(t *testing.T) {
	for name, fixture := range map[string]string{
		"middle": testdata.KEYTAB_KADMIN_KTREMOVE_HOLES,
		"eof":    testdata.KEYTAB_KADMIN_KTREMOVE_HOLE_AT_EOF,
	} {
		t.Run(name, func(t *testing.T) {
			b, err := hex.DecodeString(fixture)
			if err != nil {
				t.Fatal(err)
			}
			kt := New()
			if err := kt.Unmarshal(b); err != nil {
				t.Fatal(err)
			}
			assert.Len(t, kt.Entries, 5)
		})
	}
}

func TestUnmarshalZeroLengthRecordIsEOF(t *testing.T) {
	first, err := hex.DecodeString(testdata.KEYTAB_KTUTIL_KVNO_300)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hex.DecodeString(testdata.KEYTAB_AD_HOST_SALT)
	if err != nil {
		t.Fatal(err)
	}
	b := append(append(first, 0, 0, 0, 0), second[2:]...)
	kt := New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	assert.Len(t, kt.Entries, 1)
}

func TestUnmarshalEmptyKeytab(t *testing.T) {
	kt := New()
	if err := kt.Unmarshal([]byte{5, 2}); err != nil {
		t.Fatal(err)
	}
	assert.Empty(t, kt.Entries)
}

func TestErrorsDoNotContainKeyMaterial(t *testing.T) {
	b, err := hex.DecodeString(testdata.KEYTAB_KTUTIL_KVNO_300)
	if err != nil {
		t.Fatal(err)
	}
	keyMaterial := b[len(b)-36 : len(b)-4]
	binary.BigEndian.PutUint32(b[2:6], uint32(len(b)))
	err = New().Unmarshal(b)
	if err == nil {
		t.Fatal("expected malformed record error")
	}
	if strings.Contains(err.Error(), string(keyMaterial)) || strings.Contains(err.Error(), hex.EncodeToString(keyMaterial)) {
		t.Fatalf("error contains key material: %q", err)
	}
}

func FuzzUnmarshal(f *testing.F) {
	for _, fixture := range []string{
		testdata.KEYTAB_KTUTIL_ALL_ETYPES,
		testdata.KEYTAB_KTUTIL_KVNO_300,
		testdata.KEYTAB_KTUTIL_MULTI_KVNO_UNORDERED,
		testdata.KEYTAB_KTUTIL_MULTI_PRINCIPAL,
		testdata.KEYTAB_KADMIN_KTREMOVE_HOLES,
		testdata.KEYTAB_KADMIN_KTREMOVE_HOLE_AT_EOF,
		testdata.KEYTAB_V1_LITTLE_ENDIAN,
		testdata.KEYTAB_V1_BIG_ENDIAN,
		testdata.KEYTAB_AD_HOST_SALT,
		testdata.KEYTAB_ENTERPRISE_PRINCIPAL,
		testdata.KEYTAB_NO_KVNO32_TRAILER,
	} {
		b, err := hex.DecodeString(fixture)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(b)
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		kt := New()
		if err := kt.Unmarshal(b); err != nil {
			return
		}
		marshaled, err := kt.Marshal()
		if err != nil {
			t.Fatalf("could not marshal accepted keytab: %v", err)
		}
		roundTripped := New()
		if err := roundTripped.Unmarshal(marshaled); err != nil {
			t.Fatalf("could not reparse marshaled keytab: %v", err)
		}
		if len(kt.Entries) != len(roundTripped.Entries) {
			t.Fatalf("entry count changed from %d to %d", len(kt.Entries), len(roundTripped.Entries))
		}
		if kt.version != roundTripped.version {
			t.Fatal("keytab version changed after round trip")
		}
		for i := range kt.Entries {
			before := kt.Entries[i]
			after := roundTripped.Entries[i]
			before.kvno32Present = false
			after.kvno32Present = false
			if !reflect.DeepEqual(before, after) {
				t.Fatalf("entry %d changed after round trip", i)
			}
		}
	})
}

func TestLoad(t *testing.T) {
	t.Parallel()
	f := "test/testdata/testuser1.testtab"
	cwd, _ := os.Getwd()
	dir := os.Getenv("TRAVIS_BUILD_DIR")
	if dir != "" {
		f = dir + "/" + f
	} else if filepath.Base(cwd) == "keytab" {
		f = "../" + f
	}
	kt, err := Load(f)
	if err != nil {
		t.Fatalf("could not load keytab: %v", err)
	}
	assert.Equal(t, uint8(2), kt.version, "keytab version not as expected")
	assert.Equal(t, 12, len(kt.Entries), "keytab entry count not as expected: %+v", *kt)
	for _, e := range kt.Entries {
		if e.Principal.Realm != "TEST.GOKRB5" {
			t.Error("principal realm not as expected")
		}
		if e.Principal.NameType != int32(1) {
			t.Error("name type not as expected")
		}
		if len(e.Principal.Components) != 1 {
			t.Error("number of component not as expected")
		}
		if e.Principal.Components[0] != "testuser1" {
			t.Error("principal components not as expected")
		}
		if e.Timestamp.IsZero() {
			t.Error("entry timestamp incorrect")
		}
		if e.KVNO == uint32(0) {
			t.Error("entry kvno not as expected")
		}
	}
}

// This test provides inputs to readBytes that previously
// caused a panic.
func TestReadBytes(t *testing.T) {
	var endian binary.ByteOrder
	endian = binary.BigEndian
	p := 0

	if _, err := readBytes(nil, &p, 1, &endian); err == nil {
		t.Fatal("err should be populated because s was given that exceeds array length")
	}
	if _, err := readBytes(nil, &p, -1, &endian); err == nil {
		t.Fatal("err should be given because negative s was given")
	}
}

func TestUnmarshalPotentialPanics(t *testing.T) {
	kt := New()

	// Test a good keytab with bad bytes to unmarshal. These should
	// return errors, but not panic.
	if err := kt.Unmarshal(nil); err == nil {
		t.Fatal("should have errored, input is absent")
	}
	if err := kt.Unmarshal([]byte{}); err == nil {
		t.Fatal("should have errored, input is empty")
	}
	// Incorrect first byte.
	if err := kt.Unmarshal([]byte{4}); err == nil {
		t.Fatal("should have errored, input isn't long enough")
	}
	// First byte, but no further content.
	if err := kt.Unmarshal([]byte{5}); err == nil {
		t.Fatal("should have errored, input isn't long enough")
	}
}

// cxf testing stuff
func TestBadKeytabs(t *testing.T) {
	badPayloads := make([]string, 3)
	badPayloads = append(badPayloads, "BQIwMDAwMDA=")
	badPayloads = append(badPayloads, "BQIAAAAwAAEACjAwMDAwMDAwMDAAIDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAwMDAw")
	badPayloads = append(badPayloads, "BQKAAAAA")
	for _, v := range badPayloads {
		decodedKt, _ := base64.StdEncoding.DecodeString(v)
		parsedKt := new(Keytab)
		parsedKt.Unmarshal(decodedKt)
	}
}

func TestKeytabEntriesUser(t *testing.T) {

	// Load known-good keytab generated with ktutil
	ktutilb64 := "BQIAAABGAAEAC0VYQU1QTEUuT1JHAAR1c2VyAAAAAV5ePQAfABIAIG6I6ys5Me8XyS54Ck7kIfFBH/WxBOP3W1DdE/ntBPnGAAAAHwAAADYAAQALRVhBTVBMRS5PUkcABHVzZXIAAAABXl49AB8AEQAQm7fVug9VRBJVhEGjHyN3EgAAAB8AAAA2AAEAC0VYQU1QTEUuT1JHAAR1c2VyAAAAAV5ePQAfABcAEBENDFHhRNNvt+T54BL7uIgAAAAf"
	ktutilbytes, err := base64.StdEncoding.DecodeString(ktutilb64)
	if err != nil {
		t.Errorf("Could not parse b64 ktutil keytab: %s", err)
	}
	ktutil := new(Keytab)
	err = ktutil.Unmarshal(ktutilbytes)
	if err != nil {
		t.Fatalf("Could not load ktutil-generated keytab: %s", err)
	}

	// Generate the same keytab with gokrb5
	var ts time.Time = ktutil.Entries[0].Timestamp
	var encTypes []int32 = []int32{
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.RC4_HMAC,
	}

	kt := New()
	for _, et := range encTypes {
		err = kt.AddEntry("user", "EXAMPLE.ORG", "hello123", ts, 31, et)
		if err != nil {
			t.Errorf("Error adding entry to keytab: %s", err)
		}
	}
	generated, err := kt.Marshal()
	if err != nil {
		t.Errorf("Error marshalling generated keytab: %s", err)
	}

	// Compare content
	assert.Equal(t, generated, ktutilbytes, "Service keytab doesn't match ktutil keytab")
}

func TestKeytabEntriesService(t *testing.T) {

	// Load known-good keytab generated with ktutil
	ktutilb64 := "BQIAAABXAAIAC0VYQU1QTEUuT1JHAARIVFRQAA93d3cuZXhhbXBsZS5vcmcAAAABXl49ggoAEgAgOCSpM5CdiZQn1+rUtLtt6sTrg5Saw1DXJMai7vDWJ0QAAAAKAAAARwACAAtFWEFNUExFLk9SRwAESFRUUAAPd3d3LmV4YW1wbGUub3JnAAAAAV5ePYIKABEAEDpczoDyER1jscz0RWkThCMAAAAKAAAARwACAAtFWEFNUExFLk9SRwAESFRUUAAPd3d3LmV4YW1wbGUub3JnAAAAAV5ePYIKABcAELP27YfH0Th5rD+GtJkQmXQAAAAK"
	ktutilbytes, err := base64.StdEncoding.DecodeString(ktutilb64)
	if err != nil {
		t.Errorf("Could not parse b64 ktutil keytab: %s", err)
	}
	ktutil := new(Keytab)
	err = ktutil.Unmarshal(ktutilbytes)
	if err != nil {
		t.Errorf("Could not load ktutil-generated keytab: %s", err)
	}

	// Generate the same keytab with gokrb5
	var ts time.Time = ktutil.Entries[0].Timestamp
	var encTypes []int32 = []int32{
		etypeID.AES256_CTS_HMAC_SHA1_96,
		etypeID.AES128_CTS_HMAC_SHA1_96,
		etypeID.RC4_HMAC,
	}

	kt := New()
	for _, et := range encTypes {
		err = kt.AddEntry("HTTP/www.example.org", "EXAMPLE.ORG", "hello456", ts, 10, et)
		if err != nil {
			t.Errorf("Error adding entry to keytab: %s", err)
		}
	}
	generated, err := kt.Marshal()
	if err != nil {
		t.Errorf("Error marshalling generated keytab: %s", err)
	}

	// Compare content
	assert.Equal(t, generated, ktutilbytes, "Service keytab doesn't match ktutil keytab")
}

func TestKeytab_GetEncryptionKey(t *testing.T) {
	princ := "HTTP/princ.test.gokrb5"
	realm := "TEST.GOKRB5"

	kt := New()
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(100, 0), 1, 18)
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(200, 0), 2, 18)
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(300, 0), 3, 18)
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(400, 0), 4, 18)
	kt.AddEntry(princ, realm, "abcdefg", time.Unix(350, 0), 5, 18)
	kt.AddEntry("HTTP/other.test.gokrb5", realm, "abcdefg", time.Unix(500, 0), 5, 18)

	pn := types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, princ)

	_, kvno, err := kt.GetEncryptionKey(pn, realm, 0, 18)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, 5, kvno)
	_, kvno, err = kt.GetEncryptionKey(pn, realm, 3, 18)
	if err != nil {
		t.Error(err)
	}
	assert.Equal(t, 3, kvno)
}

func TestGetEntryMITSemantics(t *testing.T) {
	p := Principal{Realm: "EXAMPLE.ORG", Components: []string{"HTTP", "host.example.org"}, NameType: nametype.KRB_NT_SRV_HST}
	otherType := p
	otherType.NameType = nametype.KRB_NT_PRINCIPAL
	kt := New()
	kt.Entries = []Entry{
		{Principal: otherType, Timestamp: time.Unix(400, 0), KVNO: 4, Key: types.EncryptionKey{KeyType: 17, KeyValue: []byte{4}}},
		{Principal: otherType, Timestamp: time.Unix(300, 0), KVNO: 5, Key: types.EncryptionKey{KeyType: 18, KeyValue: []byte{5}}},
		{Principal: p, Timestamp: time.Unix(500, 0), KVNO: 5, Key: types.EncryptionKey{KeyType: 18, KeyValue: []byte{6}}},
		{Principal: Principal{Realm: "OTHER.ORG", Components: p.Components}, Timestamp: time.Unix(600, 0), KVNO: 6, Key: types.EncryptionKey{KeyType: 18, KeyValue: []byte{7}}},
	}

	entry, err := kt.GetEntry(p, 0, 18)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(5), entry.KVNO, "highest KVNO should win over timestamp")
	assert.Equal(t, []byte{6}, entry.Key.KeyValue, "newest timestamp should break a KVNO tie")

	entry, err = kt.GetEntry(p, 4, 17)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, otherType.NameType, entry.Principal.NameType, "principal name type should be ignored")

	entry, err = kt.GetEntry(p, 0, 0)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(5), entry.KVNO, "etype zero should match any enctype")

	anyRealm := p
	anyRealm.Realm = ""
	entry, err = kt.GetEntry(anyRealm, 0, 18)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, "OTHER.ORG", entry.Principal.Realm)
	assert.Equal(t, uint32(6), entry.KVNO)
}

func TestGetEntryKVNO8Fallback(t *testing.T) {
	b, err := hex.DecodeString(testdata.KEYTAB_NO_KVNO32_TRAILER)
	if err != nil {
		t.Fatal(err)
	}
	kt := New()
	if err := kt.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	p := kt.Entries[0].Principal

	entry, err := kt.GetEntry(p, 300, 18)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(44), entry.KVNO)

	kt.Entries[0].kvno32Present = true
	_, err = kt.GetEntry(p, 300, 18)
	assert.ErrorIs(t, err, ErrKVNONotFound)

	kt.Entries = append(kt.Entries, Entry{
		Principal:     p,
		Timestamp:     time.Unix(1, 0),
		KVNO:          300,
		Key:           types.EncryptionKey{KeyType: 18, KeyValue: []byte{1}},
		kvno32Present: true,
	})
	entry, err = kt.GetEntry(p, 300, 18)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(300), entry.KVNO, "exact KVNO should take precedence over fallback")
}

func TestGetEntryErrors(t *testing.T) {
	p := Principal{Realm: "EXAMPLE.ORG", Components: []string{"user"}}
	kt := New()
	kt.Entries = []Entry{{Principal: p, KVNO: 1, Key: types.EncryptionKey{KeyType: 18, KeyValue: []byte{1}}}}

	_, err := kt.GetEntry(Principal{Realm: p.Realm, Components: []string{"missing"}}, 0, 18)
	assert.ErrorIs(t, err, ErrNotFound)
	assert.False(t, errors.Is(err, ErrKVNONotFound))

	_, err = kt.GetEntry(p, 2, 18)
	assert.ErrorIs(t, err, ErrKVNONotFound)

	_, err = kt.GetEntry(p, 0, 17)
	assert.ErrorIs(t, err, ErrNotFound)
}

func TestAddEntryHighKVNO(t *testing.T) {
	kt := New()
	if err := kt.AddEntry("user", "EXAMPLE.ORG", "password", time.Unix(1700000000, 0), 300, etypeID.AES128_CTS_HMAC_SHA1_96); err != nil {
		t.Fatal(err)
	}
	b, err := kt.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reparsed := New()
	if err := reparsed.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(300), reparsed.Entries[0].KVNO)
	kvno8Offset := 6 + 2 + 2 + len(kt.Entries[0].Principal.Realm) + 4 + 4
	for _, component := range kt.Entries[0].Principal.Components {
		kvno8Offset += 2 + len(component)
	}
	assert.Equal(t, byte(44), b[kvno8Offset], "the 8-bit field should contain the low KVNO byte")
	assert.Contains(t, reparsed.Entries[0].String(), " 300 ")
}

func TestPrincipalParseAndString(t *testing.T) {
	tests := map[string]struct {
		expected Principal
		output   string
	}{
		`HTTP/host.example.org@EXAMPLE.ORG`: {
			expected: Principal{Realm: "EXAMPLE.ORG", Components: []string{"HTTP", "host.example.org"}, NameType: nametype.KRB_NT_PRINCIPAL},
			output:   `HTTP/host.example.org@EXAMPLE.ORG`,
		},
		`svc\/name/host\@name@REALM\/NAME`: {
			expected: Principal{Realm: "REALM/NAME", Components: []string{"svc/name", "host@name"}, NameType: nametype.KRB_NT_PRINCIPAL},
			output:   `svc\/name/host\@name@REALM\/NAME`,
		},
		`user@corp.example@EXAMPLE.ORG`: {
			expected: Principal{Realm: "EXAMPLE.ORG", Components: []string{"user@corp.example"}, NameType: nametype.KRB_NT_ENTERPRISE},
			output:   `user\@corp.example@EXAMPLE.ORG`,
		},
		"line\\n/tab\\t/back\\b/nul\\0@REALM": {
			expected: Principal{Realm: "REALM", Components: []string{"line\n", "tab\t", "back\b", "nul\x00"}, NameType: nametype.KRB_NT_PRINCIPAL},
			output:   "line\\n/tab\\t/back\\b/nul\\0@REALM",
		},
	}
	for input, test := range tests {
		t.Run(input, func(t *testing.T) {
			parsed, err := ParsePrincipal(input)
			if err != nil {
				t.Fatal(err)
			}
			assert.Equal(t, test.expected, parsed)
			assert.Equal(t, test.output, parsed.String())
		})
	}

	for _, input := range []string{"", "/host@REALM", "user@", `user\`, "user@ONE@TWO@THREE", "user@REALM/EXTRA"} {
		t.Run("invalid "+input, func(t *testing.T) {
			_, err := ParsePrincipal(input)
			assert.Error(t, err)
		})
	}
}

func TestVersionAndPrincipals(t *testing.T) {
	p1 := Principal{Realm: "EXAMPLE.ORG", Components: []string{"one"}, NameType: 1}
	p1OtherType := p1
	p1OtherType.NameType = 10
	p2 := Principal{Realm: "EXAMPLE.ORG", Components: []string{"two"}, NameType: 1}
	kt := New()
	kt.Entries = []Entry{{Principal: p1}, {Principal: p1OtherType}, {Principal: p2}}

	assert.Equal(t, uint8(2), kt.Version())
	principals := kt.Principals()
	assert.Equal(t, []Principal{p1, p2}, principals)
	principals[0].Components[0] = "changed"
	assert.Equal(t, "one", kt.Entries[0].Principal.Components[0], "Principals should return defensive component copies")
}

func TestETypesForPrincipal(t *testing.T) {
	kt := New()
	p := Principal{Realm: "EXAMPLE.ORG", Components: []string{"user"}, NameType: nametype.KRB_NT_PRINCIPAL}
	other := Principal{Realm: "OTHER.ORG", Components: []string{"user"}, NameType: nametype.KRB_NT_PRINCIPAL}
	assert.NoError(t, kt.AddKey(p, 1, types.EncryptionKey{KeyType: 17, KeyValue: make([]byte, 16)}, time.Now()))
	assert.NoError(t, kt.AddKey(p, 2, types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}, time.Now()))
	assert.NoError(t, kt.AddKey(p, 3, types.EncryptionKey{KeyType: 17, KeyValue: make([]byte, 16)}, time.Now()))
	assert.NoError(t, kt.AddKey(other, 1, types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}, time.Now()))
	assert.Equal(t, []int32{17, 18}, kt.ETypesForPrincipal(p))
}

func TestAddKeyAndEntryWithSalt(t *testing.T) {
	p := Principal{Realm: "TEST.GOKRB5", Components: []string{"host", "host.test.gokrb5"}, NameType: nametype.KRB_NT_SRV_HST}
	key, err := hex.DecodeString("07b6b34bb7a9a1ed7cd964f21c09f7afcf77757dddd29e8e5ab4de2f2a8ea92e")
	if err != nil {
		t.Fatal(err)
	}
	kt := New()
	if err := kt.AddKey(p, 1, types.EncryptionKey{KeyType: 18, KeyValue: key}, time.Unix(1700000000, 0)); err != nil {
		t.Fatal(err)
	}
	p.Components[0] = "changed"
	key[0] = 0
	assert.Equal(t, "host", kt.Entries[0].Principal.Components[0])
	assert.Equal(t, byte(0x07), kt.Entries[0].Key.KeyValue[0])

	derived := New()
	err = derived.AddEntryWithSalt("host/host.test.gokrb5", "TEST.GOKRB5", "passwordvalue", "TEST.GOKRB5hosthost.test.gokrb5", "", time.Unix(1700000000, 0), 1, 18)
	if err != nil {
		t.Fatal(err)
	}
	etype, err := crypto.GetEtype(18)
	if err != nil {
		t.Fatal(err)
	}
	expected, err := etype.StringToKey("passwordvalue", "TEST.GOKRB5hosthost.test.gokrb5", "00001000")
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, derived.Entries[0].Key.KeyValue)
	assert.Equal(t, kt.Entries[0].Key.KeyValue, derived.Entries[0].Key.KeyValue, "explicit salt derivation should match the MIT fixture")
	marshaled, err := derived.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := hex.DecodeString(testdata.KEYTAB_AD_HOST_SALT)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, fixture, marshaled)

	assert.Error(t, kt.AddKey(Principal{}, 1, types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}, time.Time{}))
	assert.Error(t, kt.AddKey(Principal{Realm: "EXAMPLE.ORG", Components: []string{""}}, 1, types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 32)}, time.Time{}))
	assert.Error(t, kt.AddKey(p, 1, types.EncryptionKey{KeyType: 999, KeyValue: make([]byte, 32)}, time.Time{}))
	assert.Error(t, kt.AddKey(p, 1, types.EncryptionKey{KeyType: 18, KeyValue: make([]byte, 16)}, time.Time{}))
	assert.Error(t, derived.AddEntryWithSalt("user", "EXAMPLE.ORG", "password", "salt", "invalid", time.Time{}, 1, 18))
}

func TestRemoveAndMerge(t *testing.T) {
	p := Principal{Realm: "EXAMPLE.ORG", Components: []string{"user"}, NameType: nametype.KRB_NT_PRINCIPAL}
	other := Principal{Realm: "EXAMPLE.ORG", Components: []string{"other"}, NameType: nametype.KRB_NT_PRINCIPAL}
	entry := func(principal Principal, kvno uint32, etype int32, value byte) Entry {
		return Entry{Principal: principal, KVNO: kvno, Key: types.EncryptionKey{KeyType: etype, KeyValue: []byte{value}}}
	}

	kt := New()
	kt.Entries = []Entry{entry(p, 1, 17, 1), entry(p, 1, 18, 2), entry(p, 2, 17, 3), entry(p, 3, 17, 4), entry(other, 1, 17, 5)}
	assert.Equal(t, 1, kt.RemoveEntry(p, 1, 17))
	assert.Equal(t, 2, kt.RemoveOldKVNO(p, 1))
	assert.Equal(t, []Entry{entry(p, 3, 17, 4), entry(other, 1, 17, 5)}, kt.Entries)
	assert.Equal(t, 1, kt.RemovePrincipal(other))

	otherKT := New()
	pOtherType := p
	pOtherType.NameType = nametype.KRB_NT_ENTERPRISE
	otherKT.Entries = []Entry{entry(p, 3, 17, 4), entry(pOtherType, 3, 17, 4), entry(p, 4, 18, 6)}
	assert.Equal(t, 2, kt.Merge(otherKT))
	assert.Len(t, kt.Entries, 3)
	otherKT.Entries[2].Key.KeyValue[0] = 9
	assert.Equal(t, byte(6), kt.Entries[2].Key.KeyValue[0])
	assert.Equal(t, 3, kt.RemoveEntry(p, 0, 0), "zero kvno and enctype should remove every matching entry")
	assert.Empty(t, kt.Entries)
}
