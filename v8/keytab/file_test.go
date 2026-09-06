package keytab

import (
	"bytes"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/otuschhoff/gokrb5/v8/config"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func testEntry(kvno uint32) Entry {
	return Entry{
		Principal: Principal{Realm: "EXAMPLE.ORG", Components: []string{"user"}, NameType: 1},
		Timestamp: time.Unix(1700000000+int64(kvno), 0),
		KVNO:      kvno,
		Key:       types.EncryptionKey{KeyType: 17, KeyValue: bytes.Repeat([]byte{byte(kvno)}, 16)},
	}
}

func setEnv(t *testing.T, key, value string) {
	t.Helper()
	previous, present := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if present {
			_ = os.Setenv(key, previous)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func TestWriteFileAtomicAndMode0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "service.keytab")
	if err := os.WriteFile(path, []byte("old"), 0644); err != nil {
		t.Fatal(err)
	}
	kt := New()
	kt.Entries = []Entry{testEntry(1)}
	if err := kt.WriteFile("WRFILE:" + path); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	}
	loaded, err := Load("FILE:" + path)
	if err != nil {
		t.Fatal(err)
	}
	if assert.Len(t, loaded.Entries, 1) {
		assert.Equal(t, kt.Entries[0].Principal, loaded.Entries[0].Principal)
		assert.Equal(t, kt.Entries[0].Timestamp, loaded.Entries[0].Timestamp)
		assert.Equal(t, kt.Entries[0].KVNO, loaded.Entries[0].KVNO)
		assert.Equal(t, kt.Entries[0].Key, loaded.Entries[0].Key)
	}
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	assert.Len(t, files, 1, "atomic write should not leave a temporary file")
}

func TestRead(t *testing.T) {
	b, err := hex.DecodeString(testdata.KEYTAB_KTUTIL_KVNO_300)
	if err != nil {
		t.Fatal(err)
	}
	kt := New()
	if err := kt.Read(bytes.NewReader(b)); err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(300), kt.Entries[0].KVNO)
}

func TestAppendToFileCreatesHeaderAndAppendsConcurrently(t *testing.T) {
	path := filepath.Join(t.TempDir(), "append.keytab")
	const writers = 32
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 1; i <= writers; i++ {
		entry := testEntry(uint32(i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			errs <- AppendToFile(path, entry)
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, []byte{5, 2}, b[:2])
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if assert.Len(t, loaded.Entries, writers) {
		kvnos := make([]int, 0, writers)
		for _, entry := range loaded.Entries {
			kvnos = append(kvnos, int(entry.KVNO))
		}
		sort.Ints(kvnos)
		for i, kvno := range kvnos {
			assert.Equal(t, i+1, kvno)
		}
	}
}

func TestAppendToFileRejectsInvalidExistingFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.keytab")
	original := []byte("not a keytab")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	assert.Error(t, AppendToFile(path, testEntry(1)))
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, original, after)
}

func TestAppendToFilePreservesV1AndHighKVNO(t *testing.T) {
	data, err := hex.DecodeString(testdata.KEYTAB_V1_LITTLE_ENDIAN)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "v1.keytab")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	if err := AppendToFile(path, testEntry(300)); err != nil {
		t.Fatal(err)
	}
	loaded, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint8(1), loaded.Version())
	if assert.Len(t, loaded.Entries, 2) {
		assert.Equal(t, uint32(300), loaded.Entries[1].KVNO)
	}
}

func TestResolveNameAndLoadDefault(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.keytab")
	envPath := filepath.Join(dir, "env.keytab")
	for i, path := range []string{configPath, envPath} {
		kt := New()
		kt.Entries = []Entry{testEntry(uint32(i + 1))}
		if err := kt.WriteFile(path); err != nil {
			t.Fatal(err)
		}
	}

	cfg := config.New()
	cfg.LibDefaults.DefaultKeytabName = "FILE:" + configPath
	setEnv(t, "KRB5_KTNAME", "")
	loaded, err := LoadDefault(cfg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(1), loaded.Entries[0].KVNO)
	setEnv(t, "KRB5_KTNAME", "WRFILE:"+envPath)
	loaded, err = LoadDefault(cfg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(2), loaded.Entries[0].KVNO)

	path, writable, err := ResolveName("WRFILE:"+dir+"/%{uid}/%{euid}/%{username}", nil)
	if err != nil {
		t.Fatal(err)
	}
	assert.True(t, writable)
	assert.NotContains(t, path, "%{")
	defaultPath, writable, err := ResolveName("", config.New())
	if err != nil {
		t.Fatal(err)
	}
	assert.False(t, writable)
	assert.Equal(t, "/etc/krb5.keytab", defaultPath)
	_, _, err = ResolveName("DIR:/tmp/keytab", nil)
	assert.Error(t, err)
}

func TestLoadDefaultClientResolutionOrder(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config-client.keytab")
	envPath := filepath.Join(dir, "env-client.keytab")
	for i, path := range []string{configPath, envPath} {
		kt := New()
		kt.Entries = []Entry{testEntry(uint32(i + 1))}
		if err := kt.WriteFile(path); err != nil {
			t.Fatal(err)
		}
	}
	cfg := config.New()
	cfg.LibDefaults.DefaultClientKeytabName = "FILE:" + configPath
	setEnv(t, "KRB5_CLIENT_KTNAME", "")
	loaded, err := LoadDefaultClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(1), loaded.Entries[0].KVNO)
	setEnv(t, "KRB5_CLIENT_KTNAME", "FILE:"+envPath)
	loaded, err = LoadDefaultClient(cfg)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, uint32(2), loaded.Entries[0].KVNO)
}

func TestFirstExistingClientKeytabName(t *testing.T) {
	dir := t.TempDir()
	missing := "FILE:" + filepath.Join(dir, "missing")
	existing := "FILE:" + filepath.Join(dir, "client.keytab")
	if err := os.WriteFile(strings.TrimPrefix(existing, "FILE:"), nil, 0600); err != nil {
		t.Fatal(err)
	}

	assert.Equal(t, existing, firstExistingKeytabName([]string{missing, existing}))
	assert.Equal(t, missing, firstExistingKeytabName([]string{missing, "FILE:" + filepath.Join(dir, "also-missing")}))
}
