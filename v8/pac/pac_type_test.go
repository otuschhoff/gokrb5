package pac

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"testing"

	"github.com/otuschhoff/gokrb5/v8/keytab"
	"github.com/otuschhoff/gokrb5/v8/test/testdata"
	"github.com/otuschhoff/gokrb5/v8/types"
	"github.com/stretchr/testify/assert"
)

func TestPACBoundsChecks(t *testing.T) {
	t.Run("impossible buffer count", func(t *testing.T) {
		b := make([]byte, 8)
		binary.LittleEndian.PutUint32(b, 1)
		var pac PACType
		if err := pac.Unmarshal(b); !errors.Is(err, ErrPACMalformed) {
			t.Fatalf("Unmarshal error = %v, want ErrPACMalformed", err)
		}
	})

	tests := []struct {
		name   string
		data   []byte
		buffer []InfoBuffer
	}{
		{"count mismatch", make([]byte, 40), []InfoBuffer{{Offset: 24, CBBufferSize: 1}}},
		{"misaligned", make([]byte, 40), []InfoBuffer{{Offset: 25, CBBufferSize: 1}}},
		{"inside header", make([]byte, 40), []InfoBuffer{{Offset: 16, CBBufferSize: 1}}},
		{"past end", make([]byte, 40), []InfoBuffer{{Offset: 32, CBBufferSize: 9}}},
		{"range overflow", make([]byte, 40), []InfoBuffer{{Offset: ^uint64(0) - 7, CBBufferSize: 16}}},
		{"overlap", make([]byte, 64), []InfoBuffer{{Offset: 40, CBBufferSize: 16}, {Offset: 48, CBBufferSize: 8}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pac := PACType{CBuffers: uint32(len(tt.buffer)), Buffers: tt.buffer, Data: tt.data}
			if tt.name == "count mismatch" {
				pac.CBuffers++
			}
			if err := pac.ProcessPACInfoBuffers(types.EncryptionKey{}, log.New(&bytes.Buffer{}, "", 0)); !errors.Is(err, ErrPACMalformed) {
				t.Fatalf("ProcessPACInfoBuffers error = %v, want ErrPACMalformed", err)
			}
		})
	}
}

func TestPACRejectsDuplicateValidationInfo(t *testing.T) {
	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	if err != nil {
		t.Fatal(err)
	}
	var original PACType
	if err := original.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	var buffers []pacBuffer
	var validation pacBuffer
	for _, info := range original.Buffers {
		payload := append([]byte(nil), original.Data[int(info.Offset):int(info.Offset)+int(info.CBBufferSize)]...)
		buffer := pacBuffer{typeID: info.ULType, data: payload}
		buffers = append(buffers, buffer)
		if info.ULType == infoTypeKerbValidationInfo {
			validation = buffer
		}
	}
	data, err := marshalPACBuffers(0, append(buffers, validation))
	if err != nil {
		t.Fatal(err)
	}
	var duplicate PACType
	if err := duplicate.Unmarshal(data); err != nil {
		t.Fatal(err)
	}
	err = duplicate.ProcessPACInfoBuffers(types.EncryptionKey{}, log.New(&bytes.Buffer{}, "", 0))
	if !errors.Is(err, ErrPACMalformed) {
		t.Fatalf("ProcessPACInfoBuffers error = %v, want ErrPACMalformed", err)
	}
}

func TestPACTypeVerify(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_AD_WIN2K_PAC)
	if err != nil {
		t.Fatalf("Test vector read error: %v", err)
	}
	var pac PACType
	err = pac.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}

	b, _ = hex.DecodeString(testdata.KEYTAB_SYSHTTP_TEST_GOKRB5)
	kt := keytab.New()
	kt.Unmarshal(b)
	pn, _ := types.ParseSPNString("sysHTTP")
	key, _, err := kt.GetEncryptionKey(pn, "TEST.GOKRB5", 2, 18)
	if err != nil {
		t.Fatalf("Error getting key: %v", err)
	}
	w := bytes.NewBufferString("")
	l := log.New(w, "", 0)
	err = pac.ProcessPACInfoBuffers(key, l)
	if err != nil {
		t.Fatalf("Processing reference pac error: %v", err)
	}

	pacInvalidServerSig := pac
	// Check the signature to force failure
	pacInvalidServerSig.ServerChecksum.Signature[0] ^= 0xFF
	pacInvalidNilKerbValidationInfo := pac
	pacInvalidNilKerbValidationInfo.KerbValidationInfo = nil
	pacInvalidNilServerSig := pac
	pacInvalidNilServerSig.ServerChecksum = nil
	pacInvalidNilKdcSig := pac
	pacInvalidNilKdcSig.KDCChecksum = nil
	pacInvalidClientInfo := pac
	pacInvalidClientInfo.ClientInfo = nil

	var pacs = []struct {
		pac PACType
	}{
		{pacInvalidServerSig},
		{pacInvalidNilKerbValidationInfo},
		{pacInvalidNilServerSig},
		{pacInvalidNilKdcSig},
		{pacInvalidClientInfo},
	}
	for i, s := range pacs {
		v, _ := s.pac.verify(key)
		assert.False(t, v, fmt.Sprintf("Validation should have failed for test %v", i))
	}

}
