package pac

import (
	"encoding/hex"
	"strings"
	"testing"
	"time"

	"github.com/jcmturner/rpc/v2/mstypes"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/otuschhoff/gokrb5/v8/test/testdata"
)

func TestPAC_ClientInfo_Unmarshal(t *testing.T) {
	t.Parallel()
	b, err := hex.DecodeString(testdata.MarshaledPAC_Client_Info)
	if err != nil {
		t.Fatal("Could not decode test data hex string")
	}
	var k ClientInfo
	err = k.Unmarshal(b)
	if err != nil {
		t.Fatalf("Error unmarshaling test data: %v", err)
	}
	wantTime := time.Date(2017, 5, 6, 15, 53, 11, 0, time.UTC)
	assert.Equal(t, wantTime, k.ClientID.Time(), "Client ID time not as expected.")
	assert.Equal(t, uint16(18), k.NameLength, "Client name length not as expected")
	assert.Equal(t, "testuser1", k.Name, "Client name not as expected")
}

func TestClientInfoUnmarshalRejectsInvalidLength(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name    string
		wire    string
		wantErr string
	}{
		{
			name:    "short header",
			wire:    "010203040506070806",
			wantErr: "PAC is malformed: PAC_CLIENT_INFO is 9 bytes, want at least 10",
		},
		{
			name:    "odd length",
			wire:    "0102030405060708010041",
			wantErr: "PAC is malformed: invalid PAC_CLIENT_INFO name length 1",
		},
		{
			name:    "truncated name",
			wire:    "010203040506070804004100",
			wantErr: "PAC is malformed: invalid PAC_CLIENT_INFO name length 4",
		},
		{
			name:    "trailing bytes",
			wire:    "0102030405060708020041000000",
			wantErr: "PAC is malformed: invalid PAC_CLIENT_INFO name length 2",
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			data, err := hex.DecodeString(tt.wire)
			require.NoError(t, err)
			var info ClientInfo
			err = info.Unmarshal(data)
			require.ErrorIs(t, err, ErrPACMalformed)
			assert.EqualError(t, err, tt.wantErr)
		})
	}
}

func TestClientInfoWireEncoding(t *testing.T) {
	t.Parallel()

	clientID := mstypes.FileTime{LowDateTime: 0x04030201, HighDateTime: 0x08070605}
	for _, tt := range []struct {
		name       string
		account    string
		wire       string
		nameLength uint16
	}{
		{name: "empty name", account: "", wire: "01020304050607080000", nameLength: 0},
		{name: "surrogate pair", account: "A\U0001f600", wire: "0102030405060708060041003dd800de", nameLength: 6},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			want, err := hex.DecodeString(tt.wire)
			require.NoError(t, err)
			info := ClientInfo{ClientID: clientID, NameLength: 0, Name: tt.account}
			data, err := info.Marshal()
			require.NoError(t, err)
			assert.Equal(t, want, data)

			var decoded ClientInfo
			require.NoError(t, decoded.Unmarshal(want))
			assert.Equal(t, ClientInfo{ClientID: clientID, NameLength: tt.nameLength, Name: tt.account}, decoded)
		})
	}
}

func TestClientInfoMarshalNameLengthBoundary(t *testing.T) {
	t.Parallel()

	const maxNameUnits = 32767
	var info ClientInfo
	info.Name = strings.Repeat("x", maxNameUnits)
	data, err := info.Marshal()
	require.NoError(t, err)
	var decoded ClientInfo
	require.NoError(t, decoded.Unmarshal(data))
	assert.Equal(t, uint16(65534), decoded.NameLength)
	assert.Equal(t, info.Name, decoded.Name)

	info.Name += "x"
	data, err = info.Marshal()
	require.EqualError(t, err, "PAC_CLIENT_INFO name is too long")
	assert.Nil(t, data)
}
