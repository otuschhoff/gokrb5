package pac

import (
	"encoding/hex"
	"io"
	"log"
	"testing"

	"github.com/jcmturner/gokrb5/v8/test/testdata"
	"github.com/jcmturner/gokrb5/v8/types"
)

func FuzzPACUnmarshal(f *testing.F) {
	seeds := []string{
		testdata.MarshaledPAC_AuthorizationData_MS,
		testdata.MarshaledPAC_AuthorizationData_GOKRB5,
		testdata.MarshaledPAC_Kerb_Validation_Info_MS,
		testdata.MarshaledPAC_AD_WIN2K_PAC,
		testdata.MarshaledPAC_Kerb_Validation_Info,
		testdata.MarshaledPAC_Client_Info,
		testdata.MarshaledPAC_UPN_DNS_Info,
		testdata.MarshaledPAC_Server_Signature,
		testdata.MarshaledPAC_KDC_Signature,
		testdata.MarshaledPAC_Kerb_Validation_Info_Trust,
		testdata.MarshaledPAC_ClientClaimsInfoStr,
		testdata.MarshaledPAC_ClientClaimsInfoInt,
		testdata.MarshaledPAC_ClientClaimsInfoMulti,
		testdata.MarshaledPAC_ClientClaimsInfoMultiUint,
		testdata.MarshaledPAC_ClientClaimsInfoMultiStr,
		testdata.MarshaledPAC_ClientClaimsInfo_XPRESS_HUFF,
	}
	for _, seed := range seeds {
		b, err := hex.DecodeString(seed)
		if err != nil {
			f.Fatalf("invalid PAC seed: %v", err)
		}
		f.Add(b)
	}

	logger := log.New(io.Discard, "", 0)
	f.Fuzz(func(t *testing.T, b []byte) {
		var value PACType
		if err := value.Unmarshal(b); err != nil {
			return
		}
		_ = value.ProcessPACInfoBuffers(types.EncryptionKey{}, logger)
	})
}
