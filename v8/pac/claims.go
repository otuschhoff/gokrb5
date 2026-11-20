package pac

import (
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/jcmturner/rpc/v2/mstypes"
	"golang.org/x/net/http2/hpack"

	"github.com/otuschhoff/gokrb5/v8/pac/internal/ndr"
)

// decodeClaimsSet decodes the ClaimsSet carried by ClaimsSetMetadata.
//
// The logic mirrors mstypes.ClaimsSetMetadata.ClaimsSet, distributed under the
// repository's Apache-2.0 license, but decodes with the bounded PAC-internal
// NDR decoder: the upstream decoder allocates slices directly from untrusted
// wire counts, which permits a small malformed PAC to terminate the process
// through memory exhaustion.
func decodeClaimsSet(m *mstypes.ClaimsSetMetadata) (mstypes.ClaimsSet, error) {
	var c mstypes.ClaimsSet
	if len(m.ClaimsSetBytes) < 1 {
		return c, errors.New("no bytes available for ClaimsSet")
	}
	switch m.CompressionFormat {
	case mstypes.CompressionFormatLZNT1:
		return c, fmt.Errorf("ClaimsSet compressed, format LZNT1 not currently supported: %s",
			hex.EncodeToString(m.ClaimsSetBytes))
	case mstypes.CompressionFormatXPress:
		return c, fmt.Errorf("ClaimsSet compressed, format XPress not currently supported: %s",
			hex.EncodeToString(m.ClaimsSetBytes))
	case mstypes.CompressionFormatXPressHuff:
		buff := new(bytes.Buffer)
		if _, err := hpack.HuffmanDecode(buff, m.ClaimsSetBytes); err != nil {
			return c, fmt.Errorf("error deflating: %w", err)
		}
		m.ClaimsSetBytes = buff.Bytes()
	}
	if err := ndr.NewDecoder(bytes.NewReader(m.ClaimsSetBytes)).Decode(&c); err != nil {
		return c, fmt.Errorf("error decoding ClaimsSet: %w", err)
	}
	return c, nil
}
