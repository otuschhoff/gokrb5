package types

import (
	"fmt"

	"github.com/jcmturner/gofork/encoding/asn1"
)

// unmarshalASN1Prefix preserves the legacy decoders' acceptance of trailing data.
func unmarshalASN1Prefix(b []byte, dst any) error {
	if _, err := asn1.Unmarshal(b, dst); err != nil {
		return fmt.Errorf("decode ASN.1 into %T: %w", dst, err)
	}
	return nil
}
