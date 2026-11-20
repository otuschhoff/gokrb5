package types

// Reference: https://www.ietf.org/rfc/rfc4120.txt
// Section: 5.2.7
import (
	"fmt"
	"time"

	"github.com/jcmturner/gofork/encoding/asn1"

	"github.com/otuschhoff/gokrb5/v8/iana/patype"
)

// PAData implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.2.7
type PAData struct {
	PADataType  int32  `asn1:"explicit,tag:1"`
	PADataValue []byte `asn1:"explicit,tag:2"`
}

// PADataSequence implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.2.7
type PADataSequence []PAData

// MethodData implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.9.1
type MethodData []PAData

// PAEncTimestamp implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.2.7.2
type PAEncTimestamp EncryptedData

// PAEncTSEnc implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.2.7.2
type PAEncTSEnc struct {
	PATimestamp time.Time `asn1:"generalized,explicit,tag:0"`
	PAUSec      int       `asn1:"explicit,optional,tag:1"`
}

// Contains tests if a PADataSequence contains PA Data of a certain type.
func (pas *PADataSequence) Contains(patype int32) bool {
	if pas == nil {
		return false
	}
	for _, pa := range *pas {
		if pa.PADataType == patype {
			return true
		}
	}
	return false
}

// GetPAEncTSEncAsnMarshalled returns the bytes of a PAEncTSEnc.
func GetPAEncTSEncAsnMarshalled() ([]byte, error) {
	return GetPAEncTSEncAsnMarshalledAt(time.Now().UTC())
}

// GetPAEncTSEncAsnMarshalledAt returns the bytes of a PAEncTSEnc for t.
func GetPAEncTSEncAsnMarshalledAt(t time.Time) ([]byte, error) {
	t = t.UTC()
	p := PAEncTSEnc{
		PATimestamp: t,
		PAUSec:      microsecondOffset(t),
	}
	b, err := asn1.Marshal(p)
	if err != nil {
		return b, fmt.Errorf("error mashaling PAEncTSEnc: %w", err)
	}
	return b, nil
}

// ETypeInfoEntry implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.2.7.4
type ETypeInfoEntry struct {
	EType int32  `asn1:"explicit,tag:0"`
	Salt  []byte `asn1:"explicit,optional,tag:1"`
}

// ETypeInfo implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.2.7.4
type ETypeInfo []ETypeInfoEntry

// ETypeInfo2Entry implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.2.7.5
type ETypeInfo2Entry struct {
	EType     int32  `asn1:"explicit,tag:0"`
	Salt      string `asn1:"explicit,optional,generalstring,tag:1"`
	S2KParams []byte `asn1:"explicit,optional,tag:2"`
}

// ETypeInfo2 implements RFC 4120 types: https://tools.ietf.org/html/rfc4120#section-5.2.7.5
type ETypeInfo2 []ETypeInfo2Entry

// PAReqEncPARep PA Data Type
type PAReqEncPARep struct {
	ChksumType int32  `asn1:"explicit,tag:0"`
	Chksum     []byte `asn1:"explicit,tag:1"`
}

// Unmarshal bytes into the PAData
func (pa *PAData) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, pa)
}

// Unmarshal bytes into the PADataSequence
func (pas *PADataSequence) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, pas)
}

// Unmarshal bytes into the PAReqEncPARep
func (pa *PAReqEncPARep) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, pa)
}

// Unmarshal bytes into the PAEncTimestamp
func (pa *PAEncTimestamp) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, pa)
}

// Unmarshal bytes into the PAEncTSEnc
func (pa *PAEncTSEnc) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, pa)
}

// Unmarshal bytes into the ETypeInfo
func (a *ETypeInfo) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, a)
}

// Unmarshal bytes into the ETypeInfoEntry
func (a *ETypeInfoEntry) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, a)
}

// Unmarshal bytes into the ETypeInfo2
func (a *ETypeInfo2) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, a)
}

// Unmarshal bytes into the ETypeInfo2Entry
func (a *ETypeInfo2Entry) Unmarshal(b []byte) error {
	return unmarshalASN1Prefix(b, a)
}

// GetETypeInfo returns an ETypeInfo from the PAData.
func (pa *PAData) GetETypeInfo() (ETypeInfo, error) {
	var d ETypeInfo
	if pa.PADataType != patype.PA_ETYPE_INFO {
		return d, fmt.Errorf("PAData does not contain PA EType Info data. TypeID Expected: %v; Actual: %v",
			patype.PA_ETYPE_INFO, pa.PADataType)
	}
	err := d.Unmarshal(pa.PADataValue)
	return d, err
}

// GetETypeInfo2 returns an ETypeInfo2 from the PAData.
func (pa *PAData) GetETypeInfo2() (ETypeInfo2, error) {
	var d ETypeInfo2
	if pa.PADataType != patype.PA_ETYPE_INFO2 {
		return d, fmt.Errorf("PAData does not contain PA EType Info 2 data. TypeID Expected: %v; Actual: %v",
			patype.PA_ETYPE_INFO2, pa.PADataType)
	}
	err := d.Unmarshal(pa.PADataValue)
	return d, err
}
