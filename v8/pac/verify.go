package pac

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/otuschhoff/gokrb5/v8/crypto"
	"github.com/otuschhoff/gokrb5/v8/iana/keyusage"
	"github.com/otuschhoff/gokrb5/v8/types"
)

// VerifyOptions supplies ticket and KDC context for PAC validation.
type VerifyOptions struct {
	KDCKey                *types.EncryptionKey
	TicketData            []byte
	ExpectedClientName    string
	ExpectedAuthTime      *time.Time
	RequireFullChecksum   bool
	RequireTicketChecksum bool
}

// Verify validates PAC signatures and binds embedded identity data together.
func (pac *PACType) Verify(serverKey types.EncryptionKey, options VerifyOptions) error {
	if pac.KerbValidationInfo == nil {
		return errors.New("PAC Info Buffers does not contain a KerbValidationInfo")
	}
	if pac.ServerChecksum == nil {
		return errors.New("PAC Info Buffers does not contain a ServerChecksum")
	}
	if pac.KDCChecksum == nil {
		return errors.New("PAC Info Buffers does not contain a KDCChecksum")
	}
	if pac.ClientInfo == nil {
		return errors.New("PAC Info Buffers does not contain a ClientInfo")
	}
	serverInput, err := pac.checksumInput(false)
	if err != nil {
		return err
	}
	if err := verifyPACChecksum(pac.ServerChecksum, serverKey, serverInput, "service"); err != nil {
		return err
	}
	if options.KDCKey != nil {
		if err := verifyPACChecksum(pac.KDCChecksum, *options.KDCKey, pac.ServerChecksum.Signature, "KDC"); err != nil {
			return err
		}
		if pac.FullChecksum != nil {
			fullInput, err := pac.checksumInput(true)
			if err != nil {
				return err
			}
			if err := verifyPACChecksum(pac.FullChecksum, *options.KDCKey, fullInput, "full KDC"); err != nil {
				return err
			}
		} else if options.RequireFullChecksum {
			return errors.New("PAC Info Buffers does not contain a FullChecksum")
		}
		if len(options.TicketData) != 0 {
			if pac.TicketChecksum == nil {
				return errors.New("PAC Info Buffers does not contain a TicketChecksum")
			}
			if err := verifyPACChecksum(pac.TicketChecksum, *options.KDCKey, options.TicketData, "ticket"); err != nil {
				return err
			}
		} else if options.RequireTicketChecksum {
			return errors.New("PAC ticket checksum verification requires ticket data")
		}
	} else if options.RequireFullChecksum || options.RequireTicketChecksum {
		return errors.New("PAC KDC checksum verification requires a KDC key")
	}
	if options.ExpectedClientName != "" && !strings.EqualFold(pac.ClientInfo.Name, options.ExpectedClientName) {
		return fmt.Errorf("PAC client name %q does not match ticket client %q", pac.ClientInfo.Name, options.ExpectedClientName)
	}
	if options.ExpectedAuthTime != nil && pac.ClientInfo.ClientID.Time().Unix() != options.ExpectedAuthTime.UTC().Unix() {
		return fmt.Errorf("PAC client authentication time %s does not match ticket authentication time %s", pac.ClientInfo.ClientID.Time().UTC(), options.ExpectedAuthTime.UTC())
	}
	return pac.verifyIdentityBuffers()
}

func (pac *PACType) checksumInput(includeFull bool) ([]byte, error) {
	input := append([]byte(nil), pac.Data...)
	for _, typeID := range []uint32{infoTypePACServerSignatureData, infoTypePACKDCSignatureData} {
		if err := pac.zeroChecksum(input, typeID); err != nil {
			return nil, err
		}
	}
	if includeFull {
		if err := pac.zeroChecksum(input, infoTypePACFullChecksum); err != nil {
			return nil, err
		}
	}
	return input, nil
}

func (pac *PACType) zeroChecksum(data []byte, typeID uint32) error {
	found := false
	for _, buffer := range pac.Buffers {
		if buffer.ULType != typeID {
			continue
		}
		if found {
			return fmt.Errorf("%w: duplicate checksum buffer type %d", ErrPACMalformed, typeID)
		}
		found = true
		end := buffer.Offset + uint64(buffer.CBBufferSize)
		if buffer.CBBufferSize < 4 || end < buffer.Offset || end > uint64(len(data)) {
			return fmt.Errorf("%w: invalid checksum buffer type %d", ErrPACMalformed, typeID)
		}
		for i := int(buffer.Offset) + 4; i < int(end); i++ {
			data[i] = 0
		}
	}
	if !found {
		return fmt.Errorf("PAC checksum buffer type %d is missing", typeID)
	}
	return nil
}

func verifyPACChecksum(signature *SignatureData, key types.EncryptionKey, data []byte, name string) error {
	etype, err := crypto.GetChksumEtype(int32(signature.SignatureType))
	if err != nil {
		return err
	}
	if !etype.VerifyChecksum(key.KeyValue, data, signature.Signature, keyusage.KERB_NON_KERB_CKSUM_SALT) {
		return fmt.Errorf("PAC %s checksum verification failed", name)
	}
	return nil
}

func (pac *PACType) verifyIdentityBuffers() error {
	expectedSID := fmt.Sprintf("%s-%d", pac.KerbValidationInfo.LogonDomainID.String(), pac.KerbValidationInfo.UserID)
	if pac.Requestor != nil && pac.Requestor.SID.String() != expectedSID {
		return fmt.Errorf("PAC requestor SID %s does not match user SID %s", pac.Requestor.SID.String(), expectedSID)
	}
	if pac.UPNDNSInfo != nil && pac.UPNDNSInfo.Flags&UPNDNSInfoFlagExtended != 0 {
		if pac.UPNDNSInfo.ObjectSID == nil || pac.UPNDNSInfo.ObjectSID.String() != expectedSID {
			return fmt.Errorf("PAC UPN/DNS SID does not match user SID %s", expectedSID)
		}
		if !strings.EqualFold(pac.UPNDNSInfo.SAMAccountName, pac.KerbValidationInfo.EffectiveName.Value) {
			return fmt.Errorf("PAC SAM account name %q does not match effective name %q", pac.UPNDNSInfo.SAMAccountName, pac.KerbValidationInfo.EffectiveName.Value)
		}
	}
	return nil
}
