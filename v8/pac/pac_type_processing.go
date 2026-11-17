package pac

import (
	"fmt"

	"github.com/otuschhoff/gokrb5/v8/types"
)

func (pac *PACType) processInfoBuffer(buf InfoBuffer, p []byte, credentialKey types.EncryptionKey) error {
	switch buf.ULType {
	case infoTypeKerbValidationInfo:
		return pac.processValidationInfo(p)
	case infoTypeCredentials:
		return pac.processCredentialsInfo(p, credentialKey)
	case infoTypePACServerSignatureData:
		return pac.processSignatureInfo(buf, p, &pac.ServerChecksum, "ServerChecksum")
	case infoTypePACKDCSignatureData:
		return pac.processSignatureInfo(buf, p, &pac.KDCChecksum, "KDCChecksum")
	case infoTypePACTicketChecksum:
		return pac.processSignatureInfo(buf, p, &pac.TicketChecksum, "TicketChecksum")
	case infoTypePACFullChecksum:
		return pac.processSignatureInfo(buf, p, &pac.FullChecksum, "FullChecksum")
	case infoTypePACClientInfo:
		return pac.processClientInfo(p)
	case infoTypeS4UDelegationInfo:
		return pac.processDelegationInfo(p)
	case infoTypeUPNDNSInfo:
		return pac.processUPNDNSInfo(p)
	case infoTypePACClientClaimsInfo:
		return pac.processClientClaimsInfo(p)
	case infoTypePACDeviceInfo:
		return pac.processDeviceInfo(p)
	case infoTypePACDeviceClaimsInfo:
		return pac.processDeviceClaimsInfo(p)
	case infoTypePACAttributesInfo:
		return pac.processAttributesInfo(p)
	case infoTypePACRequestor:
		return pac.processRequestorInfo(p)
	}
	return nil
}

func (pac *PACType) processValidationInfo(p []byte) error {
	if pac.KerbValidationInfo != nil {
		return fmt.Errorf("%w: duplicate KerbValidationInfo buffer", ErrPACMalformed)
	}
	var k KerbValidationInfo
	err := k.Unmarshal(p)
	if err != nil {
		return fmt.Errorf("error processing KerbValidationInfo: %w", err)
	}
	pac.KerbValidationInfo = &k
	return nil
}

func (pac *PACType) processCredentialsInfo(p []byte, credentialKey types.EncryptionKey) error {
	if len(credentialKey.KeyValue) == 0 {
		return nil
	}
	var credentials CredentialsInfo
	if err := credentials.Unmarshal(p, credentialKey); err != nil {
		return fmt.Errorf("error processing CredentialsInfo: %w", err)
	}
	pac.CredentialsInfo = &credentials
	return nil
}

func (pac *PACType) processSignatureInfo(buf InfoBuffer, p []byte, target **SignatureData, name string) error {
	if *target != nil {
		return fmt.Errorf("%w: duplicate %s buffer", ErrPACMalformed, name)
	}
	var k SignatureData
	zb, err := k.Unmarshal(p)
	if err != nil {
		return fmt.Errorf("error processing %s: %w", name, err)
	}
	copy(pac.ZeroSigData[buf.Offset:buf.Offset+uint64(buf.CBBufferSize)], zb)
	*target = &k
	return nil
}

func (pac *PACType) processClientInfo(p []byte) error {
	if pac.ClientInfo != nil {
		return fmt.Errorf("%w: duplicate ClientInfo buffer", ErrPACMalformed)
	}
	var k ClientInfo
	err := k.Unmarshal(p)
	if err != nil {
		return fmt.Errorf("error processing ClientInfo: %w", err)
	}
	pac.ClientInfo = &k
	return nil
}

func (pac *PACType) processDelegationInfo(p []byte) error {
	var k S4UDelegationInfo
	err := k.Unmarshal(p)
	if err != nil {
		return fmt.Errorf("error processing S4U_DelegationInfo: %w", err)
	}
	pac.S4UDelegationInfo = &k
	return nil
}

func (pac *PACType) processUPNDNSInfo(p []byte) error {
	var k UPNDNSInfo
	err := k.Unmarshal(p)
	if err != nil {
		return fmt.Errorf("error processing UPN_DNSInfo: %w", err)
	}
	pac.UPNDNSInfo = &k
	return nil
}

func (pac *PACType) processClientClaimsInfo(p []byte) error {
	if len(p) == 0 {
		return nil
	}
	var k ClientClaimsInfo
	err := k.Unmarshal(p)
	if err != nil {
		return fmt.Errorf("error processing ClientClaimsInfo: %w", err)
	}
	pac.ClientClaimsInfo = &k
	return nil
}

func (pac *PACType) processDeviceInfo(p []byte) error {
	var k DeviceInfo
	err := k.Unmarshal(p)
	if err != nil {
		return fmt.Errorf("error processing DeviceInfo: %w", err)
	}
	pac.DeviceInfo = &k
	return nil
}

func (pac *PACType) processDeviceClaimsInfo(p []byte) error {
	var k DeviceClaimsInfo
	err := k.Unmarshal(p)
	if err != nil {
		return fmt.Errorf("error processing DeviceClaimsInfo: %w", err)
	}
	pac.DeviceClaimsInfo = &k
	return nil
}

func (pac *PACType) processAttributesInfo(p []byte) error {
	if pac.AttributesInfo != nil {
		return fmt.Errorf("%w: duplicate AttributesInfo buffer", ErrPACMalformed)
	}
	var k AttributesInfo
	if err := k.Unmarshal(p); err != nil {
		return fmt.Errorf("error processing AttributesInfo: %w", err)
	}
	pac.AttributesInfo = &k
	return nil
}

func (pac *PACType) processRequestorInfo(p []byte) error {
	if pac.Requestor != nil {
		return fmt.Errorf("%w: duplicate Requestor buffer", ErrPACMalformed)
	}
	var k Requestor
	if err := k.Unmarshal(p); err != nil {
		return fmt.Errorf("error processing Requestor: %w", err)
	}
	pac.Requestor = &k
	return nil
}
