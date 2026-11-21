// Package msflags provides Microsoft Kerberos extension flags and values.
package msflags

// APOptions are the little-endian KERB-AD-AUTH-DATA-AP-OPTIONS flags.
type APOptions uint32

//revive:disable:var-naming Preserve published MS-KILE AP-OPTIONS identifiers.
const (
	// KERB_AP_OPTIONS_CBT is the channel-bindings AP-OPTIONS bit (MS-KILE 2.2.6).
	KERB_AP_OPTIONS_CBT APOptions = 0x00004000
	// KERB_AP_OPTIONS_UNVERIFIED_TARGET_NAME permits an unverified target name in AP-OPTIONS (MS-KILE 2.2.6).
	KERB_AP_OPTIONS_UNVERIFIED_TARGET_NAME APOptions = 0x00008000
)

//revive:enable:var-naming

// SupportedEncTypes is the little-endian MS-KILE supported encryption types mask.
type SupportedEncTypes uint32

// SupportedEncTypes bits of the msDS-SupportedEncryptionTypes bitmask (MS-ADA2 2.324).
const (
	// SupportedEncTypeDESCBCRC is the DES-CBC-CRC bit of the msDS-SupportedEncryptionTypes bitmask.
	SupportedEncTypeDESCBCRC SupportedEncTypes = 0x00000001
	// SupportedEncTypeDESCBCMD5 is the DES-CBC-MD5 bit of the msDS-SupportedEncryptionTypes bitmask.
	SupportedEncTypeDESCBCMD5                 SupportedEncTypes = 0x00000002
	SupportedEncTypeRC4HMAC                   SupportedEncTypes = 0x00000004
	SupportedEncTypeAES128CTSHMACSHA196       SupportedEncTypes = 0x00000008
	SupportedEncTypeAES256CTSHMACSHA196       SupportedEncTypes = 0x00000010
	SupportedEncTypeAES256CTSHMACSHA196SK     SupportedEncTypes = 0x00000020
	SupportedEncTypeAES128CTSHMACSHA256128    SupportedEncTypes = 0x00000040
	SupportedEncTypeAES256CTSHMACSHA384192    SupportedEncTypes = 0x00000080
	SupportedEncTypeFAST                      SupportedEncTypes = 0x00010000
	SupportedEncTypeCompoundIdentity          SupportedEncTypes = 0x00020000
	SupportedEncTypeClaims                    SupportedEncTypes = 0x00040000
	SupportedEncTypeResourceSIDCompressionOff SupportedEncTypes = 0x00080000
)

// Names used by the MS-KILE Supported Encryption Types Bit Flags table.
//
//revive:disable:var-naming Preserve published aliases for the MS-KILE flag names.
const (
	DES_CBC_CRC                       = SupportedEncTypeDESCBCRC
	DES_CBC_MD5                       = SupportedEncTypeDESCBCMD5
	RC4_HMAC                          = SupportedEncTypeRC4HMAC
	AES128_CTS_HMAC_SHA1_96           = SupportedEncTypeAES128CTSHMACSHA196
	AES256_CTS_HMAC_SHA1_96           = SupportedEncTypeAES256CTSHMACSHA196
	AES256_CTS_HMAC_SHA1_96_SK        = SupportedEncTypeAES256CTSHMACSHA196SK
	AES128_CTS_HMAC_SHA256_128        = SupportedEncTypeAES128CTSHMACSHA256128
	AES256_CTS_HMAC_SHA384_192        = SupportedEncTypeAES256CTSHMACSHA384192
	FAST_SUPPORTED                    = SupportedEncTypeFAST
	COMPOUND_IDENTITY_SUPPORTED       = SupportedEncTypeCompoundIdentity
	CLAIMS_SUPPORTED                  = SupportedEncTypeClaims
	RESOURCE_SID_COMPRESSION_DISABLED = SupportedEncTypeResourceSIDCompressionOff
)

//revive:enable:var-naming

// KerbErrorDataType identifies the payload carried by KERB-ERROR-DATA.
type KerbErrorDataType int32

//revive:disable:var-naming Preserve published MS-KILE error data identifiers.
const (
	// KERB_AP_ERR_TYPE_SKEW_RECOVERY identifies KERB-ERROR-DATA carrying clock-skew recovery information.
	KERB_AP_ERR_TYPE_SKEW_RECOVERY KerbErrorDataType = 2
	// KERB_ERR_TYPE_EXTENDED identifies KERB-ERROR-DATA carrying an extended error.
	KERB_ERR_TYPE_EXTENDED KerbErrorDataType = 3
)

//revive:enable:var-naming

// TokenInfoFlags identify the kind of LSAP token information.
type TokenInfoFlags uint32

// TokenInfoFlags selecting LSAP_TOKEN_INFO_INTEGRITY content (MS-KILE 2.2.4).
const (
	// TokenInfoFull requests full token information without filtering (LSAP_TOKEN_INFO_INTEGRITY).
	TokenInfoFull TokenInfoFlags = 0
	// TokenInfoUACRestricted requests UAC-restricted token information (LSAP_TOKEN_INFO_INTEGRITY).
	TokenInfoUACRestricted TokenInfoFlags = 1
	//revive:disable-next-line:var-naming Preserve the published MS-KILE token flag alias.
	UAC_RESTRICTED TokenInfoFlags = TokenInfoUACRestricted
)

// TokenIntegrityLevel identifies a Windows process integrity level.
type TokenIntegrityLevel uint32

// TokenIntegrityLevel values for LSAP_TOKEN_INFO_INTEGRITY (MS-KILE 2.2.4).
const (
	// TokenILUntrusted is the untrusted token integrity level (LSAP_TOKEN_INFO_INTEGRITY).
	TokenILUntrusted TokenIntegrityLevel = 0x00000000
	// TokenILLow is the low token integrity level (LSAP_TOKEN_INFO_INTEGRITY).
	TokenILLow       TokenIntegrityLevel = 0x00001000
	TokenILMedium    TokenIntegrityLevel = 0x00002000
	TokenILHigh      TokenIntegrityLevel = 0x00003000
	TokenILSystem    TokenIntegrityLevel = 0x00004000
	TokenILProtected TokenIntegrityLevel = 0x00005000
)

// KerbExtErrorFlagStrongCredentials marks the KERB-EXT-ERROR as supporting strong credentials.
// KERB-EXT-ERROR flags.
const KerbExtErrorFlagStrongCredentials uint32 = 0x00000001

// KerbADRestrictionTypeTokenIntegrity is the only currently defined restriction type.
const KerbADRestrictionTypeTokenIntegrity int32 = 0
