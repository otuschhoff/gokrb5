# Design Spec: MS-KILE Compliance — Kerberos Protocol Extensions for Active Directory

**Status:** Design reference; implementation and remaining validation are tracked in
[the refactoring roadmap](refactoring.md).

**Scope:** `v8` module (`github.com/otuschhoff/gokrb5/v8`)

**Normative references:** Verify against the latest published revision before each phase.

| Reference | Title | Used for |
| --- | --- | --- |
| [MS-KILE] | Kerberos Protocol Extensions | Client (§3.2) and application-server (§3.4) behaviour, MS PA-DATA, authorization data, error data |
| [MS-PAC] | Privilege Attribute Certificate Data Structure | PAC buffers, signatures, validation rules |
| [MS-SFU] | Kerberos Protocol Extensions: Service for User and Constrained Delegation | S4U2self, S4U2proxy, resource-based constrained delegation |
| [MS-KKDCP] | Kerberos Key Distribution Center (KDC) Proxy Protocol | Kerberos over HTTPS |
| [MS-PKCA] | Public Key Cryptography for Initial Authentication (PKINIT) in Kerberos | PKINIT client behaviour against AD: certificate requirements, KDC certificate validation, DH/RSA modes, KDF agility, PAC credentials |
| [MS-SPNG] | SPNEGO Extension | mechListMIC and legacy KRB5 OID behaviour |
| [MS-NEGOEX] | SPNEGO Extended Negotiation (NEGOEX) Security Mechanism | GUID-based mechanism negotiation, metadata exchange, VERIFY binding inside SPNEGO |
| [MS-PKU2U] | Public Key Cryptography Based User-to-User Authentication | KDC-less certificate authentication between peers, carried by NEGOEX |
| RFC 4120, 4121, 4757, 4537, 3244, 6113, 6806, 4556, 4401, 8062, 8636, 8070, 5652 | IETF base specifications referenced by MS-KILE, MS-PKCA, MS-NEGOEX and MS-PKU2U | Base wire formats, PKINIT (4556), PKINIT KDF agility (8636), PKINIT freshness (8070), CMS (5652), GSS pseudo-random (4401) for NEGOEX keys |

---

## 1. Goal and Scope

gokrb5 must be a fully MS-KILE-compliant **Kerberos client** and **application server** (acceptor) when the KDC is Active Directory, while remaining interoperable with MIT/Heimdal KDCs.

"Compliant" means:

1. Every MS-KILE-defined PA-DATA, authorization-data, and KRB-ERROR e-data structure that a client or application server is required to send, receive, or tolerate is encoded, decoded, and acted on as specified.
2. Every MS-PAC buffer type is parsed, validated according to the application-server rules, and exposed to callers; PAC serialisation exists for tests and future use.
3. MS-SFU constrained-delegation flows (S4U2self, S4U2proxy, RBCD) work against AD.
4. The GSS-API Kerberos mechanism behaves as Windows SSPI expects: channel bindings, delegation, DCE style, extended error flag, RFC 4121 and legacy RC4 (RFC 4757 §7) per-message tokens, and SPNEGO mechListMIC semantics.
5. FAST armoring with compound identity and claims, PKINIT compliant with MS-PKCA (certificate logon, smart-card style signers, AD KDC certificate validation, KDF agility, PAC credentials), and KKDCP are available so a gokrb5 client can authenticate in the same deployments a Windows client can.
6. NEGOEX is supported as a SPNEGO-embedded mechanism on both sides (negotiation, metadata, VERIFY binding, alerts), and PKU2U provides KDC-less peer authentication with X.509 certificates over NEGOEX, so gokrb5 interoperates with Windows in non-domain and Azure-AD-joined scenarios.
7. Parsing of every AD-supplied structure is bounds-checked and fuzzed; no panic on untrusted input.

### 1.1 Out of scope (deliberate non-goals)

| Item | Reason |
| --- | --- |
| KDC role (MS-KILE §3.3) | gokrb5 is not a KDC. Structures the KDC emits are decoded; KDC-side logic is not implemented. |
| DES-CBC-CRC (1), DES-CBC-MD5 (3), RC4-HMAC-EXP (24) | Disabled by default in Windows since Server 2008 R2; cryptographically broken. Clients must gracefully negotiate them away, not implement them. |
| NTLM | Separate protocol ([MS-NLMP]); NEGOEX and PKU2U are in scope (§3.6, §3.7) but NTLM is never offered or accepted. |
| NEGOEX auth schemes other than Kerberos and PKU2U | Windows Hello / Azure AD PRT / MSA packages are proprietary; NEGOEX must negotiate past them, not implement them. |
| Delegated Managed Service Account key package (KERB-DMSA-KEY-PACKAGE, PA-DATA 171) | Newest revision, KDC-to-client for dMSA only; decode-only support is provided in Phase 0 and no behaviour is attached. |
| KCM/KEYRING/DIR credential caches | Unchanged from the MIT compatibility spec. |

---

## 2. Current Implementation — Findings

The historical review and plan have moved to the [single refactoring roadmap](refactoring.md#appendix-a---historical-ms-kile-review-and-implementation-plan).
Use its current assessment and active phases, not the historical gap list, to
select new work. Original finding IDs and phase references are preserved there.

## 3. Target Design

### 3.1 Constants and ASN.1 structures (`v8/iana`, `v8/types`)

New/extended constant packages:

- `iana/patype`: `PA_KERB_KEY_LIST_REQ = 161`, `PA_KERB_KEY_LIST_REP = 162`, `PA_PAC_OPTIONS = 167`, `PA_SUPERSEDED_BY_USER = 170`, `PA_DMSA_KEY_PACKAGE = 171`. Rename alias `PA_FOR_X509_USER` → keep and add `PA_S4U_X509_USER = 130`.
- `iana/adtype`: `KerbAdRestrictionEntry = 141`, `KerbLocal = 142`, `ADAuthDataAPOptions = 143`, `ADCAMMAC = 96`, `ADAuthenticationIndicator = 97`.
- `iana/nametype`: `KRB_NT_WELLKNOWN = 11`, `KRB_NT_MS_PRINCIPAL = -128`, `KRB_NT_MS_PRINCIPAL_AND_ID = -129`, `KRB_NT_ENT_PRINCIPAL_AND_ID = -130`.
- `iana/flags`: `CNameInAddlTkt = 14` (already `EncTktInSkey = 28`), constants for PA-PAC-OPTIONS bits: `PACOptionClaims = 0`, `PACOptionBranchAware = 1`, `PACOptionForwardToFullDC = 2`, `PACOptionResourceBasedConstrainedDelegation = 3`.
- `iana/keyusage`: `PA_S4U_X509_USER_REQUEST = 26`, `PA_S4U_X509_USER_REPLY = 27`, `FAST_REQ_CHKSUM = 50`, `FAST_ENC = 51`, `FAST_REP = 52`, `FAST_FINISHED = 53`, `ENC_CHALLENGE_CLIENT = 54`, `ENC_CHALLENGE_KDC = 55`, `KEY_USAGE_PA_PKINIT_KX = 44`.
- New `iana/msflags` (or extend `iana/flags`): `KERB_AP_OPTIONS_CBT = 0x4000`, `KERB_AP_OPTIONS_UNVERIFIED_TARGET_NAME = 0x8000`; `SupportedEncTypes` bit field: `DES_CBC_CRC = 0x1`, `DES_CBC_MD5 = 0x2`, `RC4_HMAC = 0x4`, `AES128_CTS_HMAC_SHA1_96 = 0x8`, `AES256_CTS_HMAC_SHA1_96 = 0x10`, `AES256_CTS_HMAC_SHA1_96_SK = 0x20`, `AES128_CTS_HMAC_SHA256_128 = 0x40`, `AES256_CTS_HMAC_SHA384_192 = 0x80`, `FAST_SUPPORTED = 0x10000`, `COMPOUND_IDENTITY_SUPPORTED = 0x20000`, `CLAIMS_SUPPORTED = 0x40000`, `RESOURCE_SID_COMPRESSION_DISABLED = 0x80000`; KERB-ERROR-DATA `data-type` values `KERB_AP_ERR_TYPE_SKEW_RECOVERY = 2`, `KERB_ERR_TYPE_EXTENDED = 3`; LSAP_TOKEN_INFO_INTEGRITY `Flags` (`UAC_RESTRICTED = 0x1`) and `TokenIL` levels (untrusted 0x0, low 0x1000, medium 0x2000, high 0x3000, system 0x4000, protected 0x5000).
- New `iana/ntstatus`: the NTSTATUS codes AD returns in KERB-EXT-ERROR that a client acts upon (`STATUS_ACCOUNT_DISABLED`, `STATUS_ACCOUNT_LOCKED_OUT`, `STATUS_ACCOUNT_EXPIRED`, `STATUS_PASSWORD_EXPIRED`, `STATUS_PASSWORD_MUST_CHANGE`, `STATUS_INVALID_LOGON_HOURS`, `STATUS_INVALID_WORKSTATION`, `STATUS_LOGON_FAILURE`, `STATUS_NO_LOGON_SERVERS`, `STATUS_NOT_SUPPORTED`, `STATUS_LOGON_TYPE_NOT_GRANTED`, `STATUS_ACCOUNT_RESTRICTION`, `STATUS_UNSUPPORTED_PREAUTH`, `STATUS_TIME_DIFFERENCE_AT_DC`) with `String()`.

New ASN.1 types in `v8/types` (file `mskile.go`), each with `Marshal`/`Unmarshal` and a `PAData`/`AuthorizationDataEntry` constructor:

```go
type KerbPAPACRequest struct { IncludePAC bool `asn1:"explicit,tag:0"` }                           // MS-KILE KERB-PA-PAC-REQUEST
type PAPACOptions   struct { Flags asn1.BitString `asn1:"explicit,tag:0"` }                        // MS-KILE PA-PAC-OPTIONS
type KerbErrorData  struct { DataType int32 `asn1:"explicit,tag:1"`; DataValue []byte `asn1:"explicit,optional,tag:2"` }
type KerbExtError   struct { Status uint32; Reserved uint32; Flags uint32 }                         // 12 bytes little-endian
type KerbADRestrictionEntry struct { RestrictionType int32 `asn1:"explicit,tag:0"`; Restriction []byte `asn1:"explicit,tag:1"` }
type LSAPTokenInfoIntegrity struct { Flags uint32; TokenIL uint32; PerBootMachineID [32]byte; CrossBootMachineID [32]byte } // little-endian
type ADAuthDataAPOptions uint32                                                                      // little-endian, KERB_AP_OPTIONS_*
type PAForUser struct { UserName PrincipalName `asn1:"explicit,tag:0"`; UserRealm string `asn1:"generalstring,explicit,tag:1"`; Cksum Checksum `asn1:"explicit,tag:2"`; AuthPackage string `asn1:"generalstring,explicit,tag:3"` }
type S4UUserID struct { Nonce uint32 `asn1:"explicit,tag:0"`; CName PrincipalName `asn1:"explicit,optional,tag:1"`; CRealm string `asn1:"generalstring,explicit,tag:2"`; SubjectCertificate []byte `asn1:"explicit,optional,tag:3"`; Options asn1.BitString `asn1:"explicit,optional,tag:4"` }
type PAS4UX509User struct { UserID asn1.RawValue `asn1:"explicit,tag:0"`; Checksum Checksum `asn1:"explicit,tag:1"` } // RawValue wraps DER S4UUserID
type PASupportedEncTypes uint32
type KerbKeyListReq []int32
type KerbKeyListRep []EncryptionKey
type PASvrReferralData struct { ReferredName PrincipalName `asn1:"explicit,optional,tag:1"`; ReferredRealm string `asn1:"generalstring,explicit,tag:0"` }
type KerbSupersededByUser struct { Name PrincipalName `asn1:"explicit,tag:0"`; Realm string `asn1:"generalstring,explicit,tag:1"` }
type KerbDMSAKeyPackage struct { CurrentKeys []EncryptionKey `asn1:"explicit,tag:0"`; PreviousKeys []EncryptionKey `asn1:"explicit,optional,tag:1"`; ExpirationInterval time.Time `asn1:"generalized,explicit,tag:2"`; FetchInterval time.Time `asn1:"generalized,explicit,tag:4"` }
```

These tags were re-verified against the current MS-KILE pages during Phase 0. The spec's ASN.1 remains normative.

FAST types (RFC 6113 §5.4) go in `v8/types/fast.go`: `PAFXFastRequest` (CHOICE armored-data), `KrbFastArmoredReq`, `KrbFastReq`, `KrbFastArmor`, `KrbFastResponse`, `KrbFastFinished`, `PAFXFastReply`, `PAEncryptedChallenge` (= `EncryptedData`), `PAFXError` (= KRB-ERROR).

In Phase 1, `KRBError` gains the behavioral decoding APIs below. They are not part of the Phase 0 structure-only scope:

```go
func (k KRBError) MethodData() (types.PADataSequence, error)   // e-data as METHOD-DATA when error code permits
func (k KRBError) KerbErrorData() ([]types.KerbErrorData, error) // MS-KILE KERB-ERROR-DATA decoding
func (k KRBError) NTStatus() (ntstatus.Code, bool)             // first KERB_ERR_TYPE_EXTENDED status
```

Also in Phase 1, `krberror.Krberror` wraps `KRBError` so callers can `errors.As` into it and read `NTStatus()`.

### 3.2 Authorization-data visitor (`v8/types`, `v8/messages`)

```go
// Walk visits every entry, descending into AD-IF-RELEVANT containers; the depth limit is 8.
func (a AuthorizationData) Walk(fn func(depth int, entry AuthorizationDataEntry) error) error
func (a AuthorizationData) EntriesOfType(adType int32) ([]AuthorizationDataEntry, error)
```

`Ticket.GetPACType` and the acceptor use `EntriesOfType(adtype.ADWin2KPAC)`; the acceptor reads `Authenticator.AuthorizationData.EntriesOfType(adtype.ADAuthDataAPOptions)` to detect `KERB_AP_OPTIONS_CBT`, and ignores 141/142 by design (tested).

### 3.3 PAC (`v8/pac`)

- Bounds-check every `Offset`/`Size` against `len(Data)`, require 8-byte alignment of offsets per MS-PAC, reject overlapping buffers, return typed errors (`ErrPACMalformed`).
- New buffers: `TicketChecksum` (16, `SignatureData`), `AttributesInfo` (17: `FlagsLength uint32`, `Flags` bit 0 `PAC_WAS_REQUESTED`, bit 1 `PAC_WAS_GIVEN_IMPLICITLY`), `Requestor` (18: `mstypes.RPCSID`), `FullChecksum` (19, `SignatureData`). Zero the signature bytes of 6, 7, 16 and 19 in `ZeroSigData` as MS-PAC §2.8.2 prescribes (server checksum input excludes 16 and 19 only when they are present; verify the exact rule in the current MS-PAC revision).
- Fix `UPNDNSInfo`: `Flags & 0x1` = `U` (no UPN attribute), `Flags & 0x2` = `S` (extension present) → parse `SamNameLength/Offset`, `SidLength/Offset`, expose `SamAccountName string`, `ObjectSID mstypes.RPCSID`.
- `Verify(key, opts)` implements application-server rules (KA-1) with an options struct: `RequireClientInfoMatch(cname, authtime)`, `RequireRequestorSID`, `AllowMissingPACRequestor` (pre-2021 DCs), `ExpectedSName`.
- Marshal: `PACType.Marshal() ([]byte, error)` producing buffer table + 8-byte-aligned payloads; `Sign(serverKey, kdcKey)` for test fixtures. Each buffer type gets `Marshal` (NDR via `github.com/jcmturner/rpc/v2/ndr` writer support — add a minimal NDR encoder for the used types if `rpc/v2` lacks one; see Open Questions).
- `credentials.ADCredentials` gains: `UPN`, `DNSDomain`, `SAMAccountName`, `UserSID`, `ExtraSIDs []SIDAttributes`, `ResourceGroupSIDs`, `UserAccountControl`, `ClientClaims`, `DeviceClaims`, `DeviceInfo`, `S4UDelegationInfo`, `PACAttributes`, `PACRequestorSID`, `TicketAuthTime`. The HTTP middleware exposes them via the existing context key.

### 3.4 Client (`v8/client`, `v8/messages`)

1. **AS-REQ**: `ASReqOptions.IncludePAC *bool` → KERB-PA-PAC-REQUEST (default: emit `include-pac: true` when `Config.LibDefaults.RequestPAC` (new, default true) — mirrors Windows). Accept canonicalised `cname` when `canonicalize` was requested or the requested name type is `KRB_NT_ENTERPRISE`; when PA-REQ-ENC-PA-REP was requested, require the reply checksum to verify. Store the canonical name in `Credentials`.
2. **Reply metadata**: parse `EncPAData` for PA-SUPPORTED-ENCTYPES and PA-SVR-REFERRAL-INFO; keep per-session `SupportedEncTypes`; when choosing TGS-REQ `etype` prefer AES256-SK semantics (session key AES256 even if ticket key is RC4) as MS-KILE describes.
3. **TGS-REQ**: `TGSReqOptions{PACOptions: []int, IncludePAC *bool, Claims bool}`; default emit PA-PAC-OPTIONS with `Claims` when the KDC advertised `CLAIMS_SUPPORTED`; `BranchAware` always (harmless); `RBCD` for S4U2proxy.
4. **Realm normalisation**: `types.RealmEqual(a, b string) bool` (ASCII case-fold) used in `Verify` paths, cache keys upper-cased, `Config` lookups case-insensitive. `KDCRep.Verify` compares `CRealm` with `RealmEqual`.
5. **Errors**: `krberror` carries `NTStatus`; `gokinit` maps common statuses to MIT-equivalent text plus the Windows detail (e.g. `Client's credentials have been revoked (account disabled)`).
6. **S4U (MS-SFU)** in new `v8/client/s4u.go`:

   ```go
   func (cl *Client) GetServiceTicketForUser(user types.PrincipalName, userRealm, spn string, opts ...S4UOption) (messages.Ticket, types.EncryptionKey, error) // S4U2self
   func (cl *Client) GetServiceTicketOnBehalfOf(evidence messages.Ticket, spn string, opts ...S4UOption) (messages.Ticket, types.EncryptionKey, error)          // S4U2proxy
   ```

   - S4U2self: TGS-REQ to own TGT's realm with `sname` = own principal, PA-FOR-USER (checksum `KERB_CHECKSUM_HMAC_MD5` over `name-type(4 LE) || name-strings || realm || "Kerberos"` keyed by the TGT session key, usage `KERB_NON_KERB_CKSUM_SALT`), plus PA-S4U-X509-USER when the KDC supports it (checksum over DER `S4UUserID`, usage 26; verify reply PA-S4U-X509-USER usage 27). Handle cross-realm user: follow referrals per MS-SFU §3.1.5.1.1 using the user's realm TGT chain; the resulting ticket is `forwardable` only if protocol transition is allowed — surface the flag.
   - S4U2proxy: TGS-REQ with `cname-in-addl-tkt`, `additional-tickets = [evidence]`, PA-PAC-OPTIONS RBCD bit when `opts.ResourceBased`; map `KDC_ERR_BADOPTION` with NTSTATUS `STATUS_NOT_SUPPORTED`/`STATUS_NO_MATCH` into typed errors (`ErrDelegationNotPermitted`). Cross-realm: obtain referral TGT for the target realm first, then repeat with the evidence ticket per MS-SFU §3.1.5.2.
   - Verify the returned PAC contains `S4U_DELEGATION_INFO` naming the client and the transited services; expose via `ADCredentials.S4UDelegationInfo` on the acceptor.
7. **FAST (RFC 6113 + MS-KILE compound identity)** in `v8/client/fast.go`, `v8/messages/fast.go`:
   - `client.FASTArmor(armorTGT messages.Ticket, armorKey types.EncryptionKey)` option, or `client.FASTArmorFromKeytab(computerKeytab)` which performs the armor AS exchange itself.
   - AS-REQ/TGS-REQ are wrapped in PA-FX-FAST (`KrbFastArmoredReq`: armor = `FX_FAST_ARMOR_AP_REQUEST` (1) with AP-REQ for `krbtgt/REALM` using the armor TGT; `req-checksum` over the outer `KDC-REQ-BODY` (usage 50); `enc-fast-req` (usage 51) containing `KrbFastReq{fast-options, padata, req-body}`); armor key = `KRB-FX-CF2(subkey, ticket session key, "subkeyarmor", "ticketarmor")`.
   - Pre-auth inside FAST: PA-ENCRYPTED-CHALLENGE (`EncryptedData` of `PA-ENC-TS-ENC` under `KRB-FX-CF2(armorKey, clientKey, "clientchallengearmor", "challengelongterm")`, usage 54), replacing PA-ENC-TIMESTAMP.
   - Replies: unwrap PA-FX-FAST (`KrbFastResponse`, usage 52), apply `strengthen-key` (`KRB-FX-CF2(strengthen, reply key, "strengthenkey", "replykey")`), verify `KrbFastFinished` (usage 53, ticket checksum), unwrap PA-FX-ERROR from armored KRB-ERROR, persist PA-FX-COOKIE across retries.
   - Compound identity: when the armor is a device TGT the KDC adds PAC_DEVICE_INFO / PAC_DEVICE_CLAIMS_INFO; nothing extra client-side except requesting claims.
   - Existing `DisablePAFXFAST` stays deprecated; a new `client.RequireFAST(bool)` fails closed when the KDC does not advertise `FAST_SUPPORTED`.
8. **KKDCP** in `v8/client/kkdcp.go`: when a KDC address is `https://…`, POST `KDC-PROXY-MESSAGE{kerb-message [0] OCTET STRING (4-byte length prefix + message), target-domain [1] KerberosString OPTIONAL, dclocator-hint [2] INTEGER OPTIONAL}` DER with `Content-Type: application/kerberos`, parse the response DER, honour `krb5.conf` `kdc = https://host/KdcProxy` and `kpasswd_server = https://…`, use `http.Client` with configurable TLS. Add `config.LibDefaults.HTTPProxy`-independent `KKDCPClient` setting on `client.Settings`.
9. **PKINIT (RFC 4556 + MS-PKCA)** in new `v8/pkinit`; full design in §3.9.
10. **KDC discovery**: add `_kerberos._tcp.dc._msdcs.<realm>` then `_kerberos._tcp.<realm>`; `_kpasswd._tcp`/`_udp`; optional site-aware lookup when `Config.LibDefaults.ADSite` is set.

### 3.5 GSS-API and SPNEGO (`v8/gssapi`, `v8/spnego`)

- New `gssapi.ChannelBindings{InitiatorAddrType, InitiatorAddress, AcceptorAddrType, AcceptorAddress, ApplicationData []byte}` with `MD5Hash()` per RFC 4121 §4.1.1.2; helpers `TLSServerEndPoint(cert *x509.Certificate)` (RFC 5929 §4.1 hash selection) and `TLSUnique(cs *tls.ConnectionState)`.
- `spnego.NewKRB5TokenAPREQ` gains an options struct: `ChannelBindings`, `Flags` (Deleg, Mutual, Replay, Sequence, Conf, Integ, DCEStyle 0x1000, ExtendedError 0x4000, Identify 0x2000), `Delegate bool` (requires `ok-as-delegate` unless `ForceDelegate`), `TargetName` for `KERB_AP_OPTIONS_UNVERIFIED_TARGET_NAME`.
- 0x8003 checksum builder: `Lgth=16`, `Bnd=MD5(cb)` or zeros, `Flags`, and when delegating `Dlgth=1`, `Dlen`, `Deleg=KRB-CRED` (forwarded TGT obtained via TGS-REQ with `forwarded` option and the acceptor's address per RFC 4121 §4.1.1; encrypted with the session key, usage 14 — confirm against a Windows capture whether the enc-part is session-key or null-etype and accept both on the acceptor), `Exts` (RFC 4121 §4.1.1.2 extension list) reserved.
- Authenticator authorization data on the client: `AD-IF-RELEVANT[AD-AUTH-DATA-AP-OPTIONS{KERB_AP_OPTIONS_CBT}]` whenever channel bindings are supplied, `KERB-LOCAL` omitted.
- Acceptor (`service`/`spnego`): parse 0x8003; if `Settings.ChannelBindings` set: compare `Bnd`; policy `ExtendedProtection{Never, WhenSupported, Always}` — `WhenSupported` enforces only when the client set `KERB_AP_OPTIONS_CBT` or non-zero `Bnd`. Extract `Deleg` KRB-CRED into `credentials.Credentials.DelegatedCredentials()` (a `*client.Client` constructible from the forwarded TGT). Generate AP-REP with `subkey` and `seq-number` when `Mutual` requested; DCE-style: expect the client's final AP-REP leg and verify it.
- Legacy tokens: `gssapi.RC4MICToken` / `gssapi.RC4WrapToken` (RFC 4757 §7.2–7.3): `TOK_ID`, `SGN_ALG 0x1100`, `SEAL_ALG 0x1000|0xFFFF`, `Filler 0xFFFF`, `SND_SEQ` (RC4 of seq||direction with key `HMAC(Kss, checksum)`), `SGN_CKSUM` (HMAC-MD5 over `salt(15|13) || header || confounder || data`, truncated to 8), `Confounder` (RC4 keyed with `HMAC(Klocal, seq)` where `Klocal = Kss XOR 0xF0…`), all wrapped in the RFC 2743 `InitialContextToken` framing with the KRB5 OID. Token selection: if the negotiated key etype is `RC4_HMAC` → legacy tokens; else RFC 4121. `gssapi.Context` abstraction (`Wrap`, `Unwrap`, `GetMIC`, `VerifyMIC`, sequence-window replay detection) hides the choice.
- SPNEGO: implement MS-SPNG `mechListMIC` rules on both sides (compute over the DER `MechTypeList`, key usage 15/23 per token direction), accept `NegTokenInit2` (`negHints`) from Windows acceptors, send `1.2.840.48018.1.2.2` first when talking to a Windows acceptor that offered it (configurable), answer `accept-incomplete` with the AP-REP `responseToken` for mutual auth.
- Mechanism abstraction: retain the legacy `gssapi.Mechanism` API and add a byte-oriented `gssapi.ContextMechanism` (`OID`, step-wise `InitSecContext`/`AcceptSecContext`) plus `gssapi.Context`. NEGOEX implements this interface; `spnego.Negotiator` negotiates an ordered mechanism list and tolerates an optimistic token for an unselected mechanism by selecting the first mutually supported mechanism.

### 3.6 NEGOEX (`v8/negoex`)

NEGOEX is a GSS mechanism (OID `1.3.6.1.4.1.311.2.2.30`) offered inside SPNEGO; it negotiates auth schemes identified by GUIDs and binds the negotiation with a keyed checksum. Structures (all little-endian, verify field order and sizes against MS-NEGOEX §2.2 before implementation):

```go
type MessageHeader struct { Signature uint64 /* "NEGOEXTS" */; MessageType uint32; SequenceNum uint32; HeaderLength uint32; MessageLength uint32; ConversationID [16]byte }
type NegoMessage     struct { Header MessageHeader; Random [32]byte; ProtocolVersion uint64; AuthSchemes []AuthScheme /* GUID vector */; Extensions []Extension }
type ExchangeMessage struct { Header MessageHeader; AuthScheme AuthScheme; Exchange []byte }            // INITIATOR/ACCEPTOR_META_DATA, CHALLENGE, AP_REQUEST
type VerifyMessage   struct { Header MessageHeader; AuthScheme AuthScheme; Checksum Checksum }           // Checksum{HeaderLength, Scheme=CHECKSUM_SCHEME_RFC3961, Type, Value}
type AlertMessage    struct { Header MessageHeader; AuthScheme AuthScheme; ErrorCode uint32; Alerts []Alert }
```

Message types: `INITIATOR_NEGO 0`, `ACCEPTOR_NEGO 1`, `INITIATOR_META_DATA 2`, `ACCEPTOR_META_DATA 3`, `CHALLENGE 4`, `AP_REQUEST 5`, `VERIFY 6`, `ALERT 7`. Vectors use `(Offset uint32, Count uint16)` plus structure-specific reserved padding, or `(Offset, Length)` byte-vector encodings relative to the message start. Fixed headers are padded to their specified lengths (96/64/80/72); variable extension values are not generally 8-byte aligned. The decoder bounds-checks every vector.

Behaviour (MS-NEGOEX §3):

- A NEGOEX token is the concatenation of one or more messages sharing `ConversationID`; `SequenceNum` increments per message across the conversation. The initiator's first token holds `INITIATOR_NEGO`, optional `INITIATOR_META_DATA` per scheme, and optionally an optimistic `AP_REQUEST` for its preferred scheme. The acceptor answers `ACCEPTOR_NEGO` with the intersection in its own preference order, optional `ACCEPTOR_META_DATA`, then `CHALLENGE`; the initiator selects the first surviving scheme in that order. Subsequent tokens carry `AP_REQUEST`/`CHALLENGE` for the selected scheme until the scheme's context completes.
- `Random` (32 bytes) is cryptographically random; `ProtocolVersion` is 0.
- `VERIFY`: once a side has the scheme's checksum key it appends a `VERIFY` message whose RFC 3961 keyed checksum covers every message exchanged so far in order. The selected auth scheme supplies the local checksum key and peer verification key through `Context.NegoExKey()`/`NegoExVerifyKey()`; derivation is scheme-specific, not a generic Kerberos GSS operation. Key usages are 23 for an initiator checksum and 25 for an acceptor checksum. A received `VERIFY` must be validated before the context is reported complete; a completed scheme without a local checksum key is fatal. `ALERT_VERIFY_NO_KEY` requests retransmission when the peer VERIFY arrived before the verification key became available.
- Auth schemes are registered by their mechanism-defined GUID. PKU2U defines `235f69ad-73fb-4dbc-8203-0629e739339b`; unknown GUIDs are skipped. Kerberos V5 has no standardized NEGOEX auth-scheme GUID and MIT's Kerberos mechanism does not implement the NEGOEX metadata/key SPIs, so this design does not invent or advertise a Kerberos auth scheme. Kerberos remains a direct SPNEGO mechanism; PKU2U is added as a NEGOEX scheme in Phase 11.
- A nonzero peer `ALERT.ErrorCode` is surfaced as `negoex.AlertError`, preserving its `iana/ntstatus.Code`; `ALERT_VERIFY_NO_KEY` is generated and consumed for checksum retry. Scheme-specific failures remain scheme tokens unless that scheme defines an ALERT mapping.
- After completion, per-message tokens are those of the negotiated scheme (RFC 4121 for Kerberos and PKU2U).

API:

```go
func New(schemes ...negoex.Scheme) *Mechanism // implements gssapi.ContextMechanism with OID 1.3.6.1.4.1.311.2.2.30
func (m *Mechanism) InitSecContext(target string, in []byte, opts ...gssapi.MechanismOption) (out []byte, ctx gssapi.Context, done bool, err error)
func (m *Mechanism) AcceptSecContext(in []byte, opts ...gssapi.MechanismOption) (out []byte, ctx gssapi.Context, done bool, err error)
```

`spnego.NewNegotiator` accepts an ordered list of `gssapi.ContextMechanism` values. Applications opt into NEGOEX by including a configured `negoex.Mechanism`; legacy Kerberos constructors preserve their existing direct-SPNEGO behavior.

### 3.7 PKU2U (`v8/pku2u`)

PKU2U (OID `1.3.6.1.5.2.7`) authenticates two peers with X.509 certificates and no KDC; the acceptor plays the KDC for its own service principal. It runs as a NEGOEX auth scheme (Windows only offers it that way) and reuses Kerberos/PKINIT messages:

- Names: realm `WELLKNOWN:PKU2U`; principal names derived from certificates (UPN SAN → `KRB_NT_ENTERPRISE`; otherwise subject-based `KRB_NT_X500_PRINCIPAL`); the acceptor's name is the target name the initiator was given (host-based `host/fqdn` or a UPN).
- Metadata (`INITIATOR_META_DATA`/`ACCEPTOR_META_DATA`): each side sends its trusted-certifier list encoded per MS-PKU2U §2.2 (DER, same shape as PKINIT `TD-TRUSTED-CERTIFIERS`) so the peer can select a certificate the other side will trust.
- Exchange:
  1. Initiator `AP_REQUEST` carries `KRB_AS_REQ` for `sname` = acceptor name, `realm` = `WELLKNOWN:PKU2U`, with `PA-PK-AS-REQ` (Phase 9 code) and `KERB-PA-PAC-REQUEST{false}`.
  2. Acceptor validates the initiator certificate against its anchors and the metadata, builds `KRB_AS_REP` with `PA-PK-AS-REP` (DH mode), issues a ticket for itself encrypted under a freshly generated key it retains for the conversation, and returns it in `CHALLENGE`. The reply key is derived per RFC 4556 §3.2.3.1; the acceptor's KDC certificate role is played by its own certificate (MS-PKU2U certificate validation rules, not MS-PKCA KDC EKU rules — verify in §7).
  3. Initiator decrypts the AS-REP, sends `AP_REQUEST` with `KRB_AP_REQ` (mutual required) plus `VERIFY`.
  4. Acceptor decrypts the ticket with its retained key, verifies the authenticator, answers `CHALLENGE` with `KRB_AP_REP` and `VERIFY`.
- Context key: AP-REP subkey (initiator) / authenticator subkey; per-message tokens RFC 4121 with the negotiated etype (AES256-SHA1 default).
- No PAC is issued; `credentials.Credentials` for the initiator carries the certificate subject, UPN and chain instead of `ADCredentials`.

API:

```go
type Identity struct { Certificate *x509.Certificate; Chain []*x509.Certificate; Signer crypto.Signer }
func NewInitiator(id Identity, anchors *x509.CertPool, opts ...Option) gssapi.Mechanism
func NewAcceptor(id Identity, anchors *x509.CertPool, opts ...Option) gssapi.Mechanism
```

Both are registered as NEGOEX schemes; a bare PKU2U mechanism inside SPNEGO (without NEGOEX) is also exposed for non-Windows peers.

### 3.8 Configuration (`v8/config`)

New `[libdefaults]` keys parsed: `request_pac` (bool, default true), `pkinit_anchors`, `pkinit_identities`, `pkinit_kdc_hostname`, `pkinit_eku_checking`, `pkinit_require_crl_checking`, `pkinit_dh_min_bits`, `pkinit_pool`, `http_anchors`, `kdc_proxy`-style `kdc = https://…` in `[realms]`, `ad_site`, `extended_protection` (service). `[appdefaults]` untouched.

### 3.9 PKINIT compliant with MS-PKCA (`v8/pkinit`)

MS-PKCA profiles RFC 4556 for AD; gokrb5 implements the client role (MS-PKCA §3.1 client, §3.2.5 KDC-reply processing). All ASN.1 tag numbers and OIDs below are to be re-verified against the current MS-PKCA/RFC 4556/RFC 8636 text before implementation.

**Structures (`v8/pkinit/asn1.go`)** — `PAPKAsReq{SignedAuthPack []byte /* CMS SignedData */; TrustedCertifiers []ExternalPrincipalIdentifier; KDCPkID []byte}`, `AuthPack{PKAuthenticator; ClientPublicValue *SubjectPublicKeyInfo; SupportedCMSTypes []AlgorithmIdentifier; ClientDHNonce []byte; SupportedKDFs []KDFAlgorithmID /* RFC 8636 */}`, `PKAuthenticator{CUSec int32; CTime time.Time; Nonce int32; PAChecksum []byte; FreshnessToken []byte /* RFC 8070 */}`, `PAPKAsRep` (CHOICE `dhInfo DHRepInfo` | `encKeyPack []byte`), `DHRepInfo{DHSignedData []byte; ServerDHNonce []byte; KDF *KDFAlgorithmID}`, `KDCDHKeyInfo{SubjectPublicKey asn1.BitString; Nonce int32; DHKeyExpiration *time.Time}`, `ReplyKeyPack{ReplyKey types.EncryptionKey; AsChecksum types.Checksum}`, `TDDHParameters []AlgorithmIdentifier`, `TDTrustedCertifiers []ExternalPrincipalIdentifier`, `TDInvalidCertificates []ExternalPrincipalIdentifier`, `KRB5PrincipalName{Realm string; PrincipalName types.PrincipalName}` for `id-pkinit-san`, and the legacy `PAPKAsReqOld` recogniser (decode only, always rejected with `ErrLegacyPKINITNotSupported`).

**CMS (`v8/pkinit/cms.go`)** — minimal RFC 5652 subset: `SignedData` with one `SignerInfo` (content types `id-pkinit-authData`, `id-pkinit-DHKeyData`, `id-pkinit-rkeyData`), signed attributes `contentType`/`messageDigest`, digest algorithms SHA-1/SHA-256/SHA-384/SHA-512, signature algorithms RSA PKCS#1 v1.5 and RSASSA-PSS, ECDSA (P-256/P-384) for modern DC certificates, certificate set carrying the chain; `EnvelopedData` with one RSA `KeyTransRecipientInfo` and AES-CBC/3DES content encryption for the RSA mode (`encKeyPack`). Everything else is rejected with typed errors. Decision on stdlib-only versus a dependency is Open Question 10.

**Client identity (`v8/pkinit/identity.go`)** — `Identity{Certificate *x509.Certificate; Chain []*x509.Certificate; Signer crypto.Signer}` with loaders `FromPEM`, `FromPKCS12`, and a `Signer`-only constructor for PKCS#11/TPM callers. Selection rules (MS-PKCA §3.1.5.1): certificate must be time-valid, carry EKU `id-kp-clientAuth` or `Smart Card Logon` unless `pkinit_eku_checking = none`, and name the principal via UPN `otherName` SAN, `id-pkinit-san`, or subject mapping; `KeyTrust` mode (KP-8) allows a self-signed certificate. The SID extension (`1.3.6.1.4.1.311.25.2`) is decoded and exposed for diagnostics only.

**AS exchange (`v8/pkinit/client.go`, `v8/client/ASExchange.go`)**:

1. Build `PKAuthenticator` with `paChecksum = SHA-1(DER(KDC-REQ-BODY))`; when the KDC advertised RFC 8636 support (`supportedKDFs` echo or `KDC_ERR_NO_ACCEPTABLE_KDF`), also send `supportedKDFs = [sha512, sha384, sha256]`.
2. DH mode (default): generate an ephemeral key in MODP group 14 (fall back to the KDC's `TD-DH-PARAMETERS` on `KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED`, never below `pkinit_dh_min_bits`, default 2048), `clientDHNonce` 32 random bytes. RSA mode when configured or when the KDC returns `KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED` for DH.
3. Wrap `AuthPack` in CMS `SignedData` signed by `Identity.Signer` with the chain; send PA-PK-AS-REQ plus KERB-PA-PAC-REQUEST; include `PA-PK-OCSP-RESPONSE` when the caller supplies a stapled OCSP response.
4. Freshness (RFC 8070): if the preauth-required KRB-ERROR contains `PA-AS-FRESHNESS`, copy the token into `PKAuthenticator.freshnessToken`; `RequireFreshness` option fails closed when the KDC does not offer it.
5. On PA-PK-AS-REP: verify the CMS signature and chain of the KDC certificate; enforce MS-PKCA §3.2.5.2 — EKU `id-pkinit-KPKdc` (or `pkinit_eku_checking = kpServerAuth` legacy mode), `dNSName` SAN equal to the realm's DNS domain (`pkinit_kdc_hostname` override), or `id-pkinit-san` `krbtgt/REALM` for non-AD KDCs; revocation per `pkinit_require_crl_checking` (CRL DP and OCSP via `x509` + stdlib HTTP); `KDCDHKeyInfo.nonce` must equal the request nonce; honour `dhKeyExpiration` for DH key reuse.
6. Reply key: DH shared secret → `octetstring2key(secret || clientDHNonce || serverDHNonce)` (RFC 4556) or RFC 8636 KDF (`kdfId` from `DHRepInfo.kdf`) with the party-U/party-V info exactly as specified; RSA mode: decrypt `EnvelopedData`, verify `ReplyKeyPack.asChecksum` over the KDC-REQ-BODY with the reply key (usage 6).
7. Decrypt the AS-REP `enc-part` with the reply key; then decrypt `PAC_CREDENTIAL_INFO` (usage 16) into `PAC_CREDENTIAL_DATA`/`NTLM_SUPPLEMENTAL_CREDENTIAL` and expose it only via `client.Client.PKINITCredentials()`.
8. Errors: map every code in KP-5 to typed `pkinit.Err*` values wrapping the KRB-ERROR, decode `TD-*` typed data, surface NTSTATUS (Phase 1), retry once on DH-parameter and KDF negotiation errors.

**Config and CLI** — `pkinit_*` keys in §3.8; `gokinit -X X509_user_identity=FILE:cert.pem,key.pem|PKCS12:file.p12 -X X509_anchors=FILE:ca.pem`; PIN prompt through the existing tty helper.

**Non-goals** — KDC-side PKINIT, Windows 2000 PA-PK-AS-REQ-OLD, PKINIT anonymous (RFC 8062) except decode tolerance, ECDH (`id-pkinit-kdf` with EC groups) until Windows offers it.

---

## 4. Verification Strategy

### 4.1 Test layers

| Layer | Runs where | Mechanism |
| --- | --- | --- |
| Unit | always | Byte-exact fixtures captured from Windows Server 2019/2022 DCs and Samba AD DC (4.20+), stored as hex constants in `v8/test/testdata/mskile_vectors.go` with the capturing command/tool and OS build recorded. MS-KILE/MS-PAC/MS-SFU "Protocol Examples" sections provide additional normative vectors. |
| Fuzz | always | `FuzzPACUnmarshal`, `FuzzKerbErrorData`, `FuzzRC4Tokens`, `FuzzFASTResponse`, `FuzzPKASRep`, seeded with all fixtures; 60 s in CI. |
| Samba AD integration | CI (`INTEGRATION=1 TESTAD=1 TESTAD_REALM=SAMBA.GOKRB5 TESTAD_DIR=<provisioned files>`) | New container `jcmturner/gokrb5:samba-ad-dc` provisioned with users, an RC4-only user, an AES-only user, a service account with `msDS-AllowedToDelegateTo`, an RBCD target (`msDS-AllowedToActOnBehalfOfOtherIdentity`), a protocol-transition-enabled service, a computer account for FAST armor, claims enabled, a PKINIT CA. The container exports `krb5.keytab`, `user` and `pw` so the same `test/ad` discovery drives both Samba and Windows runs. Samba implements MS-KILE/MS-SFU/MS-PAC closely enough for functional tests. |
| Windows AD integration | live domain (`TESTAD=1`) | `test.AD(t)` gate plus `test/ad.Environment(t)`: the realm is derived from the host's FQDN domain (override `TESTAD_REALM`), KDCs are found via DNS SRV, and credentials come from the repository root — `krb5.keytab` (host keytab; the `host/<fqdn>` principal is the test service and the `<COMPUTER>$` principal the keytab login identity), `user` (principal), `pw` (password) — overridable with `TESTAD_DIR`/`TESTAD_KEYTAB`/`TESTAD_USER_FILE`/`TESTAD_PASSWORD_FILE`. All three files are git-ignored. Tests skip when the gate is unset. All Samba tests must also pass against Windows; captured differences become findings. |
| MIT/Heimdal regression | CI (existing containers) | Every phase reruns the existing MIT suites; MS-specific PA-DATA must be ignored by MIT KDCs without failure. |
| NEGOEX interop | CI (MIT krb5 ≥ 1.18 image) | MIT's SPNEGO implements NEGOEX; its `negoextest` sample mechanism and `t_negoex.py` scenarios are reproduced with `gss-client`/`gss-server` against gokrb5 initiator and acceptor. Windows client/IIS (manual) for real NEGOEX-encapsulated Kerberos. |
| PKU2U interop | manual (`TESTAD=1` on a Windows-joined host) | Two Windows hosts (or one Windows host plus gokrb5) with test certificates; Windows is the only widely deployed PKU2U peer. |

### 4.2 Fixture inventory (`v8/test/testdata/mskile_vectors.go`)

1. `AS_REQ_WIN_PAC_REQUEST` / `AS_REP_WIN_*` — Windows `kinit`-equivalent (klist purge + net use) AS exchange with KERB-PA-PAC-REQUEST, PA-ENC-TIMESTAMP, enterprise name, canonicalised reply.
2. `KRB_ERROR_WIN_EXT_ERROR_*` — KRB-ERROR with KERB-ERROR-DATA for: disabled account, locked out, password must change, invalid logon hours, skew recovery.
3. `TGS_REQ_WIN_PAC_OPTIONS`, `TGS_REP_WIN_SUPPORTED_ENCTYPES` — PA-PAC-OPTIONS with Claims/Branch-Aware; reply `encrypted-pa-data` with PA-SUPPORTED-ENCTYPES.
4. `TGS_REQ_S4U2SELF_PA_FOR_USER`, `TGS_REQ_S4U2SELF_X509_USER`, `TGS_REP_S4U2SELF`, `TGS_REQ_S4U2PROXY`, `TGS_REQ_S4U2PROXY_RBCD`, `TGS_REP_S4U2PROXY` and the corresponding decrypted PACs with `S4U_DELEGATION_INFO`.
5. `AP_REQ_WIN_CBT` — Windows client AP-REQ with 0x8003 (non-zero `Bnd`, flags), `AD-AUTH-DATA-AP-OPTIONS`, `KERB-AD-RESTRICTION-ENTRY`, `KERB-LOCAL`; `AP_REQ_WIN_DELEG` with `Deleg` KRB-CRED; `AP_REP_WIN_MUTUAL` with subkey/seq; `AP_REQ_WIN_DCE_STYLE` sequence (3 legs).
6. `PAC_WIN2022_FULL` — PAC with buffers 1, 6, 7, 10, 12 (`S` flag), 13, 14, 15, 16, 17, 18, 19 plus the service key; `PAC_WIN2016_NO_REQUESTOR`; `PAC_SAMBA_*` equivalents; tampered variants generated at test time with the new marshaller.
7. `GSS_RC4_MIC_*`, `GSS_RC4_WRAP_SEAL_*`, `GSS_RC4_WRAP_SIGN_ONLY_*` — tokens with known session key, sequence number and plaintext (RFC 4757 test vectors plus Windows captures).
8. `SPNEGO_WIN_NEGTOKENINIT2`, `SPNEGO_WIN_MECHLISTMIC_*`.
9. `FAST_AS_REQ_WIN_ARMORED`, `FAST_AS_REP_WIN`, `FAST_KRB_ERROR_WIN`, `FAST_TGS_REQ_COMPOUND_IDENTITY` with armor key and device TGT session key recorded.
10. `KKDCP_REQUEST_*`, `KKDCP_RESPONSE_*` — DER of KDC-PROXY-MESSAGE.
11. `PKINIT_AS_REQ_WIN_DH`, `PKINIT_AS_REP_WIN_DH`, `PKINIT_AS_REQ_WIN_RSA`, `PKINIT_AS_REP_WIN_RSA`, `PKINIT_AS_REQ_WIN_KDF_SHA256` / `PKINIT_AS_REP_WIN_KDF_SHA256` (RFC 8636), `PKINIT_KRB_ERROR_WIN_*` (DH params not accepted with `TD-DH-PARAMETERS`, client not trusted with `TD-TRUSTED-CERTIFIERS`, freshness required), `PKINIT_FRESHNESS_TOKEN_WIN`, test CA chain, DC certificate with `KDC Authentication` EKU, client cert/key (test-only) with UPN SAN and SID extension, `PAC_CREDENTIAL_INFO_WIN` with reply key; RFC 4556/8636 appendix vectors for `octetstring2key` and the KDFs.
12. `KPASSWD_WIN_POLICY_REPLY` — result string with policy blob.
13. `NEGOEX_WIN_INITIATOR_TOKEN`, `NEGOEX_WIN_ACCEPTOR_TOKEN`, `NEGOEX_WIN_VERIFY_*`, `NEGOEX_WIN_ALERT_NO_KEY` — Windows SPNEGO tokens carrying NEGOEX for a Kerberos scheme, with the conversation's context key so `VERIFY` can be recomputed; `NEGOEX_MIT_*` from MIT `t_negoex.py`.
14. `PKU2U_WIN_METADATA_*`, `PKU2U_WIN_AS_REQ`, `PKU2U_WIN_AS_REP`, `PKU2U_WIN_AP_REQ`, `PKU2U_WIN_AP_REP` — a full PKU2U conversation between two Windows hosts using test certificates, with the DH private values exported from a debug build or reconstructed with known test keys.

Capture procedure is documented in `v8/test/testdata/gen/mskile_capture.md` (Wireshark with `KRB5 decrypt` using exported keytabs; `klist -li 0x3e7 purge`, `Get-KerberosTicket`, `impacket-getST` for S4U, `krb5_pac` dumps from Samba). Never commit production keys.

### 4.3 Unit tests (new or changed; names indicative)

`v8/types`: round-trip and fixture tests for every structure in §3.1; `TestAuthorizationDataWalkDepthLimit`; `TestRealmEqual`.

`v8/messages`: `TestKRBErrorKerbErrorData`, `TestKRBErrorNTStatus`, `TestASRepVerifyAcceptsCanonicalizedCName`, `TestASRepVerifyRejectsCNameChangeWithoutCanonicalize`, `TestKDCRepSupportedEncTypes`, `TestNewS4U2SelfTGSReq`, `TestNewS4U2ProxyTGSReq`, `TestFASTArmoredReqRoundTrip`, `TestFASTResponseStrengthenKey`.

`v8/pac`: `TestPACBoundsChecks` (table of truncations/overlaps/misalignment → `ErrPACMalformed`, no panic), `TestPACBuffers16To19`, `TestUPNDNSInfoSExtension`, `TestPACVerifyClientInfoMismatch`, `TestPACVerifyRequestorMismatch`, `TestPACMarshalRoundTripByteExact`, `TestPACSignAndVerify`, `FuzzPACUnmarshal`.

`v8/gssapi`: `TestAuthenticatorChecksumChannelBindings`, `TestAuthenticatorChecksumDelegation`, `TestRC4MICVector`, `TestRC4WrapSealVector`, `TestRC4WrapSignOnlyVector`, `TestContextSelectsLegacyTokensForRC4`, `TestSequenceWindowReplay`, `FuzzRC4Tokens`.

`v8/spnego`: `TestMechListMICComputedWhenRequired`, `TestNegTokenInit2Hints`, `TestMutualAuthResponseToken`, `TestDCEStyleThreeLeg`.

`v8/service`: `TestVerifyAPREQChannelBindingPolicy` (Never/WhenSupported/Always × client CBT flag × Bnd match), `TestVerifyAPREQIgnoresKerbLocalAndRestrictionEntry`, `TestVerifyAPREQSNameMustMatchService`, `TestDelegatedCredentialsExtracted`, `TestUser2UserAccept`.

`v8/client`: `TestASReqIncludesPACRequest`, `TestTGSReqPACOptionsClaims`, `TestS4U2SelfChecksum`, `TestS4U2ProxyBadOptionMapsToTypedError`, `TestFASTEncryptedChallenge`, `TestFASTErrorUnwrap`, `TestKKDCPTransport` (httptest server), `TestADSRVLookupOrder`.

`v8/pkinit`: `TestAuthPackDHRoundTrip`, `TestPAChecksumOverReqBody`, `TestCMSSignedDataSignVerify`, `TestCMSEnvelopedDataRSA`, `TestClientCertSelectionEKUAndUPN`, `TestKeyTrustSelfSignedIdentity`, `TestKDCCertEKUAcceptance` (KPKdc, legacy serverAuth mode, wrong EKU rejected), `TestKDCCertDNSNameMatchesRealm`, `TestKDCCertRevocationPolicy`, `TestReplyKeyOctetString2KeyVectors`, `TestReplyKeyRFC8636KDFVectors`, `TestDHParamsNotAcceptedRetry`, `TestNoAcceptableKDFRetry`, `TestFreshnessTokenEchoed`, `TestFreshnessRequiredFailsClosed`, `TestLegacyPKASReqOldRejected`, `TestPKINITErrorsTyped`, `TestPACCredentialInfoDecrypt`, `FuzzPKASRep`, `FuzzCMS`.

`v8/negoex`: `TestMessageHeaderRoundTrip`, `TestNegoMessageVectors`, `TestDecoderRejectsOutOfRangeVectors`, `TestConversationSequenceNumbers`, `TestSchemeIntersectionOrder`, `TestVerifyChecksumOverConversation`, `TestConversationRejectsCompletedMechanismWithoutVerifyKey`, `TestConversationRetriesVerifyAfterNoKeyAlert`, `FuzzNegoExUnmarshal`.

`v8/pku2u`: `TestMetadataTrustedCertifiers`, `TestASReqWellKnownRealm`, `TestAcceptorIssuesSelfTicket`, `TestInitiatorRejectsUntrustedAcceptorCert`, `TestMutualAPRepRequired`, `TestCertificateToPrincipalMapping`, `TestEndToEndOverNegoEx`, `FuzzPKU2UMetadata`.

`v8/spnego`: `TestOptimisticNegoExTokenSelectsKRB5`, `TestMechanismOrderWithNegoEx`.

### 4.4 Integration tests (Samba AD DC container in CI; live Windows domain via `TESTAD=1` discovery)

1. Enterprise logon `user@corp.example` → canonical `cname` accepted; ticket usable.
2. Disabled/locked/expired accounts → `NTStatus()` populated with the expected code.
3. RC4-only user → AS/TGS succeed with RC4 keys and legacy GSS tokens verified by Samba's `smbclient`/`gss-server` equivalents.
4. S4U2self for an arbitrary user, S4U2proxy to `HTTP/target` with classic and RBCD delegation; negative: unauthorised target → `ErrDelegationNotPermitted`. Acceptor sees `S4U_DELEGATION_INFO`.
5. Channel bindings: gokrb5 client → gokrb5 acceptor over TLS with `tls-server-end-point`, `Always` policy: success; tampered binding: `KRB_AP_ERR_BAD_INTEGRITY`. Windows-only: gokrb5 client → IIS with Extended Protection Required.
6. Delegation: client with `ok-as-delegate` target sends KRB-CRED; acceptor constructs a client from the forwarded TGT and obtains a second-hop ticket.
7. Mutual auth and DCE style against Samba `gss-server`/Windows RPC acceptor.
8. FAST: with device keytab armor, `RequireFAST(true)` logon succeeds; TGS with compound identity yields PAC_DEVICE_INFO; KDC policy "fail unarmored" honoured.
9. Claims: user with claims → `ClientClaims` populated.
10. KKDCP: Samba/`kdcproxy` container in front of the KDC; client configured with `https://` KDC only.
11. PKINIT: certificate logon in DH and RSA modes against Samba `pkinit` and a Windows CA-issued certificate; RFC 8636 KDF negotiated with Windows Server 2012+; freshness token echoed against Windows Server 2016+; untrusted client certificate → `KDC_ERR_CLIENT_NOT_TRUSTED` typed error with trusted certifiers listed; PAC_CREDENTIAL_INFO NT hash decrypted equals the account's NT hash (Samba test account); `gokinit -X X509_user_identity=…` produces a ccache MIT `klist` accepts.
12. All existing MIT suites unchanged.
13. NEGOEX: byte fixtures from MIT's `negoextest` and captured Windows PKU2U exchanges decode and re-encode exactly; equivalent multi-hop, metadata-pruning, VERIFY retry, and failure scenarios run against gokrb5's scheme interface. Windows end-to-end NEGOEX interop is exercised with PKU2U after Phase 11; direct Kerberos SPNEGO remains a separate scenario.
14. PKU2U (manual): gokrb5 initiator ↔ Windows acceptor and Windows initiator ↔ gokrb5 acceptor with test-CA certificates; untrusted certificate → `ALERT` and failure; gokrb5 ↔ gokrb5 automated in CI.

---

## 5. Exit Criteria

### 5.1 Structures and parsing

- [ ] EC-S1: Every structure in §3.1 round-trips byte-exactly against its captured fixture.
- [ ] EC-S2: All fuzz targets run 60 s in CI with zero crashes; PAC/UPN/RC4/FAST/PKINIT parsers return errors, never panic, on every truncation of every fixture.
- [ ] EC-S3: `KRBError.NTStatus()` returns the expected code for fixture set 2.

### 5.2 Client role (MS-KILE §3.2, MS-SFU §3.1/§3.2)

- [ ] EC-C1: AS-REQ carries KERB-PA-PAC-REQUEST; canonicalised cname accepted; enterprise logon succeeds against Samba and Windows.
- [ ] EC-C2: PA-SUPPORTED-ENCTYPES consumed; TGS etype selection follows AES-SK semantics; RC4-only accounts work.
- [ ] EC-C3: S4U2self (PA-FOR-USER and PA-S4U-X509-USER), S4U2proxy (classic and RBCD) succeed; cross-realm S4U follows MS-SFU referral rules; PAC `S4U_DELEGATION_INFO` matches.
- [ ] EC-C4: FAST armoring with encrypted challenge, cookie persistence, armored error unwrapping and compound identity pass integration tests; `RequireFAST` fails closed.
- [ ] EC-C5: GSS initiator supports channel bindings, delegation (honouring `ok-as-delegate`), mutual, DCE style, extended-error flag; Windows IIS with Extended Protection Required accepts the client (manual gate).
- [ ] EC-C6: Legacy RC4 tokens are produced when the session key is RC4 and verified by Windows/Samba; RFC 4121 tokens otherwise.
- [ ] EC-C7: KKDCP transport works with `https://` KDC entries for AS, TGS and kpasswd.
- [ ] EC-C8: PKINIT per §5.5.
- [ ] EC-C9: Realm comparison is case-insensitive everywhere; mixed-case `krb5.conf` realms interoperate.
- [ ] EC-C10: `gokinit` surfaces NTSTATUS detail; `goklist` shows PAC-derived flags unchanged from MIT output (no regression).

### 5.3 Application-server role (MS-KILE §3.4, MS-PAC)

- [ ] EC-A1: PAC validation enforces server checksum, client-info name/authtime, requestor SID (when present), UPN_DNS_INFO `S` consistency, duplicate-buffer and alignment rules; every rule has a negative test built with the marshaller.
- [ ] EC-A2: `ADCredentials` exposes all fields in §3.3 and the HTTP context carries them.
- [ ] EC-A3: Channel-binding policy Never/WhenSupported/Always behaves per MS-KILE with `KERB_AP_OPTIONS_CBT` detection; `KERB-LOCAL`/`KERB-AD-RESTRICTION-ENTRY` are ignored.
- [ ] EC-A4: Mutual authentication returns AP-REP with subkey/sequence; DCE style three-leg verified; delegated KRB-CRED extracted and usable.
- [ ] EC-A5: Legacy RC4 tokens verified/unwrapped; sequence-window replay detection on both token families.
- [ ] EC-A6: SPNEGO acceptor computes/validates `mechListMIC` per MS-SPNG and accepts NegTokenInit2.
- [ ] EC-A7: Ticket `sname` must match a configured service principal; user-to-user tickets accepted when enabled.

### 5.4 NEGOEX and PKU2U (MS-NEGOEX, MS-PKU2U)

- [ ] EC-N1: NEGOEX messages round-trip byte-exactly against fixtures 13; decoder never panics (fuzz 60 s).
- [ ] EC-N2: NEGOEX inside generic SPNEGO completes in both directions; `VERIFY` is computed and validated, and tampering any prior message fails verification. Windows end-to-end coverage uses PKU2U, the standardized Windows NEGOEX auth scheme in scope.
- [ ] EC-N3: SPNEGO acceptor handles an optimistic NEGOEX token from Windows by negotiating down to KRB5 when NEGOEX is disabled, and up to NEGOEX when enabled.
- [ ] EC-N4: PKU2U conversation completes gokrb5↔gokrb5 in CI and gokrb5↔Windows manually; certificate trust and name mapping rules enforced; no NTLM fallback ever offered.
- [ ] EC-N5: Per-message tokens after NEGOEX/PKU2U use RFC 4121 with the negotiated key and interoperate with the peer.

### 5.5 PKINIT (MS-PKCA)

- [ ] EC-P1: PA-PK-AS-REQ/REP, CMS and typed-data structures round-trip byte-exactly against fixtures 11; `FuzzPKASRep`/`FuzzCMS` 60 s clean; PA-PK-AS-REQ-OLD is rejected with a typed error.
- [ ] EC-P2: DH (group 14, KDC-directed fallback) and RSA modes obtain a TGT from Samba and Windows; RFC 4556 `octetstring2key` and RFC 8636 KDF vectors pass; Windows Server 2012+ negotiates a SHA-2 KDF.
- [ ] EC-P3: Client certificate selection enforces MS-PKCA EKU/UPN rules with `pkinit_eku_checking` modes; key-trust (self-signed) identities work when enabled.
- [ ] EC-P4: KDC certificate validation enforces chain, `KDC Authentication` EKU (or configured legacy mode), realm `dNSName`/`pkinit_kdc_hostname`, nonce match and revocation policy; a KDC certificate lacking the EKU or with a mismatched name is rejected in a negative test.
- [ ] EC-P5: Every PKINIT KRB-ERROR code in KP-5 maps to a typed error carrying decoded `TD-*` data and NTSTATUS; DH-parameter and KDF negotiation errors trigger exactly one retry.
- [ ] EC-P6: Freshness token echoed when offered; `RequireFreshness` fails closed; OCSP stapling sent when supplied.
- [ ] EC-P7: `PAC_CREDENTIAL_INFO` decrypted with the reply key and exposed only on the client; the acceptor never exposes it.
- [ ] EC-P8: `gokinit -X X509_user_identity=… -X X509_anchors=…` and `pkinit_*` `krb5.conf` keys behave like MIT `kinit` for the supported subset.

### 5.6 Quality gates

- [ ] EC-Q1: No exported API removed; new options are additive; `CHANGELOG.md` lists every new setting.
- [ ] EC-Q2: `go vet`, `gofmt -l`, `go test ./...` (all Go versions in CI), `INTEGRATION=1` MIT suites, `TESTAD=1` Samba suites green; the same suites green against a live Windows domain on the manual runner before release.
- [ ] EC-Q3: `USAGE.md` documents S4U, channel bindings, delegation, FAST, KKDCP, PKINIT, NEGOEX, PKU2U, Extended Protection; `README.md` feature list updated.

---

## 6. Phased Implementation Plan (LLM-executable)

The historical review and plan have moved to the [single refactoring roadmap](refactoring.md#appendix-a---historical-ms-kile-review-and-implementation-plan).
Use its current assessment and active phases, not the historical gap list, to
select new work. Original finding IDs and phase references are preserved there.

## 7. Open Questions (resolve during the referenced phase by reading the current spec revision or by capture)

1. **PAC checksum coverage (Phase 4)** — Confirm in the current MS-PAC §2.8 whether the server/KDC checksums are computed with buffers 16 and 19 zeroed (present-but-zeroed) or excluded, and whether PAC_TICKET_CHECKSUM covers the ticket with the PAC AD zeroed or removed. Capture from Windows Server 2022 to confirm.
2. **Requestor/attributes enforcement (Phase 4)** — MS-PAC says the application server MAY validate PAC_REQUESTOR; Windows (post-KB5008380 enforcement mode) requires it for tickets from patched DCs. Decide default: enforce when present, configurable `RequirePACRequestor` for 2021+ environments.
3. **KRB-CRED encryption in GSS delegation (Phase 3)** — RFC 4121 says the session key; Windows historically used the session key but some acceptors also accept `etype 0` (null). Capture and decide whether the acceptor must accept both.
4. **DCE-style AP-REP details (Phase 3)** — Confirm the third-leg AP-REP contents (`seq-number` only vs. full) against MS-KILE §3.4.5 and an RPC capture.
5. **PA-S4U-X509-USER options bits (Phase 6)** — Confirm `KERB_S4U_OPTIONS` bit positions (`check-logon-hours`, `signed-with-kdc-key`) and reply checksum key usage against the current MS-SFU revision.
6. **NDR encoder (Phase 4)** — Check whether `github.com/jcmturner/rpc/v2/ndr` provides marshalling; if not, implement the minimal writer in `v8/pac/internal/ndrw` and raise upstream.
7. **RFC 4757 token framing (Phase 5)** — Confirm whether Windows wraps legacy per-message tokens in the RFC 2743 `InitialContextToken` header in SPNEGO/HTTP contexts (it does for RPC); capture from an RC4-only account.
8. **FAST armor without a device account (Phase 7)** — Windows requires a device TGT for compound identity; a user TGT can armor its own TGS-REQ. Decide whether `FASTArmorFromKeytab` also accepts user keytabs and document that compound identity then does not apply.
9. **KKDCP `dclocator-hint` (Phase 8)** — Whether to send it (Windows sends DS flags); default omit unless `ad_site` configured.
10. **PKINIT CMS scope (Phase 9)** — Minimal CMS implementation vs. a dependency; stdlib has none. Decide after measuring the size of the required subset (SignedData with one signer incl. ECDSA/RSASSA-PSS, EnvelopedData RSA-only). Candidates: `github.com/github/smimesign/ietf-cms`, `go.mozilla.org/pkcs7`; both need auditing for the PKINIT content types.
11. **KERB-DMSA-KEY-PACKAGE / KERB-SUPERSEDED-BY-USER (Phase 0, resolved)** — The current MS-KILE definitions were verified on 2026-09-06. `KERB-SUPERSEDED-BY-USER` uses `name [0]`, `realm [1]`. `KERB-DMSA-KEY-PACKAGE` uses `current-keys [0]`, optional `previous-keys [1]`, `expiration-interval [2]`, and `fetch-interval [4]`. Phase 0 provides strict decode/encode support without attaching client behaviour.
12. **NEGOEX keys (Phase 10, resolved)** — `GSS_C_INQ_NEGOEX_KEY` and `GSS_C_INQ_NEGOEX_VERIFY_KEY` are mechanism extension points returning directional keys; NEGOEX itself does not derive them with a generic Kerberos PRF. The selected scheme supplies both keys. Checksum key usages are 23 (initiator) and 25 (acceptor).
13. **NEGOEX auth-scheme GUIDs (Phase 10/11, resolved)** — Auth-scheme GUIDs are supplied by mechanisms through the NEGOEX SPI. Kerberos V5 has no standardized GUID and is not registered as a NEGOEX mechanism by MIT. PKU2U defines `235f69ad-73fb-4dbc-8203-0629e739339b`; add that constant and captured fixtures with Phase 11.
14. **PKU2U acceptor certificate rules (Phase 11, resolved pending Windows confirmation)** — Peer certificates use generic X.509 chain and optional revocation validation, not MS-PKCA KDC EKU rules. Host targets require a matching DNS SAN; other targets use UPN SAN then X.500 subject mapping. Trust anchors are always explicit. Fixture 14 must confirm Azure-AD-issued certificate profiles.
15. **PKU2U without NEGOEX (Phase 11, resolved)** — Windows only negotiates PKU2U via NEGOEX. Bare PKU2U remains an explicit `ContextMechanism` for non-Windows peers and is never advertised automatically.
16. **MS-PKCA KDC certificate name rule (Phase 9)** — Confirm from the current MS-PKCA §3.2.5.2 whether the `dNSName` SAN must equal the realm's DNS domain, the responding DC's FQDN, or either; capture DC certificates issued by the default "Kerberos Authentication" template (which carries both) and the older "Domain Controller" template.
17. **RFC 8636 KDF selection by Windows (Phase 9)** — Verify which `kdfId` values Windows Server 2012–2022 select when offered SHA-256/384/512, and whether omitting `supportedKDFs` still yields `octetstring2key`; fixtures must cover both.
18. **Freshness enforcement (Phase 9)** — Confirm the KRB-ERROR code and e-data Windows returns when the freshness extension is required but absent, so `RequireFreshness`/retry logic matches.
19. **Key-trust identities (Phase 9)** — Confirm the AuthPack/CMS shape Windows Hello key-trust clients send (self-signed certificate vs. bare public key) before implementing KP-8.
20. **PKU2U AP-REP subkey (Phase 11, resolved pending Windows confirmation)** — RFC 4121 permits an acceptor-asserted AP-REP subkey and requires it to become the base key with the AcceptorSubkey token flag. The implementation generates one, encrypts AP-REP with the authenticator subkey, and installs the asserted key on both sides. Fixture 14 must confirm Windows PKU2U behavior; do not change this based only on symmetric gokrb5 tests.

[MS-KILE]: https://learn.microsoft.com/openspecs/windows_protocols/ms-kile/
[MS-PAC]: https://learn.microsoft.com/openspecs/windows_protocols/ms-pac/
[MS-SFU]: https://learn.microsoft.com/openspecs/windows_protocols/ms-sfu/
[MS-KKDCP]: https://learn.microsoft.com/openspecs/windows_protocols/ms-kkdcp/
[MS-PKCA]: https://learn.microsoft.com/openspecs/windows_protocols/ms-pkca/
[MS-SPNG]: https://learn.microsoft.com/openspecs/windows_protocols/ms-spng/
[MS-NEGOEX]: https://learn.microsoft.com/openspecs/windows_protocols/ms-negoex/
[MS-PKU2U]: https://learn.microsoft.com/openspecs/windows_protocols/ms-pku2u/
[MS-NLMP]: https://learn.microsoft.com/openspecs/windows_protocols/ms-nlmp/
