# Design Spec: MS-KILE Compliance — Kerberos Protocol Extensions for Active Directory

Status: Draft
Scope: `v8` module (`github.com/jcmturner/gokrb5/v8`)
Normative references (verify against the latest published revision before each phase):

| Reference | Title | Used for |
|---|---|---|
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
|---|---|
| KDC role (MS-KILE §3.3) | gokrb5 is not a KDC. Structures the KDC emits are decoded; KDC-side logic is not implemented. |
| DES-CBC-CRC (1), DES-CBC-MD5 (3), RC4-HMAC-EXP (24) | Disabled by default in Windows since Server 2008 R2; cryptographically broken. Clients must gracefully negotiate them away, not implement them. |
| NTLM | Separate protocol ([MS-NLMP]); NEGOEX and PKU2U are in scope (§3.6, §3.7) but NTLM is never offered or accepted. |
| NEGOEX auth schemes other than Kerberos and PKU2U | Windows Hello / Azure AD PRT / MSA packages are proprietary; NEGOEX must negotiate past them, not implement them. |
| Delegated Managed Service Account key package (KERB-DMSA-KEY-PACKAGE, PA-DATA 171) | Newest revision, KDC-to-client for dMSA only; decode-only support is provided in Phase 0 and no behaviour is attached. |
| KCM/KEYRING/DIR credential caches | Unchanged from the MIT compatibility spec. |

---

## 2. Current Implementation — Findings

Sources reviewed: `v8/client/*.go`, `v8/messages/*.go`, `v8/types/*.go`, `v8/pac/*.go`, `v8/gssapi/*.go`, `v8/spnego/*.go`, `v8/service/*.go`, `v8/crypto/*.go`, `v8/kadmin/*.go`, `v8/config/*.go`, `v8/iana/**`.

### 2.1 What exists and is compliant

| Capability | Location |
|---|---|
| AES128/256-SHA1, AES-SHA2, RC4-HMAC, DES3 etypes and checksums | `v8/crypto` |
| RC4 string-to-key (UTF-16LE NT hash), ETYPE-INFO2 salts and s2kparams | `v8/crypto/rfc4757`, `v8/crypto/crypto.go` |
| PA-ENC-TIMESTAMP, ETYPE-INFO/INFO2 precedence, PA-REQ-ENC-PA-REP (RFC 6806 §11) | `v8/client/ASExchange.go`, `v8/messages/KDCRep.go` |
| `KDC_ERR_WRONG_REALM` client referrals, TGS `krbtgt/OTHER` server referrals (RFC 6806) | `v8/client/ASExchange.go`, `v8/client/TGSExchange.go` |
| `KRB_ERR_RESPONSE_TOO_BIG` UDP→TCP fallback, `udp_preference_limit` | `v8/client/network.go` |
| Clock-skew recovery from KRB-ERROR `stime` | `v8/client/clock.go`, `ASExchange.go` |
| `KDC_ERR_KEY_EXPIRED` → password change (RFC 3244, protocol 0xff80, port 464) | `v8/kadmin`, `v8/cmd/gokinit` |
| Enterprise principals (`KRB_NT_ENTERPRISE`), `canonicalize` KDC option | `v8/credentials`, `v8/messages/KDCReq.go` |
| User-to-user TGS-REQ (`enc-tkt-in-skey`, `additional-tickets`) | `v8/messages/KDCReq.go` |
| AD-IF-RELEVANT unwrapping, AD-WIN2K-PAC extraction | `v8/messages/Ticket.go` |
| PAC buffers 1, 6, 7, 10, 11, 12 (partial), 13, 14, 15; server-checksum verification with HMAC-MD5 and AES checksums | `v8/pac` |
| RFC 4121 MIC (0x0404) and Wrap (0x0504) tokens | `v8/gssapi` |
| SPNEGO NegTokenInit/Resp, KRB5 and MS-legacy KRB5 OIDs, HTTP Negotiate middleware | `v8/spnego` |
| Service AP-REQ verification: keytab decrypt, skew, addresses, replay cache, PAC group SIDs into `credentials.ADCredentials` | `v8/service`, `v8/messages/APReq.go` |
| DNS SRV KDC discovery, kpasswd discovery | `v8/config/hosts.go` |

### 2.2 Defects and gaps — protocol structures (`KS-n`)

| ID | Finding | Severity |
|---|---|---|
| KS-1 | No ASN.1 types for KERB-PA-PAC-REQUEST (128), PA-PAC-OPTIONS (167), KERB-ERROR-DATA / KERB-EXT-ERROR, KERB-AD-RESTRICTION-ENTRY (141) with LSAP_TOKEN_INFO_INTEGRITY, KERB-LOCAL (142), AD-AUTH-DATA-AP-OPTIONS (143), PA-FOR-USER (129), PA-S4U-X509-USER (130), PA-SUPPORTED-ENCTYPES (165), KERB-KEY-LIST-REQ/REP (161/162), PA-SVR-REFERRAL-INFO (20, RFC 6806 Appendix A), KERB-SUPERSEDED-BY-USER (170), KERB-DMSA-KEY-PACKAGE (PA-DATA 171). Only the `patype` constants up to 166 exist; 167, 161, 162, 170, 171 are missing. | High |
| KS-2 | `iana/adtype` lacks 141, 142, 143; `iana/nametype` lacks `KRB_NT_WELLKNOWN` (11), `KRB_NT_MS_PRINCIPAL` (-128), `KRB_NT_MS_PRINCIPAL_AND_ID` (-129), `KRB_NT_ENT_PRINCIPAL_AND_ID` (-130); no constants for `KERB_AP_OPTIONS_CBT` (0x4000), `KERB_AP_OPTIONS_UNVERIFIED_TARGET_NAME` (0x8000), PA-PAC-OPTIONS flag bits, PA-SUPPORTED-ENCTYPES bit field, `KDC_OPT_CNAME_IN_ADDL_TKT` (bit 14), key usages 26/27 (PA-S4U-X509-USER), NTSTATUS values commonly surfaced in KERB-EXT-ERROR. | Medium |
| KS-3 | `messages.KRBError.EData` is only parsed as METHOD-DATA in specific retry paths. KERB-ERROR-DATA (data-type 3 `KERB_ERR_TYPE_EXTENDED` carrying an NTSTATUS, data-type 2 `KERB_AP_ERR_TYPE_SKEW_RECOVERY`) and TYPED-DATA are never decoded, so AD-specific failure reasons (e.g. `STATUS_ACCOUNT_DISABLED`, `STATUS_PASSWORD_MUST_CHANGE`) are lost. | Medium |
| KS-4 | `PACType.ProcessPACInfoBuffers` slices `pac.Data[Offset:Offset+Size]` without bounds checks; a malformed PAC panics the service. `UPNDNSInfo.Unmarshal` slices by untrusted offsets similarly. No PAC fuzz target. | High (security) |
| KS-5 | PAC buffer types 16 (PAC_TICKET_CHECKSUM), 17 (PAC_ATTRIBUTES_INFO), 18 (PAC_REQUESTOR), 19 (PAC_FULL_CHECKSUM) are not recognised and are silently dropped. | Medium |
| KS-6 | `UPNDNSInfo` flag handling is wrong: `upnNoUPNAttr = 31` is used as a bit index where MS-PAC defines flag `U` = 0x00000001; flag `S` = 0x00000002 (SamName/Sid extension) is not parsed. | Medium |
| KS-7 | No PAC marshalling; fixtures cannot be synthesised and negative tests (tampered checksums, duplicate buffers, misaligned offsets) are impossible to construct programmatically. | Medium |
| KS-8 | `AuthorizationData` walking is ad hoc (`Ticket.GetPACType` only looks for `AD-IF-RELEVANT[0] == AD-WIN2K-PAC`). There is no generic visitor that returns all entries of a given type from nested AD-IF-RELEVANT containers in either ticket or authenticator authorization data. | Medium |

### 2.3 Defects and gaps — client behaviour (`KC-n`)

| ID | Finding | Severity |
|---|---|---|
| KC-1 | AS-REQ never includes KERB-PA-PAC-REQUEST. AD includes a PAC by default, but MS-KILE §3.2.5 clients send `include-pac` and RODC/branch scenarios depend on it; services that want PAC-less tickets cannot ask. | Medium |
| KC-2 | `ASRep.Verify`/`TGSRep.Verify` reject any `cname` that differs from the request. When `canonicalize` is set or the request used `KRB_NT_ENTERPRISE`, AD legitimately returns the canonical `cname`; RFC 6806 §11 / MS-KILE require acceptance (protected by PA-REQ-ENC-PA-REP when present). Enterprise logons to AD currently fail. | High |
| KC-3 | PA-SUPPORTED-ENCTYPES in the reply `encrypted-pa-data` is ignored, so the client cannot learn that the target supports AES-SK, claims, FAST, or compound identity, and cannot restrict TGS etypes accordingly. | Medium |
| KC-4 | No PA-PAC-OPTIONS in TGS-REQ: Claims, Branch-Aware, Forward-to-Full-DC and RBCD flags cannot be set. | Medium |
| KC-5 | No S4U2self (PA-FOR-USER, PA-S4U-X509-USER) and no S4U2proxy (`cname-in-addl-tkt` with evidence ticket), so constrained delegation and protocol transition are impossible. | High |
| KC-6 | No FAST (RFC 6113) armoring: PA-FX-FAST, PA-FX-COOKIE, PA-FX-ERROR, PA-ENCRYPTED-CHALLENGE are absent. `DisablePAFXFAST` actually toggles PA-REQ-ENC-PA-REP. AD policies "Fail unarmored authentication requests" and compound identity cannot be satisfied. | High |
| KC-7 | Realm comparisons are case-sensitive string equality throughout (`Ticket.Realm`, `CRealm`, cache keys). MS-KILE realm names are case-insensitive; AD emits upper-case, `krb5.conf` and users often supply mixed case. | Medium |
| KC-8 | Delegation: GSS `ContextFlagDeleg` extends the 0x8003 checksum to 28 bytes but never populates `Dlgth`/`Deleg` with a KRB-CRED; the `ok-as-delegate` ticket flag is not consulted. | High |
| KC-9 | 0x8003 checksum `Bnd` is always 16 zero bytes; no API to supply GSS channel bindings (tls-server-end-point, tls-unique). No AD-AUTH-DATA-AP-OPTIONS with `KERB_AP_OPTIONS_CBT`, so Windows services with Extended Protection "Required" reject gokrb5 clients. | High |
| KC-10 | Authenticator does not carry `KERB-LOCAL` or `KERB-AD-RESTRICTION-ENTRY`; Windows clients do, servers must ignore. Client-side emission is optional but the acceptor must tolerate it (see KA-4). | Low |
| KC-11 | No DCE-style (`GSS_C_DCE_STYLE` 0x1000) three-leg exchange and no `GSS_C_EXTENDED_ERROR_FLAG` (0x4000); required for RPC/SMB-style acceptors and Windows error propagation. | Medium |
| KC-12 | No legacy RFC 4757 §7 / RFC 1964 per-message tokens (TOK_ID 0x0101 MIC, 0x0201 Wrap, SGN_ALG 0x1100, SEAL_ALG 0x1000). Windows uses them whenever the session key is RC4-HMAC; gokrb5 wraps with 0x0504 regardless of key type, which Windows rejects. | High |
| KC-13 | No KKDCP (Kerberos over HTTPS) transport; `kdc = https://host/KdcProxy` in `krb5.conf` is not understood. | Medium |
| KC-14 | No PKINIT: see §2.6 (`KP-n`) for the MS-PKCA breakdown. | Medium |
| KC-15 | KDC discovery does not use AD-specific SRV names (`_kerberos._tcp.dc._msdcs.<domain>`, site-aware variants) or `_kpasswd`; falls back only to `_kerberos._tcp.<realm>`. | Low |
| KC-16 | `PA-SVR-REFERRAL-INFO` in `EncKDCRepPart.EncPAData` is ignored; the referral realm is inferred from the `krbtgt/REALM` sname only. | Low |
| KC-17 | kpasswd result strings from AD carry a 30-byte password-policy blob after the text; it is exposed as raw bytes with no decoder. | Low |

### 2.4 Defects and gaps — application-server behaviour (`KA-n`)

| ID | Finding | Severity |
|---|---|---|
| KA-1 | PAC validation stops at server-checksum verification. MS-PAC/MS-KILE application-server rules not applied: PAC_CLIENT_INFO `Name` must equal the ticket `cname` (case-insensitive) and `ClientId` must equal ticket `authtime`; PAC_REQUESTOR SID (when present) must equal KERB_VALIDATION_INFO `UserId` under `LogonDomainId`; UPN_DNS_INFO `S` extension SAM name/SID (when present) must match; duplicate buffer types must be rejected rather than ignored where MS-PAC says "MUST NOT". | High |
| KA-2 | Only `GroupMembershipSIDs`, logon times and a few names are exposed in `credentials.ADCredentials`. UPN, DNS domain, SAM account name, user SID, extra SIDs with attributes, resource group SIDs, client/device claims, device info, S4U delegation chain, PAC attributes flags and `UserAccountControl` are parsed but not surfaced. | Medium |
| KA-3 | Acceptor ignores the 0x8003 checksum entirely: no channel-binding comparison, no reading of `Flags`, no delegation (`Deleg` KRB-CRED) extraction, no DCE-style AP-REP handling, no `KERB_AP_OPTIONS_CBT` detection for Extended Protection policy. | High |
| KA-4 | Acceptor does not tolerate/ignore authenticator authorization data (`KERB-LOCAL`, `KERB-AD-RESTRICTION-ENTRY`, `AD-AUTH-DATA-AP-OPTIONS`); presence is not fatal today only because the field is never inspected — confirm and lock with tests. | Low |
| KA-5 | No AP-REP generation with subkey/sequence number when the client requests mutual authentication (`ContextFlagMutual`); SPNEGO acceptor returns `accept-completed` without a `responseToken`. Windows clients with mutual auth fail. | High |
| KA-6 | Legacy RC4 per-message tokens cannot be verified/unwrapped on the acceptor (mirror of KC-12). | High |
| KA-7 | User-to-user tickets (`enc-tkt-in-skey`) cannot be accepted; `APReq.Verify` only tries keytab keys. | Low |
| KA-8 | The acceptor does not validate the ticket `sname` against the service's own principal names when the keytab contains several principals unless `KeytabPrincipal` is set — MS-KILE §3.4.5 requires the ticket be for this service. | Medium |
| KA-9 | SPNEGO acceptor does not emit or verify `mechListMIC` per MS-SPNG rules (required when the negotiated mech is not the initiator's first preference, or when the client sends one). | Medium |

### 2.5 Defects and gaps — NEGOEX and PKU2U (`KN-n`)

| ID | Finding | Severity |
|---|---|---|
| KN-1 | No NEGOEX mechanism (`1.3.6.1.4.1.311.2.2.30`): no message framing (`MESSAGE_HEADER`, `NEGO_MESSAGE`, `EXCHANGE_MESSAGE`, `VERIFY_MESSAGE`, `ALERT_MESSAGE`), no auth-scheme GUID negotiation, no conversation state machine. | High |
| KN-2 | SPNEGO acceptor behaviour when the initiator's optimistic `mechToken` is NEGOEX (the Windows default) is unverified: it must answer `accept-incomplete` selecting KRB5 (or NEGOEX once implemented) instead of failing. SPNEGO initiator cannot offer NEGOEX. | Medium |
| KN-3 | No PKU2U mechanism (`1.3.6.1.5.2.7`): no `WELLKNOWN:PKU2U` realm handling, no acceptor-as-KDC AS exchange, no PKU2U metadata (trusted-certifier) exchange, no certificate-to-principal mapping. | High |
| KN-4 | No GSS context key export equivalent to `GSS_C_INQ_NEGOEX_KEY` / `GSS_C_INQ_NEGOEX_VERIFY_KEY`, which NEGOEX needs to compute and verify the `VERIFY` checksum over the conversation. | Medium |
| KN-5 | `gssapi` has no OID constants for NEGOEX or PKU2U and no generic mechanism interface; `spnego` hard-codes KRB5 as the only negotiable mechanism. | Medium |

### 2.6 Defects and gaps — PKINIT / MS-PKCA (`KP-n`)

| ID | Finding | Severity |
|---|---|---|
| KP-1 | No PA-PK-AS-REQ (16) / PA-PK-AS-REP (17) ASN.1 (`AuthPack`, `PKAuthenticator`, `DHRepInfo`, `KDCDHKeyInfo`, `ReplyKeyPack`, `TD-*` typed data) and no CMS `SignedData`/`EnvelopedData` codec; the `patype` constants 14–18 exist but nothing consumes them. The legacy Windows 2000 PA-PK-AS-REQ-OLD (14/15) must be recognised and rejected with a clear error, not treated as unknown PA-DATA. | High |
| KP-2 | No Diffie-Hellman (MODP 2/14/16) or RSA (`encKeyPack`) reply-key path; `octetstring2key` (RFC 4556 §3.2.3.1) and the RFC 8636 KDF (`id-pkinit-kdf-ah-sha256/384/512`) that Windows Server 2012+ negotiates via `supportedKDFs`/`kdfId` are absent. | High |
| KP-3 | No client certificate selection/validation per MS-PKCA §3.1.5: EKU `id-kp-clientAuth` or `Smart Card Logon` (`1.3.6.1.4.1.311.20.2.2`), UPN in `otherName` SAN (`1.3.6.1.4.1.311.20.2.3`) or `id-pkinit-san`, the strong-mapping SID extension (`1.3.6.1.4.1.311.25.2`) for diagnostics, `pkinit_identities` sources (PEM, PKCS#12, `crypto.Signer` for PKCS#11/TPM). | High |
| KP-4 | No KDC certificate validation per MS-PKCA §3.2.5.2: chain to `pkinit_anchors`, `KDC Authentication` EKU (`id-pkinit-KPKdc`, `1.3.6.1.5.2.3.5`) or, for legacy DCs, `Server Authentication` with the DC template, `dNSName` SAN matching the realm's DNS domain or `pkinit_kdc_hostname`, `id-pkinit-san` `krbtgt/REALM` for non-MS KDCs, CRL/OCSP revocation checking (`pkinit_require_crl_checking`), signature verification of `dhSignedData`/`signedAuthPack`, `dhKeyExpiration` handling and DH key reuse. | High |
| KP-5 | PKINIT KRB-ERROR handling absent: `KDC_ERR_CLIENT_NOT_TRUSTED`, `KDC_ERR_KDC_NOT_TRUSTED`, `KDC_ERR_INVALID_SIG`, `KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED` (+ `TD-DH-PARAMETERS` retry), `KDC_ERR_CANT_VERIFY_CERTIFICATE`, `KDC_ERR_INVALID_CERTIFICATE`, `KDC_ERR_REVOKED_CERTIFICATE`, `KDC_ERR_REVOCATION_STATUS_UNKNOWN`, `KDC_ERR_CLIENT_NAME_MISMATCH`, `KDC_ERR_KDC_NAME_MISMATCH`, `KDC_ERR_INCONSISTENT_KEY_PURPOSE`, `KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED`, `KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED`, `KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED`, `KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED`, `KDC_ERR_NO_ACCEPTABLE_KDF`, with `TD-TRUSTED-CERTIFIERS`/`TD-INVALID-CERTIFICATES`/`TD-CERTIFICATE-INDEX` decoding and the NTSTATUS from KERB-ERROR-DATA. | Medium |
| KP-6 | No PKINIT freshness (RFC 8070, PA-AS-FRESHNESS 150) which Windows Server 2016+ KDCs offer and can require ("KDC support for PKInit Freshness Extension"); no PA-PK-OCSP-RESPONSE (18) stapling in either direction. | Medium |
| KP-7 | `PAC_CREDENTIAL_INFO` (buffer 2) is skipped; with a PKINIT reply key it must be decrypted (usage 16) into `PAC_CREDENTIAL_DATA` → `NTLM_SUPPLEMENTAL_CREDENTIAL` for the client (MS-PAC §2.6, MS-PKCA §3.2.5.2). `credentials_info.go`/`supplemental_cred.go` parse the plaintext but nothing decrypts. | Medium |
| KP-8 | No support for PKINIT with self-signed keys used by Windows Hello for Business key trust (client certificate without a chain; KDC maps via `msDS-KeyCredentialLink`) — requires an explicit "no chain, KDC-mapped" identity mode. | Low |
| KP-9 | `gokinit` has no `-X X509_user_identity=`/`-X X509_anchors=` options and `krb5.conf` `pkinit_*` keys are not parsed. | Low |

---

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
- Mechanism abstraction: `gssapi.Mechanism` interface (`OID()`, `InitSecContext`, `AcceptSecContext`, `Context`) implemented by KRB5 (existing code), NEGOEX (§3.7) and PKU2U (§3.8); `spnego` negotiates over an ordered `[]Mechanism` instead of KRB5 only, and tolerates unknown optimistic tokens by selecting the first mutually supported mechanism.

### 3.6 NEGOEX (`v8/negoex`)

NEGOEX is a GSS mechanism (OID `1.3.6.1.4.1.311.2.2.30`) offered inside SPNEGO; it negotiates auth schemes identified by GUIDs and binds the negotiation with a keyed checksum. Structures (all little-endian, verify field order and sizes against MS-NEGOEX §2.2 before implementation):

```go
type MessageHeader struct { Signature uint64 /* "NEGOEXTS" */; MessageType uint32; SequenceNum uint32; HeaderLength uint32; MessageLength uint32; ConversationID [16]byte }
type NegoMessage     struct { Header MessageHeader; Random [32]byte; ProtocolVersion uint64; AuthSchemes []AuthScheme /* GUID vector */; Extensions []Extension }
type ExchangeMessage struct { Header MessageHeader; AuthScheme AuthScheme; Exchange []byte }            // INITIATOR/ACCEPTOR_META_DATA, CHALLENGE, AP_REQUEST
type VerifyMessage   struct { Header MessageHeader; AuthScheme AuthScheme; Checksum Checksum }           // Checksum{HeaderLength, Scheme=CHECKSUM_SCHEME_RFC3961, Type, Value}
type AlertMessage    struct { Header MessageHeader; AuthScheme AuthScheme; ErrorCode uint32; Alerts []Alert }
```

Message types: `INITIATOR_NEGO 0`, `ACCEPTOR_NEGO 1`, `INITIATOR_META_DATA 2`, `ACCEPTOR_META_DATA 3`, `CHALLENGE 4`, `AP_REQUEST 5`, `VERIFY 6`, `ALERT 7`. Vectors use `(Offset uint32, Count uint16, Pad uint16)` / `(Offset, Length)` byte-vector encodings relative to the message start; the encoder writes fixed parts first and appends variable data 8-byte aligned; the decoder bounds-checks every vector.

Behaviour (MS-NEGOEX §3):

- A NEGOEX token is the concatenation of one or more messages sharing `ConversationID`; `SequenceNum` increments per message across the conversation. The initiator's first token holds `INITIATOR_NEGO`, optional `INITIATOR_META_DATA` per scheme, and optionally an optimistic `AP_REQUEST` for its preferred scheme. The acceptor answers `ACCEPTOR_NEGO` (its scheme list restricted to the intersection, ordered by initiator preference), optional `ACCEPTOR_META_DATA`, then `CHALLENGE`. Subsequent tokens carry `AP_REQUEST`/`CHALLENGE` for the selected scheme until the scheme's context completes.
- `Random` (32 bytes) is cryptographically random; `ProtocolVersion` is 0.
- `VERIFY`: once a side has the scheme's context key it appends a `VERIFY` message whose checksum (RFC 3961 `get_mic`-style with the scheme's checksum type) covers every message exchanged so far in order. The key is obtained from the selected mechanism's context via `Mechanism.NegoExKey()`/`NegoExVerifyKey()`, derived with the mechanism's GSS pseudo-random function (RFC 4401) exactly as MIT krb5 implements `GSS_C_INQ_NEGOEX_KEY`/`GSS_C_INQ_NEGOEX_VERIFY_KEY`; key usage numbers for initiator and acceptor checksums are taken from MS-NEGOEX §2.2.5 (record the values in `iana/keyusage` after verification). A received `VERIFY` must be validated before the context is reported complete; a missing `VERIFY` when a key is available is fatal. `ALERT` with `ALERT_VERIFY_NO_KEY` is sent when the peer verified but this side has no key yet.
- Auth schemes: `negoex.SchemeKerberos` (GUID from MS-NEGOEX/MS-KILE), `negoex.SchemePKU2U` (GUID from MS-PKU2U §2.2); unknown GUIDs are carried through negotiation and skipped. Each scheme is a `gssapi.Mechanism`; the Kerberos scheme wraps the existing KRB5 initiator/acceptor so NEGOEX-encapsulated Kerberos also works.
- Errors are surfaced as `ALERT` with the `ErrorCode` NTSTATUS mapped via `iana/ntstatus`.
- After completion, per-message tokens are those of the negotiated scheme (RFC 4121 for Kerberos and PKU2U).

API:

```go
func New(schemes ...gssapi.Mechanism) *Mechanism                 // implements gssapi.Mechanism with OID 1.3.6.1.4.1.311.2.2.30
func (m *Mechanism) InitSecContext(target string, in []byte, opts ...Option) (out []byte, ctx gssapi.Context, done bool, err error)
func (m *Mechanism) AcceptSecContext(in []byte, opts ...Option) (out []byte, ctx gssapi.Context, done bool, err error)
```

`spnego` lists NEGOEX before KRB5 when any non-Kerberos scheme is configured (Windows order), otherwise KRB5 first with NEGOEX as fallback.

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
|---|---|---|
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

`v8/negoex`: `TestMessageHeaderRoundTrip`, `TestNegoMessageVectorsAlignment`, `TestDecoderRejectsOutOfRangeVectors`, `TestConversationSequenceNumbers`, `TestSchemeIntersectionOrder`, `TestVerifyChecksumOverConversation`, `TestMissingVerifyIsFatal`, `TestAlertVerifyNoKey`, `TestKerberosSchemeEndToEnd`, `FuzzNegoExUnmarshal`.

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
13. NEGOEX: gokrb5 acceptor completes with MIT `gss-client` using SPNEGO+NEGOEX (Kerberos scheme) and with MIT's `negoextest` scheme; gokrb5 initiator completes against MIT `gss-server`; `VERIFY` failures are rejected. Windows manual: browser/`curl --negotiate` from Windows to the gokrb5 HTTP acceptor and gokrb5 client to IIS both succeed with NEGOEX present in `mechTypes`.
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
- [ ] EC-N2: Kerberos over NEGOEX inside SPNEGO completes in both directions against MIT and Windows; `VERIFY` computed and validated; tampering any prior message fails verification.
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

Conventions for every phase:

- Read the cited spec sections first; where this document and the spec disagree, the spec wins — record the discrepancy in §7.
- Each phase is independently mergeable and ends with a check that must pass before the next phase starts.
- Follow repository conventions: `testify/assert`, fixtures as hex constants in `v8/test/testdata/`, integration tests call `test.Integration(t)`/`test.AD(t)` first, no new third-party dependencies beyond those listed in the phase.
- Keep changes within the listed files unless compilation forces otherwise; run `gofmt`, `go vet ./...`, `go test ./...` from `v8/` after each step.
- Never weaken an existing check to make a test pass; add options with safe defaults instead.
- Do not commit captured material containing real credentials or non-test keys.

### Phase 0 — Constants, ASN.1 structures, fixtures (KS-1, KS-2, parts of KS-3)

Files: `v8/iana/patype/constants.go`, `v8/iana/adtype/constants.go`, `v8/iana/nametype/constants.go`, `v8/iana/flags/constants.go`, `v8/iana/keyusage/constants.go`, new `v8/iana/msflags/constants.go`, new `v8/iana/ntstatus/constants.go`, new `v8/types/mskile.go`, new `v8/types/fast.go`, new `v8/types/mskile_test.go`, new `v8/test/testdata/mskile_vectors.go`, new `v8/test/testdata/gen/mskile_capture.md`.

Steps:
1. Add every constant listed in §3.1. Keep existing names; add new aliases rather than renaming.
2. Implement the structures in §3.1 with `Marshal`/`Unmarshal`, mirroring the style of `types/PAData.go` (`gofork/encoding/asn1`, `generalstring` tags). Little-endian binary structures (`KerbExtError`, `LSAPTokenInfoIntegrity`, `ADAuthDataAPOptions`, `PASupportedEncTypes`) use `encoding/binary` with strict length checks.
3. Add constructors: `NewKerbPAPACRequestPAData(include bool)`, `NewPAPACOptionsPAData(bits ...int)`, `NewADAuthDataAPOptionsEntry(opts uint32)`, `(PAData).GetPAPACOptions()`, etc.
4. Capture or spec-derive fixtures 1–3, 5 (structures only), 6 (PAC 17/18 payloads), 12 from §4.2. Fixtures that cannot be captured now are marked `// SPEC-DERIVED — replace with Windows capture` exactly as the MIT spec does.
5. Write round-trip tests and fixture-decode tests; add `TestFixturesDecode` entries in `test_vectors_test.go` style.

Check: `go test ./iana/... ./types/... ./test/testdata` green; `go vet ./...` clean; no behavioural change (`go test ./...` unchanged).

### Phase 1 — Parser hardening and generic authorization-data access (KS-3, KS-4, KS-8, KA-4)

Files: `v8/pac/pac_type.go`, `v8/pac/upn_dns_info.go`, `v8/pac/*_test.go`, new `v8/pac/fuzz_test.go`, `v8/types/AuthorizationData.go`, `v8/messages/Ticket.go`, `v8/messages/KRBError.go`, `v8/krberror/error.go`, `v8/service/APExchange.go`, tests alongside.

Steps:
1. In `ProcessPACInfoBuffers` validate each `InfoBuffer` (`Offset+Size <= len(Data)`, `Offset % 8 == 0`, no overlap with the header table or other buffers, `CBuffers` sane); return `ErrPACMalformed` wrapping the detail. Copy slices via a checked helper.
2. Bounds-check `UPNDNSInfo.Unmarshal` (and audit `client_info.go`, `s4u_delegation_info.go`, `credentials_info.go`, `signature_data.go` for unchecked slicing).
3. Add `FuzzPACUnmarshal` seeded with all `MarshaledPAC_*` fixtures; property: never panics.
4. Implement `AuthorizationData.Walk`/`EntriesOfType`; refactor `Ticket.GetPACType` to use it; add `TestAuthorizationDataWalkDepthLimit`.
5. Implement `KRBError.MethodData()`, `KerbErrorData()`, `NTStatus()`; make `krberror.Krberror` expose the underlying `KRBError` (`errors.As`) and print the NTSTATUS name when present.
6. Add `TestVerifyAPREQIgnoresKerbLocalAndRestrictionEntry` using fixture 5 structures injected into an authenticator built by the existing service tests.

Check: `go test ./pac/... ./types/... ./messages/... ./service/...` green; `go test -run XXX -fuzz FuzzPACUnmarshal -fuzztime 30s ./pac` no crashes.

### Phase 2 — Client AS/TGS MS-KILE behaviour (KC-1, KC-2, KC-3, KC-4, KC-7, KC-16, KC-15, KC-17)

Files: `v8/messages/KDCReq.go`, `v8/messages/KDCRep.go`, `v8/client/ASExchange.go`, `v8/client/TGSExchange.go`, `v8/client/client.go`, `v8/client/session.go`, `v8/client/cache.go`, `v8/credentials/credentials.go`, `v8/config/krb5conf.go`, `v8/config/hosts.go`, `v8/kadmin/message.go`, `v8/cmd/gokinit/main.go`, `v8/cmd/internal/krbcli/*.go`, tests alongside.

Steps:
1. Add `types.RealmEqual`; replace realm `==`/`!=` comparisons in `messages` verification, `client` session/cache lookups (normalise keys to upper case), and `config` realm lookups.
2. `ASReqOptions.IncludePAC *bool` and `Config.LibDefaults.RequestPAC` (parse `request_pac`); emit KERB-PA-PAC-REQUEST by default.
3. `ASRep.Verify`/`TGSRep.Verify`: accept `cname` change when `canonicalize` was set or the request name type was `KRB_NT_ENTERPRISE`; if PA-REQ-ENC-PA-REP was requested, require successful verification before accepting. Update `Credentials` with the canonical name and realm; keep the original for display.
4. Parse `EncPAData` for PA-SUPPORTED-ENCTYPES → `session.supportedEncTypes`; parse PA-SVR-REFERRAL-INFO and prefer its realm in `TGSExchange` referral handling.
5. `TGSReqOptions{PACOptions, IncludePAC}`; emit PA-PAC-OPTIONS with Claims when advertised and Branch-Aware always; TGS `etype` list: when the target advertises `AES256_CTS_HMAC_SHA1_96_SK`, keep AES256 first even for RC4 tickets.
6. `config/hosts.go`: SRV order `_kerberos._tcp.dc._msdcs.<realm>`, then existing; `_kpasswd`; optional `ad_site`.
7. `kadmin`: decode the 30-byte policy blob (`Version, MinLength, History, Properties, ExpireIn, MinAge`) into `PasswordPolicy` when present.
8. `gokinit`: print NTSTATUS detail after the MIT-style message.

Check: `go test ./...` green; `INTEGRATION=1` MIT suites green (MIT ignores the new PA-DATA); with the Samba container or a live domain `TESTAD=1 go test ./client -run 'Enterprise|NTStatus|SupportedEncTypes'` green.

### Phase 3 — GSS initiator/acceptor core: channel bindings, delegation, mutual auth, DCE style (KC-8, KC-9, KC-10, KC-11, KA-3, KA-5, KA-8)

Files: new `v8/gssapi/channelBindings.go`, new `v8/gssapi/authenticatorChecksum.go`, `v8/gssapi/contextFlags.go`, `v8/spnego/krb5Token.go`, `v8/spnego/negotiationToken.go`, `v8/spnego/http.go`, `v8/service/settings.go`, `v8/service/APExchange.go`, `v8/messages/APReq.go`, `v8/messages/APRep.go`, `v8/messages/KRBCred.go`, `v8/client/client.go` (forwarded-TGT request helper), `v8/credentials/credentials.go`, tests alongside.

Steps:
1. Implement `ChannelBindings`, `MD5Hash`, `TLSServerEndPoint`, `TLSUnique`.
2. Replace `newAuthenticatorChksum` with a typed `AuthenticatorChecksum{Bnd, Flags, Deleg}` marshaller/unmarshaller (RFC 4121 §4.1.1) including `Exts`.
3. `NewKRB5TokenAPREQ` options: bindings, flags, delegate. Delegation: request a forwarded TGT via TGS-REQ (`forwarded`, `forwardable`, acceptor addresses optional), build KRB-CRED (usage 14, session key), honour `ok-as-delegate` unless forced. Add `AD-IF-RELEVANT[AD-AUTH-DATA-AP-OPTIONS{CBT}]` to the authenticator when bindings are given.
4. Acceptor: parse the checksum; enforce `Settings.ExtendedProtection` policy; extract delegated KRB-CRED into `Credentials.DelegatedCredentials()`; verify `sname` against `Settings.ServicePrincipals()` (default: all keytab principals) — KA-8.
5. Mutual auth: build AP-REP (`ctime`, `cusec`, `subkey`, `seq-number`) and return it as SPNEGO `responseToken` with `accept-completed`; client verifies AP-REP and stores subkey/seq for per-message tokens. DCE style: acceptor keeps state for the third leg; client sends it.
6. Tests: §4.3 gssapi/spnego/service items with fixture 5; policy matrix test.

Check: `go test ./gssapi/... ./spnego/... ./service/... ./client/...` green; Samba integration items 5–7 green.

### Phase 4 — PAC completeness and application-server validation (KS-5, KS-6, KS-7, KA-1, KA-2)

Files: `v8/pac/pac_type.go`, `v8/pac/upn_dns_info.go`, new `v8/pac/attributes_info.go`, new `v8/pac/requestor.go`, new `v8/pac/marshal.go`, new `v8/pac/verify_options.go`, `v8/pac/*_test.go`, `v8/credentials/credentials.go`, `v8/service/APExchange.go`, `v8/spnego/http.go`, `USAGE.md`.

Steps:
1. Add buffers 16–19 and the `ZeroSigData` handling for 16/19 per MS-PAC §2.8.
2. Fix `UPNDNSInfo` flags; add `S` extension fields.
3. Implement `PACType.Marshal`, per-buffer `Marshal`, `Sign(serverKey, kdcKey, ticketKey?)`; if `rpc/v2/ndr` lacks an encoder, add a minimal one under `v8/pac/internal/ndrw` for the types used (document in §7).
4. Implement `Verify(key, VerifyOptions)` with the KA-1 rules; default options replicate current behaviour plus client-info checks (fail closed on mismatch), `RequestorSID` enforced when present.
5. Expand `credentials.ADCredentials`; populate in `VerifyAPREQ`; document context access in `USAGE.md`.
6. Negative tests built with the marshaller: tampered server checksum, duplicate KERB_VALIDATION_INFO, misaligned offset, requestor mismatch, client-info name mismatch, `S`-extension SID mismatch; `FuzzPACUnmarshal` reseeded with marshalled outputs.

Check: `go test ./pac/... ./service/... ./credentials/...` green; fixture 6 PACs verify; `go test -fuzz FuzzPACUnmarshal -fuzztime 30s ./pac` clean.

### Phase 5 — Legacy RC4 GSS tokens and SPNEGO mechListMIC (KC-12, KA-6, KA-9)

Files: new `v8/gssapi/rc4Tokens.go`, new `v8/gssapi/context.go` (token-family selection, sequence window), `v8/gssapi/MICToken.go`, `v8/gssapi/wrapToken.go`, `v8/spnego/negotiationToken.go`, `v8/spnego/spnego.go`, `v8/spnego/http.go`, `v8/crypto/rfc4757/*.go` (export `HMAC` helpers if needed), tests alongside.

Steps:
1. Implement RFC 4757 §7 token formats with RFC 2743 framing; key derivations per §7.3 (`Ksign`, `Kseq`, `Klocal`, `Kcrypt`) using existing `rfc4757` primitives.
2. Implement `gssapi.Context` (`Wrap/Unwrap/GetMIC/VerifyMIC`, initiator/acceptor direction bits, 64-entry sequence window) choosing legacy tokens when the key etype is `RC4_HMAC`.
3. SPNEGO: compute `mechListMIC` (MIC over DER `MechTypeList`) when MS-SPNG requires; verify incoming MICs; parse NegTokenInit2 `negHints`; make the legacy-OID-first preference configurable.
4. Tests: RFC 4757 vectors, Windows captures (fixture 7, 8), `TestContextSelectsLegacyTokensForRC4`, replay-window tests, `FuzzRC4Tokens`.

Check: `go test ./gssapi/... ./spnego/...` green; Samba integration item 3 green; fuzz clean.

### Phase 6 — S4U2self, S4U2proxy, RBCD (KC-5, MS-SFU)

Files: new `v8/client/s4u.go`, `v8/messages/KDCReq.go` (`NewS4U2SelfTGSReq`, `NewS4U2ProxyTGSReq`), `v8/messages/KDCRep.go` (verify PA-S4U-X509-USER reply checksum), `v8/client/TGSExchange.go` (referral handling for S4U per MS-SFU §3.1.5), `v8/krberror/error.go` (`ErrDelegationNotPermitted`, `ErrProtocolTransitionNotPermitted`), `v8/credentials/credentials.go` (`S4UDelegationInfo` exposure already from Phase 4), tests alongside, `USAGE.md`.

Steps:
1. PA-FOR-USER builder with HMAC-MD5 checksum exactly per MS-SFU §2.2.1 (byte order and concatenation), keyed with the TGT session key, usage 17.
2. PA-S4U-X509-USER builder (usage 26) and reply verification (usage 27); send both when the KDC advertises support (Windows 2008+); fall back to PA-FOR-USER only on `KDC_ERR_PADATA_TYPE_NOSUPP`.
3. S4U2self flow including cross-realm user (obtain referral TGT for the user's realm, retry there, then present to own realm per MS-SFU §3.1.5.1.1); expose whether the ticket is `forwardable`.
4. S4U2proxy flow: `cname-in-addl-tkt`, evidence ticket in `additional-tickets`, RBCD bit in PA-PAC-OPTIONS on request; cross-realm target via referral TGT (MS-SFU §3.1.5.2.2); map KDC errors + NTSTATUS to typed errors.
5. Cache S4U tickets under `(user, spn)` keys separate from the client's own tickets.
6. Tests: unit with fixture 4; Samba integration item 4 (classic, RBCD, protocol transition on/off, unauthorised target).

Check: `go test ./client/... ./messages/...` green; `TESTAD=1` S4U suite green against Samba; MIT suite unchanged.

### Phase 7 — FAST armoring, encrypted challenge, compound identity, claims (KC-6)

Files: new `v8/messages/fast.go`, new `v8/client/fast.go`, `v8/client/ASExchange.go`, `v8/client/TGSExchange.go`, `v8/client/settings.go`, `v8/crypto/crypto.go` (`KRBFXCF2` — check `v8/crypto/common` first), `v8/messages/KDCRep.go`, `v8/messages/KRBError.go`, tests alongside, `USAGE.md`.

Steps:
1. Implement `KRB-FX-CF2` (RFC 6113 §5.1) with test vectors from RFC 6113 appendix / MIT `t_cf2`.
2. Armor acquisition: explicit `(ticket, key)` option or keytab-based armor AS exchange; armor key derivation; `FX_FAST_ARMOR_AP_REQUEST`.
3. Wrap AS-REQ/TGS-REQ into PA-FX-FAST; implement PA-ENCRYPTED-CHALLENGE pre-auth; carry PA-FX-COOKIE; unwrap PA-FX-FAST replies (strengthen key, `KrbFastFinished` ticket checksum) and PA-FX-ERROR.
4. `RequireFAST` fail-closed; auto-FAST when armor is available and the KDC advertised `FAST_SUPPORTED` (from Phase 2 metadata) or returned PA-FX-FAST in the preauth-required error.
5. Claims: request via PA-PAC-OPTIONS; compound identity verified through PAC_DEVICE_INFO presence in integration tests.
6. Tests: round-trips with fixture 9; `TestFASTEncryptedChallenge`, `TestFASTErrorUnwrap`, `TestFASTStrengthenKey`; Samba integration items 8–9; MIT `kdc-latest` FAST regression (MIT supports FAST — reuse containers).

Check: `go test ./...` green; MIT FAST test green; Samba FAST/claims tests green.

### Phase 8 — KKDCP transport (KC-13)

Files: new `v8/client/kkdcp.go`, `v8/client/network.go`, `v8/config/krb5conf.go` (`kdc = https://…`, `kpasswd_server = https://…`), `v8/config/hosts.go`, `v8/kadmin/passwd.go` / `v8/client/passwd.go`, `v8/client/settings.go` (`HTTPClient`), tests with `httptest`, `USAGE.md`.

Steps:
1. `KDC-PROXY-MESSAGE` ASN.1 type in `v8/types` (Phase 0 may pre-add it) with marshal/unmarshal.
2. When a resolved KDC entry has scheme `https`, send via POST with 4-byte-length-prefixed message, `Content-Type: application/kerberos`, `target-domain` = realm; parse reply; map HTTP errors to `NetworkingError`.
3. Apply the same path to kpasswd when `kpasswd_server` is `https://`.
4. Tests: `TestKKDCPTransport` with an `httptest` server that unwraps and forwards to a fake KDC responder; config parsing tests; Samba integration item 10 with a `kdcproxy` sidecar.

Check: `go test ./client/... ./config/...` green; integration item 10 green.

### Phase 9 — PKINIT compliant with MS-PKCA (KC-14, KP-1 … KP-9)

Files: new package `v8/pkinit/` (`asn1.go`, `cms.go`, `identity.go`, `dh.go`, `kdf.go`, `kdccert.go`, `client.go`, `errors.go`, `pkinit_test.go`, `fuzz_test.go`), `v8/client/ASExchange.go` (PA-PK-AS-REQ path and PKINIT error retries), `v8/client/settings.go` (`PKINITIdentity`, `PKINITAnchors`, `RequireFreshness`, `PKINITOCSPResponse`), `v8/client/client.go` (`PKINITCredentials()`), `v8/config/krb5conf.go` (`pkinit_*` keys), `v8/pac/pac_type.go` + `v8/pac/credentials_info.go` (decrypt buffer 2 with a supplied reply key), `v8/iana/errorcode` (verify all PKINIT codes present), `v8/cmd/gokinit` (`-X` options, PIN prompt), `go.mod` (only if Open Question 10 selects a dependency), `v8/test/testdata/mskile_vectors.go` (fixture 11), tests alongside, `USAGE.md`.

Steps:
1. ASN.1 structures from §3.9 including RFC 8636 `supportedKDFs`/`kdf`, RFC 8070 `freshnessToken`, `TD-*` typed data, `KRB5PrincipalName`, and the PA-PK-AS-REQ-OLD recogniser; round-trip tests against fixture 11 and the RFC 4556 examples.
2. CMS subset per §3.9 with sign/verify and RSA `EnvelopedData`; `FuzzCMS`.
3. `Identity` loaders (PEM, PKCS#12, `crypto.Signer`) and MS-PKCA client-certificate selection rules with `pkinit_eku_checking` modes and key-trust mode.
4. DH (groups 2/14/16, `pkinit_dh_min_bits`) and RSA reply-key paths; `octetstring2key` and RFC 8636 KDF with vectors; `ReplyKeyPack.asChecksum` verification.
5. KDC certificate validation per §3.9 step 5, including revocation policy and `dhKeyExpiration`; negative tests for wrong EKU, wrong `dNSName`, expired chain, revoked certificate.
6. Wire the AS exchange: preauth-required detection, freshness token echo, PA-PK-OCSP-RESPONSE, typed error mapping with `TD-*` decoding, single retry on `KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED` and `KDC_ERR_NO_ACCEPTABLE_KDF`.
7. Decrypt `PAC_CREDENTIAL_INFO` with the reply key; expose via `client.Client.PKINITCredentials()`; ensure `service` never surfaces it.
8. `krb5.conf` `pkinit_*` parsing and `gokinit -X` options with PIN prompt; `goklist` unchanged.
9. Tests: §4.3 `pkinit` list; Samba integration item 11; Windows manual checklist entries for DH, RSA, KDF, freshness, untrusted cert, smart-card signer.

Check: `go test ./pkinit/... ./client/... ./pac/... ./cmd/...` green; `go test -fuzz FuzzPKASRep -fuzztime 30s ./pkinit` and `FuzzCMS` clean; Samba PKINIT test green; MIT `kdc-latest` PKINIT (MIT supports RFC 4556) regression green.

### Phase 10 — Mechanism abstraction and NEGOEX (KN-1, KN-2, KN-4, KN-5)

Files: new `v8/gssapi/mechanism.go` (`Mechanism`, `Context` interfaces; `NegoExKey()`/`NegoExVerifyKey()` on the KRB5 context), `v8/gssapi/gssapi.go` (OIDs `OIDNegoEx`, `OIDPKU2U`), new package `v8/negoex/` (`message.go`, `vectors.go`, `conversation.go`, `verify.go`, `scheme_kerberos.go`, `negoex_test.go`, `fuzz_test.go`), `v8/spnego/negotiationToken.go`, `v8/spnego/spnego.go`, `v8/spnego/http.go`, `v8/iana/keyusage/constants.go`, `v8/test/testdata/mskile_vectors.go` (fixture 13), tests alongside, `USAGE.md`.

Steps:
1. Define `gssapi.Mechanism`/`gssapi.Context`; adapt the existing KRB5 initiator/acceptor (`spnego/krb5Token.go`, Phase 3/5 context) to implement them without changing exported behaviour. Implement the KRB5 NEGOEX key derivation with the GSS PRF (RFC 4401) mirroring MIT's `krb5_gss_inquire_sec_context_by_oid`; add the verified key-usage constants.
2. Implement NEGOEX structures and vector encoding with strict bounds checks; `FuzzNegoExUnmarshal` seeded with fixture 13.
3. Implement the conversation state machine for initiator and acceptor (scheme intersection, optimistic `AP_REQUEST`, `CHALLENGE` loop, `VERIFY` computation/validation over the message log, `ALERT` handling, NTSTATUS mapping).
4. Register the Kerberos scheme; wire NEGOEX into `spnego` as a negotiable mechanism with configurable ordering; make the SPNEGO acceptor select the first mutually supported mechanism when the optimistic token is for an unsupported one (KN-2) and add `TestOptimisticNegoExTokenSelectsKRB5`.
5. Tests: §4.3 `negoex` and `spnego` items; MIT interop job (`gss-client`/`gss-server` with NEGOEX) in CI.

Check: `go test ./gssapi/... ./negoex/... ./spnego/...` green; `go test -fuzz FuzzNegoExUnmarshal -fuzztime 30s ./negoex` clean; MIT NEGOEX interop green; existing SPNEGO tests unchanged.

### Phase 11 — PKU2U (KN-3)

Files: new package `v8/pku2u/` (`names.go`, `metadata.go`, `initiator.go`, `acceptor.go`, `ticket.go`, `pku2u_test.go`, `fuzz_test.go`), `v8/pkinit` (export the AS-REQ/AS-REP PKINIT builders and reply-key derivation for reuse), `v8/negoex/scheme_pku2u.go`, `v8/credentials/credentials.go` (`CertificateIdentity` on the acceptor side), `v8/spnego/http.go` (acceptor option to enable PKU2U), `v8/test/testdata/mskile_vectors.go` (fixture 14), tests alongside, `USAGE.md`.

Steps:
1. Implement `WELLKNOWN:PKU2U` realm handling and certificate-to-principal mapping (UPN SAN, subject fallback) with unit tests.
2. Implement metadata encoding/decoding (trusted certifiers) and selection of a certificate acceptable to the peer.
3. Initiator: build the PKINIT AS-REQ for the acceptor name, process AS-REP, send AP-REQ with mutual flag; complete on AP-REP; derive the context key from the AP-REP subkey.
4. Acceptor: validate the initiator certificate (anchors + metadata), act as KDC — generate the ticket key, issue AS-REP with PA-PK-AS-REP (DH), retain the key for the conversation, verify AP-REQ, return AP-REP.
5. Register PKU2U as a NEGOEX scheme and as a standalone SPNEGO mechanism; expose `CertificateIdentity` in the HTTP context.
6. Tests: §4.3 `pku2u` items; gokrb5↔gokrb5 end-to-end over NEGOEX in CI; fixture 14 decode tests; Windows manual checklist entries.

Check: `go test ./pku2u/... ./negoex/... ./spnego/...` green; fuzz clean; end-to-end CI test green.

### Phase 12 — Samba AD DC CI, Windows manual suite, fuzz jobs, documentation (all EC items)

Files: new `v8/test/testdata/docker/samba-ad-dc/` (Dockerfile, provisioning script creating the accounts in §4.1 and exporting `krb5.keytab`, `user`, `pw` for `test/ad`), `.github/workflows/testingv8.yml` (new jobs `ad-samba` with `TESTAD=1 TESTAD_REALM=… TESTAD_DIR=… INTEGRATION=1`, `negoex-mit`, and 60 s fuzz jobs for all fuzz targets), `v8/test/ad/ad.go` (add `Kind()` reporting `samba|windows` from the discovered KDC so tests can skip Windows-only or Samba-only cases), new `v8/test/adintegration/*_test.go` (build tag `adintegration`) implementing §4.4 items 1–14, `v8/USAGE.md`, `v8/README.md`, `v8/CHANGELOG.md`, this document (§7 resolutions, status → Implemented).

Steps:
1. Build and pin the Samba container; provision users, service accounts, delegation attributes, claims, CA and computer account; export keytabs into `testdata` (test-only secrets). Add the MIT ≥ 1.18 image used for NEGOEX interop.
2. Implement §4.4 tests; each skips without the gate.
3. Add CI jobs; ensure runtime < 15 min.
4. Document every new API/setting; update feature tables; write the Windows manual-run checklist (`docs/design/ms-kile-windows-checklist.md`) including NEGOEX and PKU2U scenarios.
5. Re-audit: rerun the survey in §2 against the final code; every finding must map to a passing test or a §7 resolution.

Check: all §5 checkboxes ticked; CI green; Windows checklist executed once and recorded.

---

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
12. **NEGOEX key derivation (Phase 10)** — Confirm the exact GSS PRF inputs and key-usage numbers used for `GSS_C_INQ_NEGOEX_KEY`/`GSS_C_INQ_NEGOEX_VERIFY_KEY` by reading MS-NEGOEX §2.2.5/§3.1.5 and MIT `src/lib/gssapi/krb5/inq_context.c`; capture a Windows `VERIFY` and recompute it before finalising.
13. **NEGOEX auth-scheme GUIDs (Phase 10/11)** — Take the Kerberos and PKU2U scheme GUIDs from the current MS-NEGOEX/MS-PKU2U revisions (and MIT `negoex_util.c`), not from memory; add a test that decodes fixture 13 with them.
14. **PKU2U acceptor certificate rules (Phase 11)** — Determine which EKU/SAN rules MS-PKU2U applies to the acceptor certificate (it is not a KDC certificate under MS-PKCA) and whether Azure-AD-style certificates require additional name mapping; decide the default anchors policy.
15. **PKU2U without NEGOEX (Phase 11)** — Windows only negotiates PKU2U via NEGOEX; decide whether the standalone SPNEGO mechanism is exposed by default or behind an option to avoid advertising an OID Windows will never select.
16. **MS-PKCA KDC certificate name rule (Phase 9)** — Confirm from the current MS-PKCA §3.2.5.2 whether the `dNSName` SAN must equal the realm's DNS domain, the responding DC's FQDN, or either; capture DC certificates issued by the default "Kerberos Authentication" template (which carries both) and the older "Domain Controller" template.
17. **RFC 8636 KDF selection by Windows (Phase 9)** — Verify which `kdfId` values Windows Server 2012–2022 select when offered SHA-256/384/512, and whether omitting `supportedKDFs` still yields `octetstring2key`; fixtures must cover both.
18. **Freshness enforcement (Phase 9)** — Confirm the KRB-ERROR code and e-data Windows returns when the freshness extension is required but absent, so `RequireFreshness`/retry logic matches.
19. **Key-trust identities (Phase 9)** — Confirm the AuthPack/CMS shape Windows Hello key-trust clients send (self-signed certificate vs. bare public key) before implementing KP-8.
