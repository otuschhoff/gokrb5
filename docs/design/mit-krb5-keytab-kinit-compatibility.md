# Design Spec: MIT krb5 Compatibility — Keytab Handling and `kinit`

Status: Draft
Scope: `v8` module (`github.com/jcmturner/gokrb5/v8`)
Reference implementation: MIT Kerberos 5 (krb5 ≥ 1.18; verify against latest stable)

---

## 1. Goal

gokrb5 must be a drop-in peer to MIT krb5 for:

1. **Keytab handling** — create, write, read and modify keytab files such that
   - any keytab produced by MIT tools (`ktutil`, `kadmin ktadd`, `k5srvutil`, `kadmin.local ktadd`) is read correctly by gokrb5, and
   - any keytab produced by gokrb5 is read correctly by MIT tools (`klist -kte`, `kinit -kt`, `kvno`, `ktutil rkt`) and yields identical key lookup results.
2. **`kinit` support** — obtaining an initial TGT from
   - an interactively entered password, and/or
   - a keytab,
   with MIT-equivalent request semantics, credential-cache output that MIT `klist`/`kdestroy`/`kvno` can consume, and MIT-equivalent option handling.

"Compatible" means: same on-disk bytes where the format is deterministic, same lookup/selection results, same wire-level AS-REQ semantics, and interoperable artifacts (keytab, ccache) in both directions.

Out of scope for this spec: PKINIT, anonymous PKINIT, FAST armor (`kinit -T`), OTP, `KEYRING:`/`DIR:`/`KCM:`/`MEMORY:` ccache types, `KDB:`/`MEMORY:` keytab types, `kswitch`, `kinit -n`, `kinit -X`.

---

## 2. Current Implementation — Findings

Sources reviewed: [v8/keytab/keytab.go](../../v8/keytab/keytab.go), [v8/keytab/keytab_test.go](../../v8/keytab/keytab_test.go), [v8/credentials/ccache.go](../../v8/credentials/ccache.go), [v8/credentials/credentials.go](../../v8/credentials/credentials.go), [v8/client/client.go](../../v8/client/client.go), [v8/client/ASExchange.go](../../v8/client/ASExchange.go), [v8/client/session.go](../../v8/client/session.go), [v8/client/settings.go](../../v8/client/settings.go), [v8/crypto/crypto.go](../../v8/crypto/crypto.go), [v8/messages/KDCReq.go](../../v8/messages/KDCReq.go), [v8/messages/KDCRep.go](../../v8/messages/KDCRep.go), [v8/config/krb5conf.go](../../v8/config/krb5conf.go), [v8/types/PrincipalName.go](../../v8/types/PrincipalName.go).

### 2.1 Keytab — what exists

| Capability | Status | Location |
|---|---|---|
| Read v2 (big-endian) keytab | Works; byte-exact round-trip verified against `ktutil` output for AES128/256-SHA1 and RC4 | `Unmarshal`, `TestKeytabEntriesUser/Service` |
| Read v1 (native-endian) keytab | Implemented, untested with a real MIT v1 fixture | `Unmarshal`, `parsePrincipal` |
| Skip deleted "hole" records (negative length) | Implemented | `Unmarshal` |
| 32-bit KVNO trailer | Read if ≥4 bytes remain; written always | `Unmarshal`, `entry.marshal` |
| Create empty keytab | `New()` → version 2 | |
| Add entry from password | `AddEntry(principal, realm, password, ts, kvno uint8, etype)` — default salt only | |
| Write | `Marshal()`, `Write(io.Writer)` | |
| Key lookup | `GetEncryptionKey(princ, realm, kvno, etype)` | |
| Display | `String()` (custom format), `JSON()` | |

### 2.2 Keytab — defects and gaps to fix

Numbered for traceability (`KT-n`).

| ID | Finding | Severity |
|---|---|---|
| KT-1 | `Unmarshal` discards the error returned by `parsePrincipal` (`parsePrincipal(eb, &p, kt, &ke, &endian)` with no assignment). A truncated principal silently yields a garbage entry. | High |
| KT-2 | `GetEncryptionKey` with `kvno == 0` selects the entry with the **newest timestamp**, not the **highest kvno**. MIT (`krb5_ktfile_get_entry`, `kt_file.c`) selects the highest kvno when kvno is unspecified. Merged keytabs with out-of-order timestamps produce different keys. | High |
| KT-3 | `GetEncryptionKey` requires an exact `etype` match; no wildcard (`etype == 0` → any) as in MIT. MIT also treats "similar" enctypes (e.g. DES variants) as matching — document as unsupported (DES not implemented). | Medium |
| KT-4 | `GetEncryptionKey` requires exact realm match. MIT matches any realm when the lookup principal's realm is empty. | Medium |
| KT-5 | `GetEncryptionKey` has no 8-bit kvno wrap-around handling. MIT matches an entry whose stored kvno is `kvno & 0xff` when only the 8-bit field was written (legacy writers). | Low |
| KT-6 | 32-bit kvno trailer is read for **v1** files too. MIT only reads the trailer for v2 (`KRB5_KT_VNO`). | Low |
| KT-7 | v1 round-trip is broken: `parsePrincipal` decrements `NumComponents` on read, `principal.marshal` writes it back unchanged, so v1 → marshal → v1 writes the wrong count. `NumComponents` should be derived from `len(Components)` at marshal time, not stored. | Medium |
| KT-8 | `AddEntry` accepts `KVNO uint8`. kvnos > 255 are common (AD, long-lived service principals). MIT writes `vno & 0xff` to the 8-bit field and the full value to the 32-bit trailer. | High |
| KT-9 | `entry.String()` prints `KVNO8`, not `KVNO`. For kvno ≥ 256 the display is wrong (MIT `klist -k` shows the 32-bit value). | Medium |
| KT-10 | `AddEntry` derives the key with the RFC 4120 default salt only. No way to (a) supply a salt (AD host principals, `ktutil addent -salt`), (b) supply s2kparams/iterations, or (c) add an entry from raw key bytes (what `kadmin ktadd` does — it never has the password). | High |
| KT-11 | No API to **modify**: remove an entry, remove all entries for a principal, remove entries with kvno < N (`kadmin ktremove princ old`), keep-only-latest-kvno, or merge two keytabs (`ktutil rkt`+`wkt`). `Entries` is exported but its element type `entry` is unexported, so callers cannot construct or filter entries themselves. | High |
| KT-12 | No file-level write helper. MIT creates keytabs `0600`, uses `krb5_lock_file` while appending, and appends (never rewrites) on `ktadd`. gokrb5 needs `WriteFile(path)` with atomic write (temp + `rename`), `0600`, and an `Append`-safe path, otherwise concurrent `ktadd` from MIT tools can corrupt the file. | Medium |
| KT-13 | `Unmarshal` on a keytab that already has entries appends to `Entries` (no reset). Calling `Unmarshal` twice duplicates entries. | Low |
| KT-14 | Error messages format raw bytes with `%s` (`fmt.Errorf("%s's length is less than %d", b, …)`), dumping binary key material into logs. | Medium (security) |
| KT-15 | Zero-length record (`l == 0`) terminates parsing. MIT behaviour for a zero-length record must be verified (`kt_file.c: krb5_ktfileint_internal_read_entry`); trailing zero padding is common when a hole is created at EOF. | Low |
| KT-16 | No default keytab resolution: `KRB5_KTNAME`, `KRB5_CLIENT_KTNAME`, `[libdefaults] default_keytab_name`, `default_client_keytab_name`, `FILE:`/`WRFILE:` prefix stripping, `%{euid}`/`%{uid}`/`%{username}` parameter expansion. `config.LibDefaults.DefaultKeytabName` is parsed but never used. | Medium |
| KT-17 | No `klist -kte`-compatible text rendering. Useful for diff-based interoperability tests and for a `gokrb5 klist -k` tool. | Low |
| KT-18 | No exported accessor for the keytab version, and no way to request writing v1 (MIT can still read v1; writing v1 is not required — read-only support is sufficient). | Low |
| KT-19 | `JSON()` serialises raw key material. Acceptable but should be documented, and a redacted mode is preferable for logging. | Low |

### 2.3 `kinit` — what exists

| Capability | Status | Location |
|---|---|---|
| AS exchange with password | Works: PA-ENC-TIMESTAMP, `KDC_ERR_PREAUTH_REQUIRED` retry, salt and s2kparams from ETYPE-INFO2 | `Client.Login`, `ASExchange`, `setPAData`, `crypto.GetKeyFromPassword` |
| AS exchange with keytab | Works when the keytab contains the etype the KDC selects | same, `Client.Key`, `ASRep.DecryptEncPart` |
| Client referrals (`KDC_ERR_WRONG_REALM`) | Works (max 5) | `ASExchange` |
| Load client state from a ccache | Works (v1–v4 read) | `credentials.LoadCCache`, `client.NewFromCCache` |
| TGT renewal | Works (TGS renew), auto-renew goroutine | `renewTGT`, `enableAutoSessionRenewal` |
| Options from krb5.conf | `forwardable`, `proxiable`, `canonicalize`, `ticket_lifetime`, `renew_lifetime`, `noaddresses`, `default_tkt_enctypes`, `kdc_default_options` | `messages.NewASReq` |
| Change password | `Client.ChangePasswd` (RFC 3244) | `client/passwd.go` |

### 2.4 `kinit` — defects and gaps to fix

Numbered `KI-n`.

| ID | Finding | Severity |
|---|---|---|
| KI-1 | **No ccache writer.** `credentials.CCache` has `Unmarshal` only. A `kinit` cannot exist without `Marshal`/`WriteFile` producing MIT FILE ccache v4 (header with KDC time-offset tag, default principal, credentials, `X-CACHECONF:` config entries). This is the largest gap. | Blocker |
| KI-2 | `ccache.Unmarshal` and its `read*` helpers do no bounds checking; truncated or malicious ccache files panic. `parseHeader` compares an absolute offset (`*p`) with a relative length (`h.length`) — correct only by coincidence for the standard 12-byte header. | High |
| KI-3 | `messages.NewASReq` overwrites `RTime`: `a.ReqBody.RTime = t.Add(c.LibDefaults.RenewLifetime)` is immediately followed by `a.ReqBody.RTime = t.Add(48 * time.Hour)`. `renew_lifetime`/`kinit -r` is ignored. | High |
| KI-4 | `setPAData` derives the pre-auth etype from `LibDefaults.PreferredPreauthTypes[0]`. In MIT `preferred_preauth_types` is a list of **PA-DATA types** (17=PKINIT…, 16, 15, 14), not enctypes; it only "works" because 17 happens to be `aes128-cts-hmac-sha1-96`. Must use the first `DefaultTktEnctypeIDs` entry that the credential can produce a key for (for a keytab: an etype present in the keytab). | High |
| KI-5 | `crypto.GetKeyFromPassword` uses `ETYPE-INFO2[0]` / `ETYPE-INFO[0]` unconditionally and, when that etype differs from the requested one, derives the key with the **other** etype but labels the result with the requested `etypeID` (`key.KeyType = etypeID`). Must select the ETYPE-INFO2 entry whose etype equals the one being used, and set `KeyType` from the etype actually used. `client.preAuthEType` has the same `[0]` assumption. | High |
| KI-6 | With a keytab, the AS-REQ `etype` list is `DefaultTktEnctypeIDs` from config regardless of what keys the keytab holds. MIT (`krb5_get_init_creds_keytab`, `get_in_tkt.c`) restricts the request enctypes to those present in the keytab for the client principal, so the KDC never issues a reply the client cannot decrypt. | High |
| KI-7 | No interactive password prompt, no CLI. Need a `kinit`-equivalent command (proposed `v8/cmd/gokinit`) using `golang.org/x/term.ReadPassword` on `/dev/tty`, honouring `KRB5CCNAME`, `KRB5_CONFIG`, `KRB5_KTNAME`, `KRB5_CLIENT_KTNAME`. | High |
| KI-8 | No default ccache name resolution: `KRB5CCNAME` → `[libdefaults] default_ccache_name` (with `%{uid}`, `%{euid}`, `%{username}`, `%{TEMP}` expansion) → `FILE:/tmp/krb5cc_%{uid}`. `FILE:` prefix must be accepted and stripped; other types must be rejected with a clear error. | High |
| KI-9 | Principal defaulting differs from MIT `kinit`: no principal → default principal of existing ccache, else `$USER@default_realm`; `-k` with no principal → `host/<canonical fqdn>@default_realm`; principal without `@REALM` → `default_realm`. `client.New*` documentation says an empty realm uses the default realm but `IsConfigured` rejects it. | Medium |
| KI-10 | Clock skew: MIT retries the AS exchange once after `KRB_AP_ERR_SKEW`/`KDC_ERR_PREAUTH_FAILED` using the KDC time from the KRB-ERROR (`kdc_timesync`), and stores the offset in the ccache header (tag 1). gokrb5 has `KDCTimeSync` config but no implementation. | Medium |
| KI-11 | `KDC_ERR_KEY_EXPIRED`: MIT `kinit` prompts for a new password and retries. gokrb5 returns the error. Implement in the CLI using `Client.ChangePasswd`. | Low |
| KI-12 | Enterprise principals (`kinit -E`, `KRB_NT_ENTERPRISE`): `credentials.New` splits the username on `/`; `types.ParseSPNString` splits on the last `@`. An enterprise name `user@corp.example@REALM` must become a single component with name type 10. | Low |
| KI-13 | `Settings.DisablePAFXFAST` actually controls `PA_REQ_ENC_PA_REP` (RFC 6806 §11), not FAST. Rename/document; keep the old name as a deprecated alias. | Low |
| KI-14 | Ticket-flag handling for `-f/-F`, `-p/-P`, `-a/-A`, `-C` (canonicalize), `-l`, `-r`, `-s` (start time / postdated), `-S service`, `-v` (validate) is only reachable via `config.LibDefaults`. The CLI needs per-invocation overrides that take precedence over krb5.conf. `-s` and `-v` may be deferred. | Medium |
| KI-15 | ccache `GetEntries` filters `X-CACHECONF:` entries when loading; the writer must be able to emit them (`fast_avail`, `pa_type`, `refresh_time` for keytab-based caches) so MIT `kinit -R`/GSSAPI auto-refresh behaves identically. | Medium |
| KI-16 | Password-keytab preference: `Credentials.WithPassword` clears the keytab and vice versa. MIT `kinit -k` with a password-less principal must still work; `kinit` without `-k` must never read the keytab. Behaviour is compatible; add tests to lock it. | Low |

---

## 3. Target Design

### 3.1 Keytab package (`v8/keytab`)

#### 3.1.1 Exported data model

```go
// Entry is one keytab record. Exported so callers can inspect, filter and construct entries.
type Entry struct {
    Principal Principal
    Timestamp time.Time
    KVNO      uint32               // authoritative version number
    Key       types.EncryptionKey
}

type Principal struct {
    Realm      string
    Components []string
    NameType   int32
}

type Keytab struct {
    version uint8
    Entries []Entry
}
```

- `KVNO8` is removed from the model; it is computed as `uint8(KVNO & 0xff)` during marshal and reconciled during unmarshal (32-bit trailer wins when non-zero, else the 8-bit value).
- `NumComponents` is removed; computed at marshal time (`len(Components)`, `+1` for v1).
- Migration: keep `entry`/`principal` as type aliases for one minor release (`type entry = Entry`) to avoid breaking `kt.Entries[i].Principal.Realm` style access.

#### 3.1.2 Read

- `Load(path string) (*Keytab, error)` — accepts `FILE:`/`WRFILE:` prefix.
- `LoadDefault(cfg *config.Config) (*Keytab, error)` — resolution order `KRB5_KTNAME` → `default_keytab_name` → `FILE:/etc/krb5.keytab`.
- `LoadDefaultClient(cfg *config.Config) (*Keytab, error)` — `KRB5_CLIENT_KTNAME` → `default_client_keytab_name` → `FILE:/var/kerberos/krb5/user/%{euid}/client.keytab` (Linux/RHEL default; also accept the Debian default `/var/lib/krb5/user/%{euid}/client.keytab` when the first does not exist — verify defaults against the MIT build configuration table).
- `Unmarshal(b []byte) error` — resets `Entries` first; honours all rules in §3.1.5.
- `Read(io.Reader)` convenience.

#### 3.1.3 Create / write

- `New()` → v2.
- `Marshal() ([]byte, error)` — compacted (no holes), deterministic entry order = slice order.
- `Write(io.Writer) (int, error)` — unchanged.
- `WriteFile(path string) error` — writes to `<path>.tmp.<rand>`, `chmod 0600`, `fsync`, `rename`. Strips `FILE:`/`WRFILE:` prefix.
- `AppendToFile(path string, entries ...Entry) error` — opens `O_APPEND`, takes an advisory `flock(LOCK_EX)` (Unix; no-op on Windows), writes marshalled records only. Creates the file with the 2-byte header if it does not exist. This is what MIT `ktadd` does and makes gokrb5 safe to interleave with MIT tools.

#### 3.1.4 Add / modify

```go
func (kt *Keytab) AddKey(p Principal, kvno uint32, key types.EncryptionKey, ts time.Time) error
func (kt *Keytab) AddEntry(principalName, realm, password string, ts time.Time, kvno uint32, etype int32) error           // default salt, default s2kparams (kept, kvno widened)
func (kt *Keytab) AddEntryWithSalt(principalName, realm, password, salt, s2kparams string, ts time.Time, kvno uint32, etype int32) error
func (kt *Keytab) RemoveEntry(p Principal, kvno uint32, etype int32) int      // 0 = wildcard; returns count removed
func (kt *Keytab) RemovePrincipal(p Principal) int
func (kt *Keytab) RemoveOldKVNO(p Principal, keep int) int                     // kadmin "ktremove old" / k5srvutil delold semantics
func (kt *Keytab) Merge(other *Keytab) int                                     // ktutil rkt;rkt;wkt — de-duplicates identical (principal,kvno,etype,key)
func (kt *Keytab) Principals() []Principal
func (kt *Keytab) Version() uint8
func ParsePrincipal(s string) (Principal, error)                                // "svc/host@REALM" incl. backslash escapes, enterprise names
func (p Principal) String() string                                              // MIT unparse with escapes
```

#### 3.1.5 Lookup — MIT semantics

`GetEncryptionKey(princ types.PrincipalName, realm string, kvno int, etype int32) (types.EncryptionKey, int, error)` becomes a thin wrapper over:

```go
func (kt *Keytab) GetEntry(p Principal, kvno uint32, etype int32) (Entry, error)
```

Rules (mirror `krb5_ktfile_get_entry`):

1. Principal components must match exactly (case-sensitive). Name type is ignored.
2. Realm must match exactly unless the lookup realm is `""`, in which case any realm matches.
3. `etype == 0` matches any enctype; otherwise exact match (no "similar enctype" support — document).
4. `kvno == 0`: among matches choose the highest `KVNO`; tie-break by newest `Timestamp`.
5. `kvno != 0`: exact match on `KVNO`; if none, and `kvno > 255`, accept an entry whose `KVNO == kvno & 0xff` **only if** that entry was written without a 32-bit trailer (tracked by an unexported flag set during unmarshal). If still none → `ErrKVNONotFound`.
6. No principal match → `ErrNotFound`. Sentinel errors are exported so callers can distinguish.

#### 3.1.6 Rendering

- `String()` retained.
- `Klist(showTimestamps, showKeys, showEtypes bool) string` producing byte-identical output to `klist -k [-t] [-K] [-e]` for the same keytab (column layout, `KVNO Timestamp Principal` header, timestamp format `%m/%d/%y %H:%M:%S`, etype names in parentheses e.g. `(aes256-cts-hmac-sha1-96)`, keys as `(0x…)`). Used by interop tests for diffing.

### 3.2 Credential cache writer (`v8/credentials`)

- `func (c *CCache) Marshal() ([]byte, error)` — writes v4 by default (`c.Version == 0 → 4`), big-endian, header with tag 1 (KDC time offset: `int32 seconds, int32 microseconds`), default principal, then credentials in slice order. Supports v3 output for tests (repeated enctype field).
- `func (c *CCache) WriteFile(path string) error` — atomic temp+rename, `0600`.
- `func NewCCache(defaultPrincipal types.PrincipalName, realm string) *CCache`.
- `func (c *CCache) AddCredential(cred *Credential)`, `func (c *CCache) SetConfig(key, principal, value string)` writing `X-CACHECONF:` entries with server principal `krb5_ccache_conf_data/<key>[/<princ>]@X-CACHECONF:`, client = default principal, ticket data = value bytes, `endtime = 0`, flags 0.
- `func (c *CCache) KDCTimeOffset() (time.Duration, bool)` and `SetKDCTimeOffset(d time.Duration)`.
- `DefaultCCacheName(cfg *config.Config) (string, error)` with `KRB5CCNAME` → `default_ccache_name` → `FILE:/tmp/krb5cc_%{uid}`, parameter expansion, `FILE:` prefix handling, error for unsupported types.
- Harden `Unmarshal`: every `read*` returns an error on short input; header loop iterates `*p < start+length`; unknown header tags are skipped (MIT ignores unknown tags).
- `func (cl *Client) CCache() (*credentials.CCache, error)` in `v8/client` — exports the client's current TGT session(s) and cached service tickets into a `CCache` (client principal, TGT with flags/times/session key, `pa_type` config entry, `fast_avail` omitted). Round-trip `NewFromCCache(cl.CCache())` must be lossless.

### 3.3 AS exchange corrections (`v8/client`, `v8/crypto`, `v8/messages`)

1. `NewASReq`: remove the hard-coded 48 h `RTime`; set `RTime = t + RenewLifetime` only when `RenewLifetime > 0`; set `Renewable` flag accordingly. Accept per-request overrides via a new `ASReqOptions` struct (lifetime, renew lifetime, forwardable, proxiable, canonicalize, addresses, enterprise, service principal, start time) applied on top of config.
2. `setPAData`: choose the pre-auth etype as the first of `DefaultTktEnctypeIDs` for which `cl.Key(et, 0, nil)` succeeds; never consult `PreferredPreauthTypes`.
3. Keytab-driven etype list: when `Credentials.HasKeytab()`, intersect `DefaultTktEnctypeIDs` with the etypes available for `(cname, realm)` in the keytab, preserving config order; error if empty ("no supported encryption types (config file error?)" — the MIT wording).
4. `GetKeyFromPassword` / `preAuthEType`: iterate ETYPE-INFO2 (then ETYPE-INFO) entries, pick the first whose etype is in the client's requested etype list (KDC lists in its own preference order), use that entry's salt and s2kparams, and set `KeyType` to the etype actually used. ETYPE-INFO2 takes precedence over ETYPE-INFO over PA-PW-SALT (RFC 4120 §5.2.7.5). RFC 8009 etypes: ETYPE-INFO2 salt is used verbatim (saltp is computed inside the etype).
5. Clock skew: on `KRB_AP_ERR_SKEW` (or `KDC_ERR_PREAUTH_FAILED` with a KRB-ERROR `stime`) and `KDCTimeSync > 0`, compute `offset = stime - now`, retry once with `PA-ENC-TIMESTAMP` built from `now + offset`, and record the offset for the ccache header.
6. Principal defaulting in a new `client.NewFromPrincipalString(princ string, cfg *config.Config, …)` helper: empty realm → `DefaultRealm`; error if no realm can be determined.

### 3.4 `gokinit` command (`v8/cmd/gokinit`)

Flag surface (subset of MIT `kinit(1)`), identical short names:

```
gokinit [-V] [-l lifetime] [-r renewable_life] [-f | -F] [-p | -P] [-a | -A] [-C] [-E]
        [-v] [-R] [-k [-i | -t keytab_file]] [-c cache_name] [-S service_name] [principal]
```

Behaviour:

- No `-k`: prompt `Password for <principal>: ` on the controlling tty, no echo; `KRB5_PASSWORD`-style env is **not** supported (MIT does not either). If stdin is not a tty, read one line from stdin (MIT behaviour with `-P`-less piped input is to fail; we follow MIT: fail with `kinit: Cannot read password` unless `--password-stdin` (gokrb5 extension, off by default) is given).
- `-k`: keytab from `-t`, else `-i` client keytab, else default keytab.
- `-R`: load `-c`/default ccache, renew the TGT, rewrite the ccache.
- `-S service`: request a ticket for `service` instead of `krbtgt/REALM`.
- `-v`: validate (postdated) — may be deferred; if unimplemented, exit with the MIT error text `kinit: -v not supported`.
- Output: silent on success (`-V` prints `Using default cache: …`, `Using principal: …`, `Authenticated to Kerberos v5` exactly like MIT).
- Exit status 1 on failure; error text `kinit: <message> while getting initial credentials` (mapping table from `krberror`/KRB-ERROR codes to MIT `com_err` strings for the common cases: password incorrect, client not found, preauth failed, clock skew, key expired, cannot contact any KDC).
- Writes ccache v4 with `pa_type` config entry; for keytab logins also `refresh_time`.

Also provide `v8/cmd/goklist` (`-k -t -K -e -c`) and `v8/cmd/gokdestroy` as thin wrappers — they are cheap and make interop testing self-contained. `goktutil` is optional; `keytab` package API + tests cover it.

---

## 4. Verification Strategy

### 4.1 Test layers

| Layer | Runs where | Mechanism |
|---|---|---|
| Unit | always | Go tests with byte fixtures captured from MIT tools, checked into `v8/test/testdata` (as hex/base64 constants, following existing convention). Every fixture records the exact MIT command and krb5 version that produced it in a comment. |
| Interop (local MIT binaries) | when `ktutil`, `klist`, `kinit`, `kvno` are on `PATH` and `INTEGRATION=1` | Tests generate artifacts with gokrb5 and validate with MIT, and vice-versa, using `os/exec`. Skip with `t.Skip` when binaries are absent. |
| KDC integration | CI (`INTEGRATION=1`, existing `jcmturner/gokrb5:kdc-*` containers) | Full `kinit` flows against the three KDC versions on ports 88/78/98, plus `kdc-shorttickets` (58) for renewal. |
| Fuzz | always (`go test -fuzz` in CI short mode with seed corpus) | `FuzzKeytabUnmarshal`, `FuzzCCacheUnmarshal`. |

### 4.2 Fixture inventory to capture from MIT (`v8/test/testdata/test_vectors.go`)

All generated once with a pinned MIT version (record `krb5-config --version`), for principal `testuser1@TEST.GOKRB5` / password `passwordvalue` and SPN `HTTP/host.test.gokrb5@TEST.GOKRB5` unless stated:

1. `KEYTAB_KTUTIL_ALL_ETYPES` — `ktutil addent -password` for etypes 17, 18, 19, 20, 23, 16 at kvno 1, single principal.
2. `KEYTAB_KTUTIL_KVNO_300` — kvno 300 (exercises 8-bit wrap + 32-bit trailer).
3. `KEYTAB_KTUTIL_MULTI_KVNO_UNORDERED` — kvno 3 (newer timestamp) and kvno 4 (older timestamp), same etype → asserts KT-2.
4. `KEYTAB_KTUTIL_MULTI_PRINCIPAL` — user + service + `host/` principals, two realms.
5. `KEYTAB_KADMIN_KTREMOVE_HOLES` — file produced by `kadmin.local ktadd` ×3 then `ktremove` of the middle entry (negative-length hole). Also one with a hole at EOF (KT-15).
6. `KEYTAB_V1_LITTLE_ENDIAN` / `KEYTAB_V1_BIG_ENDIAN` — legacy v1 fixtures. If no MIT tool can emit v1, synthesize per format spec and mark as spec-derived.
7. `KEYTAB_AD_HOST_SALT` — entry generated with a non-default salt (`ktutil addent -password -salt TEST.GOKRB5hosthost.test.gokrb5`).
8. `KEYTAB_ENTERPRISE_PRINCIPAL` — `ktutil addent -e ... -p user\@corp.example@TEST.GOKRB5`-style name (name type 10 if `ktutil` supports it; otherwise `kadmin` with `-E`).
9. `KEYTAB_NO_KVNO32_TRAILER` — hand-built record without 32-bit trailer (legacy writer), kvno8 = 5 → verifies fallback rule.
10. `CCACHE_V4_KINIT_PASSWORD` — `kinit testuser1` then `cat /tmp/krb5cc_*`; includes `X-CACHECONF:` entries and KDC offset header.
11. `CCACHE_V4_KINIT_KEYTAB` — `kinit -kt` variant (has `refresh_time`).
12. `CCACHE_V4_WITH_SERVICE_TICKET` — after `kvno HTTP/host.test.gokrb5`.
13. `CCACHE_V4_RENEWABLE_FORWARDABLE` — `kinit -f -r 7d`.
14. `CCACHE_V3` — produced with `KRB5CCNAME` on an old MIT if available; else synthesized.
15. `KLIST_KTE_OUTPUT_*` — captured text of `klist -kte` for fixtures 1–4 (for `Klist()` diff tests).

### 4.3 Unit tests (new or changed)

`v8/keytab`:

- `TestUnmarshal_AllFixtures` (table over every fixture; asserts entry count, kvno, etype, key bytes, principal, timestamp).
- `TestUnmarshal_HoleSkipping`, `TestUnmarshal_HoleAtEOF`, `TestUnmarshal_ZeroLengthRecord`.
- `TestUnmarshal_TruncatedPrincipalReturnsError` (KT-1).
- `TestUnmarshal_V1RoundTrip` (KT-6, KT-7): v1 → Marshal(v1) bytes identical.
- `TestUnmarshal_ResetsEntries` (KT-13).
- `TestMarshal_ByteExactVsKtutil` — extend existing test to every etype and to kvno 300 (KT-8).
- `TestGetEntry_HighestKVNOWins` (KT-2), `TestGetEntry_EtypeWildcard` (KT-3), `TestGetEntry_EmptyRealmMatchesAny` (KT-4), `TestGetEntry_KVNO8Fallback` (KT-5), `TestGetEntry_ErrNotFound_vs_ErrKVNONotFound`.
- `TestAddKey`, `TestAddEntryWithSalt_MatchesKtutilSalt` (fixture 7), `TestRemoveEntry`, `TestRemovePrincipal`, `TestRemoveOldKVNO`, `TestMerge_Dedup`.
- `TestWriteFile_AtomicAndMode0600`, `TestAppendToFile_CreatesHeaderWhenMissing`, `TestAppendToFile_ConcurrentWriters` (N goroutines appending; result parses and contains N entries).
- `TestLoadDefault_ResolutionOrder` (env var, config, fallback, `FILE:` prefix, `%{euid}` expansion).
- `TestKlist_MatchesCapturedOutput` (fixture 15).
- `TestErrorsDoNotContainKeyMaterial` (KT-14): feed truncated data, assert error string contains no bytes from the key.
- `FuzzUnmarshal` seeded with all fixtures; property: never panics; `Marshal(Unmarshal(x))` re-parses to an equal `Keytab`.

`v8/credentials`:

- `TestCCacheMarshal_RoundTripV4` (fixtures 10–13: `Unmarshal` → `Marshal` → byte-identical).
- `TestCCacheMarshal_V3`.
- `TestCCacheUnmarshal_TruncatedInputsReturnError` (KI-2), `FuzzCCacheUnmarshal`.
- `TestCCache_ConfigEntries_WriteAndFilter` (KI-15).
- `TestDefaultCCacheName_Resolution` (KI-8).
- `TestParseHeader_UnknownTagSkipped`, `TestParseHeader_OffsetArithmetic`.

`v8/messages`:

- `TestNewASReq_RenewLifetimeHonoured` (KI-3): `RTime == Till - TicketLifetime + RenewLifetime`, Renewable flag set; not set when 0.
- `TestNewASReq_Options_OverrideConfig`.

`v8/crypto`:

- `TestGetKeyFromPassword_SelectsMatchingETypeInfo2Entry` (KI-5): ETYPE-INFO2 with `[aes256, aes128]`, request aes128 → aes128 key, `KeyType == 17`.
- `TestGetKeyFromPassword_ETypeInfo2PrecedenceOverPWSalt`.

`v8/client` (unit, mocked KDC via the existing `testdata` KRB-ERROR vectors or a fake UDP responder):

- `TestSetPAData_ETypeFromTktEnctypesNotPreauthTypes` (KI-4).
- `TestASReq_ETypesRestrictedToKeytab` (KI-6).
- `TestClient_CCacheExport_RoundTrip` (§3.2 last bullet).
- `TestClockSkewRetry` (KI-10) with a fake KDC returning `KRB_AP_ERR_SKEW` with `stime` then success.
- `TestPrincipalDefaulting` (KI-9).

### 4.4 Interop tests (require MIT binaries, `INTEGRATION=1`)

Package `v8/test/interop` (build tag `interop`):

1. **gokrb5 → MIT keytab**: build keytab with `AddEntry`/`AddKey` for all etypes and kvno 300; `klist -kte` output equals `kt.Klist(true,true,true)`; `kvno -k <file> --keytab` succeeds (in KDC integration); `ktutil rkt <file>; list -e -t` parses.
2. **MIT → gokrb5 keytab**: run `ktutil` script to build keytab; `Load` → `GetEntry` for each (princ, kvno, etype) returns key equal to `ktutil list -K`.
3. **Modify interop**: `kadmin.local ktadd` into file → gokrb5 `RemoveOldKVNO` → `WriteFile` → `klist -kt` shows only latest; then MIT `ktadd` appends more → gokrb5 `Load` sees all.
4. **Concurrent append**: gokrb5 `AppendToFile` while `ktutil wkt` writes → both readers parse without error (best-effort; documents locking limits).
5. **gokinit → MIT**: `gokinit -c FILE:$TMP/cc testuser1` with password on tty (use `expect`-style pty via `github.com/creack/pty` in test only) → `klist -c $TMP/cc` shows TGT with expected flags/lifetimes; `kvno -c $TMP/cc HTTP/host.test.gokrb5` succeeds; `kdestroy -c $TMP/cc` works.
6. **MIT kinit → gokrb5**: `kinit` (existing `login()` in `ccache_integration_test.go`) → `LoadCCache` → `NewFromCCache` → `GetServiceTicket` succeeds; then `cl.CCache().WriteFile()` → MIT `klist` shows both tickets.
7. **kinit -kt parity**: `kinit -kt kt.keytab testuser1` vs `gokinit -kt kt.keytab testuser1` → compare `klist -e` output ignoring timestamps and the `Ticket cache:` line: flags, etypes, principal, lifetimes must match.
8. **Renewal parity**: against `kdc-shorttickets` (port 58): `gokinit -r 1h`, wait past 5/6 of lifetime, `gokinit -R`, `klist` shows extended `Valid starting`.
9. **Error text parity**: wrong password, unknown principal, unreachable KDC → stderr equals MIT `kinit` text for the same condition (table-driven; allow trailing-detail differences after the ` while ` clause only if documented).

### 4.5 KDC integration additions (`v8/client/client_integration_test.go`)

- `TestClient_Login_Keytab_KDCPrefersEtypeNotInKeytab`: keytab with aes128 only, config `default_tkt_enctypes = aes256 aes128` → login succeeds (KI-6).
- `TestClient_Login_RenewLifetime`: `renew_lifetime = 7d` → `renewTill` ≈ now+7d (KI-3).
- `TestClient_Login_KVNO300Keytab`: KDC principal at kvno ≥ 256 (requires test container change: `kadmin.local cpw` ×256 in the KDC image, or `modprinc -kvno 300`) (KT-8).

---

## 5. Exit Criteria

The work is complete when **all** of the following hold:

### 5.1 Keytab

- [ ] EC-K1: Every fixture in §4.2 items 1–9 loads without error; parsed fields equal the recorded MIT values.
- [ ] EC-K2: For fixtures 1–4 and 7, `Marshal()` output is byte-identical to the MIT file. For fixture 5 (holes), `Marshal()` output re-parses to the same entry set and MIT `klist -kte` lists identical entries.
- [ ] EC-K3: `GetEntry` returns the same entry MIT returns for all of: kvno=0 (highest kvno), explicit kvno, kvno ≥ 256, empty realm, etype=0, missing kvno (error type `ErrKVNONotFound`), missing principal (`ErrNotFound`). Verified by the interop test comparing with `kvno`/`klist -K` results.
- [ ] EC-K4: All modify operations (`AddKey`, `AddEntry(WithSalt)`, `RemoveEntry`, `RemovePrincipal`, `RemoveOldKVNO`, `Merge`) produce files that MIT `klist -kte` and `ktutil rkt` read, with the expected entry set.
- [ ] EC-K5: `WriteFile` creates `0600` files atomically; `AppendToFile` interleaves with MIT `ktadd` without corruption in the interop test.
- [ ] EC-K6: Default keytab resolution matches MIT for `KRB5_KTNAME`, `KRB5_CLIENT_KTNAME`, config keys and built-in fallbacks, including `FILE:`/`WRFILE:` prefixes and `%{euid}` expansion.
- [ ] EC-K7: `FuzzUnmarshal` runs 60 s in CI with zero crashes; no error string contains key bytes.
- [ ] EC-K8: `Klist()` output is byte-identical to captured `klist -kte` for fixtures 1–4.
- [ ] EC-K9: No exported API from v8.4.x is removed; deprecated names remain as aliases with `// Deprecated:` comments. `go vet`, `gofmt -l`, `golint`-clean per existing CI.

### 5.2 kinit

- [ ] EC-I1: `CCache.Marshal()` round-trips fixtures 10–14 byte-identically.
- [ ] EC-I2: A ccache written by `gokinit` (password and `-kt` paths) is accepted by MIT `klist`, `kvno`, `kdestroy`, and MIT `kinit -R`, against all three KDC containers.
- [ ] EC-I3: `klist -e` output for `gokinit` vs MIT `kinit` with the same flags (`-f`, `-r 7d`, `-l 2h`, `-S HTTP/host.test.gokrb5`, `-C`) is identical except for `Ticket cache:` path and absolute timestamps; relative lifetimes (`Valid starting`→`Expires`, `renew until`) differ by ≤ 5 s.
- [ ] EC-I4: Keytab login succeeds when the KDC's preferred etype is absent from the keytab (KI-6 test green on all KDC containers).
- [ ] EC-I5: `renew_lifetime` / `-r` is reflected in the issued TGT's `renew-till` (KI-3).
- [ ] EC-I6: Pre-auth etype selection no longer reads `PreferredPreauthTypes`; a config with `preferred_preauth_types = 16, 14` still logs in (KI-4).
- [ ] EC-I7: ETYPE-INFO2 with multiple entries where the first is not the requested etype yields a correctly typed key and successful login (KI-5; unit + integration against `kdc-latest`).
- [ ] EC-I8: Interactive prompt works on a pty (`Password for testuser1@TEST.GOKRB5: `, no echo); non-tty stdin without `--password-stdin` fails with MIT-equivalent message.
- [ ] EC-I9: Error messages for wrong password, unknown principal, preauth failed, clock skew, unreachable KDC match the MIT `kinit` strings in the table-driven test.
- [ ] EC-I10: Clock-skew retry: with the client clock skewed by +10 min against `kdc-centos-default`, `gokinit` succeeds when `kdc_timesync = 1` and the ccache header carries the offset that MIT `klist` (debug) would show; with `kdc_timesync = 0` it fails with the skew error.
- [ ] EC-I11: `FuzzCCacheUnmarshal` 60 s zero crashes.
- [ ] EC-I12: Existing test-suite (`go test ./...` with and without `INTEGRATION=1`) passes on all Go versions in `.github/workflows/testingv8.yml`.

---

## 6. Phased Implementation Plan (LLM-executable)

Each phase is independently mergeable, lists exact files, and ends with a verifiable check. Do not start a phase before the previous phase's check passes. Keep changes minimal and within the listed files unless a compile error forces otherwise. Follow repository conventions: tests use `testify/assert`, fixtures live in `v8/test/testdata/test_vectors.go` as string constants, integration tests call `test.Integration(t)` first.

### Phase 0 — Fixture capture (no library code changes)

Files: `v8/test/testdata/test_vectors.go`, `v8/test/testdata/README.md` (new; documents generation commands and MIT version).

Steps:
1. Write a shell script `v8/test/testdata/gen/mit_fixtures.sh` that, given `ktutil`, `kadmin.local`, `kinit`, `klist`, `kvno` on PATH and the `kdc-centos-default` container, produces every fixture in §4.2 as hex, plus captured `klist -kte` text.
2. Run it (or, if MIT tools are unavailable in the current environment, hand-assemble fixtures strictly per the keytab/ccache format specifications and mark them `// SPEC-DERIVED — replace with MIT capture`).
3. Add constants `KEYTAB_*`, `CCACHE_*`, `KLIST_*` to `test_vectors.go`.

Check: `go vet ./v8/...` passes; each constant decodes from hex without error in a trivial test `TestFixturesDecode`.

### Phase 1 — Keytab read correctness (KT-1, KT-6, KT-7, KT-13, KT-14, KT-15)

Files: `v8/keytab/keytab.go`, `v8/keytab/keytab_test.go`.

Steps:
1. Capture and return the error from `parsePrincipal` in `Unmarshal`.
2. Only read the 32-bit kvno trailer when `kt.version == 2`; record on the entry (unexported bool `kvno32Present`) whether it was present.
3. Stop storing `NumComponents`; compute in `principal.marshal` (`len(Components)`, `+1` if v1). Keep the struct field for one release but ignore it (`json:"-"`), or remove if no external usage — check with `grep -r NumComponents` in the module.
4. `Unmarshal` sets `kt.Entries = nil` before parsing.
5. Replace every `%s` of a byte slice in error messages with the length or offset only.
6. Zero-length record: after verifying MIT behaviour in `kt_file.c`, either continue (skip 4 bytes) or stop; encode the decision in a test with the fixture from §4.2 item 5.
7. Add tests: `TestUnmarshal_AllFixtures`, `TestUnmarshal_TruncatedPrincipalReturnsError`, `TestUnmarshal_V1RoundTrip`, `TestUnmarshal_ResetsEntries`, `TestUnmarshal_HoleSkipping`, `TestUnmarshal_HoleAtEOF`, `TestErrorsDoNotContainKeyMaterial`, `FuzzUnmarshal`.

Check: `go test ./v8/keytab/...` green; `go test -run XXX -fuzz FuzzUnmarshal -fuzztime 30s ./v8/keytab` no crashes.

### Phase 2 — Exported model and MIT lookup semantics (KT-2, KT-3, KT-4, KT-5, KT-8, KT-9)

Files: `v8/keytab/keytab.go`, `v8/keytab/keytab_test.go`, callers: `v8/credentials/credentials.go`, `v8/client/client.go`, `v8/messages/KDCRep.go`, `v8/service/*.go` (grep `GetEncryptionKey` and `kt.Entries`).

Steps:
1. Rename `entry` → `Entry`, `principal` → `Principal`; add `type entry = Entry`, `type principal = Principal` aliases marked deprecated.
2. Remove `KVNO8` from `Entry`; derive in marshal/unmarshal. Fix `Entry.String()` to print `KVNO`.
3. Widen `AddEntry`'s `KVNO` parameter to `uint32`. (Breaking for callers passing `uint8` literals? Untyped constants still compile; typed `uint8` variables need a cast — acceptable, document in CHANGELOG.)
4. Implement `GetEntry` with rules §3.1.5, define `ErrNotFound`, `ErrKVNONotFound`; rewrite `GetEncryptionKey` to delegate.
5. Add `Version()`, `Principals()`, `ParsePrincipal`, `Principal.String()` with MIT escaping (`\/`, `\@`, `\\`, `\n`, `\t`, `\b`, `\0`).
6. Tests listed in §4.3 for `GetEntry_*`, `TestMarshal_ByteExactVsKtutil` extended to kvno 300 (fixture 2) and all etypes (fixture 1).

Check: `go build ./v8/... && go test ./v8/...` green (non-integration); `grep -rn "KVNO8" v8/ | grep -v _test.go` returns nothing.

### Phase 3 — Keytab create/modify/write API (KT-10, KT-11, KT-12, KT-16, KT-17)

Files: `v8/keytab/keytab.go`, new `v8/keytab/file.go` (WriteFile/AppendToFile/locking), new `v8/keytab/file_unix.go` + `file_windows.go` (flock shim), new `v8/keytab/default.go` (name resolution), new `v8/keytab/klist.go`, tests alongside.

Steps:
1. Implement `AddKey`, `AddEntryWithSalt`, `RemoveEntry`, `RemovePrincipal`, `RemoveOldKVNO`, `Merge`.
2. Implement `WriteFile` (temp+rename, 0600, fsync) and `AppendToFile` (O_APPEND|O_CREATE 0600, flock on Unix, header written if file size is 0).
3. Implement `LoadDefault`, `LoadDefaultClient`, `ResolveName(name string, cfg *config.Config) (path string, writable bool, err error)` with prefix handling and `%{euid}`/`%{uid}`/`%{username}` expansion. Add `DefaultClientKeytabName` parsing to `config.LibDefaults` (`default_client_keytab_name`) in `v8/config/krb5conf.go` if absent.
4. Implement `Klist(showTimestamps, showKeys, showEtypes bool)`; etype names must come from a single table — add `iana/etypeID.ETypeToString`-style map if none exists (check `v8/iana/etypeID`).
5. Tests: §4.3 keytab items for add/remove/merge/write/append/default/klist.

Check: `go test ./v8/keytab/...` green including `TestAppendToFile_ConcurrentWriters`; `TestKlist_MatchesCapturedOutput` byte-equal against fixture 15.

### Phase 4 — CCache hardening and writer (KI-1, KI-2, KI-8, KI-15)

Files: `v8/credentials/ccache.go`, new `v8/credentials/ccache_marshal.go`, new `v8/credentials/ccache_default.go`, `v8/credentials/ccache_test.go`, `v8/config/krb5conf.go` (`default_ccache_name` parsing if missing).

Steps:
1. Make all `read*` helpers return `error`; propagate; fix `parseHeader` offset arithmetic; skip unknown header tags.
2. Implement `Marshal` (v3 and v4), `WriteFile`, `NewCCache`, `AddCredential`, `SetConfig`/`GetConfig`, `KDCTimeOffset`/`SetKDCTimeOffset`.
3. Implement `DefaultCCacheName(cfg)`.
4. Tests: §4.3 credentials items; `FuzzCCacheUnmarshal`.

Check: `go test ./v8/credentials/...` green; round-trip of fixtures 10–14 byte-identical.

### Phase 5 — AS exchange corrections (KI-3, KI-4, KI-5, KI-6, KI-9, KI-10, KI-13)

Files: `v8/messages/KDCReq.go`, `v8/crypto/crypto.go`, `v8/client/ASExchange.go`, `v8/client/client.go`, `v8/client/settings.go`, new `v8/client/ccache_export.go`, tests in each package.

Steps:
1. `NewASReq`: delete the 48 h override; add `ASReqOptions` and `NewASReqWithOptions`; keep `NewASReq` signature.
2. `GetKeyFromPassword`: accept the requested etype list (new variadic or wrapper `GetKeyFromPasswordForETypes`), select the matching ETYPE-INFO2/ETYPE-INFO entry, set `KeyType` from the etype used. Update `preAuthEType` to return the first KDC-offered etype present in the client's list.
3. `setPAData`: iterate `DefaultTktEnctypeIDs`, use first etype for which `cl.Key` succeeds.
4. `Login`/`ASExchange`: when a keytab is in use, build the AS-REQ etype list as the ordered intersection described in §3.3(3).
5. Clock skew retry per §3.3(5); store offset on the client (`cl.kdcTimeOffset`).
6. Add `client.NewFromPrincipalString` / realm defaulting; make `IsConfigured` accept an empty realm when `Config.LibDefaults.DefaultRealm` is set (resolve at construction).
7. Add `Client.CCache()` export; mark `DisablePAFXFAST` deprecated in favour of `DisablePAReqEncPARep` (same behaviour).
8. Tests: §4.3 messages/crypto/client items; §4.5 integration tests.

Check: `go test ./v8/...` green; with the KDC containers running, `INTEGRATION=1 go test ./v8/client/...` green including the three new integration tests.

### Phase 6 — `gokinit`, `goklist`, `gokdestroy` commands (KI-7, KI-11, KI-12, KI-14)

Files: new `v8/cmd/gokinit/main.go`, `v8/cmd/goklist/main.go`, `v8/cmd/gokdestroy/main.go`, new `v8/cmd/internal/krbcli/` (shared: config loading with `KRB5_CONFIG`, principal defaulting, error-text mapping, tty password prompt), `v8/go.mod` (add `golang.org/x/term`).

Steps:
1. Implement flag parsing with Go `flag` using MIT short names; `-h` prints MIT-style usage line.
2. Implement password prompt on `/dev/tty` (fallback `--password-stdin`).
3. Wire keytab (`-k`, `-t`, `-i`), ccache (`-c`, default), options → `ASReqOptions`, `-S`, `-R`, `-E`.
4. `KDC_ERR_KEY_EXPIRED` → prompt for new password twice, `ChangePasswd`, retry login (KI-11).
5. Error mapping table → MIT strings; exit code 1.
6. `goklist`: `-c`, `-k`, `-t`, `-K`, `-e`, `-s` (silent status) reproducing MIT column layout. `gokdestroy`: `-c`, `-A` (all — FILE only), `-q`.
7. Unit tests for flag→options mapping and error-text table; pty-based test for the prompt (skips if no pty).

Check: `go build ./v8/cmd/...`; `go test ./v8/cmd/...` green; manual smoke: `gokinit -kt v8/test/testdata/testuser1.testtab testuser1` against a local KDC container, then MIT `klist`.

### Phase 7 — Interop test suite and CI (all EC items)

Files: new `v8/test/interop/*_test.go` (build tag `interop`), `.github/workflows/testingv8.yml`.

Steps:
1. Implement interop tests §4.4 items 1–9; each `t.Skip`s when a required binary is missing.
2. CI: install `krb5-user`/`krb5-workstation` on the runner; add a job step `INTEGRATION=1 go test -tags interop ./v8/test/interop/...`.
3. Add `-fuzztime 60s` fuzz jobs for the two fuzz targets.
4. Update `v8/USAGE.md` (keytab management, ccache export, `gokinit`) and `v8/README.md` feature table; add CHANGELOG entry listing deprecated aliases and the `AddEntry` kvno type change.

Check: all §5 checkboxes ticked; CI green on every Go version in the matrix.

---

## 7. Open Questions (resolve during Phase 0/1 by reading MIT source)

1. MIT behaviour for a zero-length keytab record (`kt_file.c`, `krb5_ktfileint_internal_read_entry`) — treat as EOF or skip?
2. Exact 8-bit kvno fallback rule in `krb5_ktfile_get_entry` (condition and whether it applies only when the 32-bit trailer is absent).
3. Client keytab default path per platform (`/var/kerberos/krb5/user/%{euid}/client.keytab` vs `/var/lib/krb5/user/%{euid}/client.keytab`) — mirror MIT's `DEFCKTNAME` build default and document.
4. Which `X-CACHECONF:` entries MIT `kinit` writes in the pinned version (`pa_type`, `fast_avail`, `refresh_time`, `start_realm`) so `gokinit` output is diff-clean under `klist -c` with config entries shown.
5. Whether to emit `ETYPE-INFO`-only (pre-RFC 4120) handling for `kdc-older`; confirm the `kdc-older` container's ETYPE-INFO variant.
