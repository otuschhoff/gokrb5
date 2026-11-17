# Design Spec: MIT krb5 Compatibility — Keytab Handling and `kinit`

Status: Implemented; compatibility questions resolved against MIT krb5 1.21.3
Scope: `v8` module (`github.com/otuschhoff/gokrb5/v8`)
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

The historical review and plan have moved to the [single refactoring roadmap](refactoring.md#appendix-b---historical-mit-compatibility-review-and-implementation-plan).
Use its current assessment and active phases, not the historical gap list, to
select new work. Original finding IDs and phase references are preserved there.

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
- `LoadDefaultClient(cfg *config.Config) (*Keytab, error)` — `KRB5_CLIENT_KTNAME` → `default_client_keytab_name` → compiled-policy fallbacks. MIT's `DEFCKTNAME` is build-time configurable; gokrb5 probes `/var/kerberos`, `/etc`, then `/var/lib` variants and returns the primary path if none exists.
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
5. `kvno != 0`: exact match on `KVNO`; if none, and `kvno > 255`, accept an entry whose parsed `KVNO == kvno & 0xff`, regardless of whether the record contained a 32-bit trailer. If still none → `ErrKVNONotFound`.
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
- `func (cl *Client) CCache() (*credentials.CCache, error)` in `v8/client` — exports the client's current TGT session(s) and cached service tickets into a `CCache` (client principal, TGT with flags/times/session key, and TGT-associated `pa_type` when pre-authentication was selected). `fast_avail` is omitted because gokrb5 does not negotiate FAST. `AddCredential` records global `start_realm` for cross-realm TGTs. Round-trip `NewFromCCache(cl.CCache())` must be lossless.

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
- Writes ccache v4 with a TGT-associated `pa_type` entry when pre-authentication was selected. It does not write `refresh_time`; MIT writes that key from GSS client-keytab refresh code, not `kinit`.

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
11. `ccache_v4_kinit_keytab.hex` — generated by `kinit -kt` when a test KDC is available; validated by live interop rather than represented by aliased password-login bytes. Ordinary MIT `kinit -kt` does not add `refresh_time`.
12. `CCACHE_V4_WITH_SERVICE_TICKET` — after `kvno HTTP/host.test.gokrb5`.
13. `ccache_v4_renewable_forwardable.hex` — generated by `kinit -f -r 7d` when a test KDC is available and validated by live interop.
14. `CCACHE_V3` — produced with `KRB5CCNAME` on an old MIT if available; else synthesized.
15. `KLIST_KTE_OUTPUT_*` — captured text of `klist -kte` for fixtures 1–4 (for `Klist()` diff tests).

### 4.3 Unit tests (new or changed)

`v8/keytab`:

- `TestUnmarshal_AllFixtures` (table over every fixture; asserts entry count, kvno, etype, key bytes, principal, timestamp).
- `TestUnmarshal_HoleSkipping`, `TestUnmarshal_HoleAtEOF`, `TestUnmarshal_ZeroLengthRecord`.
- `TestUnmarshal_TruncatedPrincipalReturnsError` (KT-1).
- `TestUnmarshal_V1RoundTrip` (KT-6, KT-7): v1 → Marshal(v1) bytes identical, including an optional native-endian 32-bit kvno trailer.
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

The historical review and plan have moved to the [single refactoring roadmap](refactoring.md#appendix-b---historical-mit-compatibility-review-and-implementation-plan).
Use its current assessment and active phases, not the historical gap list, to
select new work. Original finding IDs and phase references are preserved there.

## 7. Resolved Compatibility Questions

These conclusions were verified against the `krb5-1.21.3-final` source tag.

1. A zero-length keytab record is EOF. `src/lib/krb5/keytab/kt_file.c`, `krb5_ktfileint_internal_read_entry`, returns `KRB5_KT_END` when `size == 0`; `doc/formats/keytab_file_format.rst` specifies the same behavior.
2. Explicit KVNO lookup first seeks an exact match, then accepts the first entry whose parsed KVNO equals `kvno & 0xff`. `krb5_ktfile_get_entry` does not condition this fallback on absence of the optional 32-bit trailer. Trailer parsing remains independent: a present, nonzero 32-bit value overrides KVNO8.
3. The client-keytab path is build policy, not a platform constant. `src/configure.ac` accepts `DEFCKTNAME`, inherits it from `krb5-config --defcktname` when available, and otherwise uses `FILE:$localstatedir/krb5/user/%{euid}/client.keytab`. `src/lib/krb5/os/ktdefname.c`, `k5_kt_client_default_name`, applies environment and profile overrides first. The locally installed 1.21.3 build reports `FILE:/etc/krb5/user/%{euid}/client.keytab`; gokrb5 also recognizes common `/var/kerberos` and `/var/lib` builds.
4. Initial-credential acquisition writes TGT-associated `pa_type` when a pre-authentication mechanism was selected and TGT-associated `fast_avail=yes` when FAST was negotiated (`src/lib/krb5/krb/get_in_tkt.c`, `save_selected_preauth_type` and `write_out_ccache`). Generic ccache storage writes global `start_realm` for a cross-realm TGT (`src/lib/krb5/ccache/ccfns.c`, `krb5_cc_store_cred`). `refresh_time` is written by GSS credential acquisition for client-keytab refresh (`src/lib/gssapi/krb5/acquire_cred.c`, `set_refresh_time`), not by ordinary `kinit` or `kinit -k`.
5. ETYPE-INFO behavior depends on requested enctypes, not KDC version. `src/kdc/kdc_preauth.c`, `requires_info2` and `add_etype_info`, always emits ETYPE-INFO2 and additionally emits ETYPE-INFO for requests containing no enctype that requires INFO2. gokrb5 accepts ETYPE-INFO-only method data for legacy interoperability and gives ETYPE-INFO2 precedence when both are present.
