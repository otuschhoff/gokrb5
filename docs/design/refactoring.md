# v8 Code Quality and Refactoring Roadmap

Status: active, authoritative remediation backlog; Phases 0-2 complete, all
Phase 3 decomposition slices implemented, Phase 4's local coverage items done
(floor raised to 86.0%), and Phase 5 slices 1-18 done (formatter normalization,
keytab complexity, dead code, mechanical clarity, shadow elimination,
errorlint, revive mechanical, exported documentation, the NDR carry-over,
I/O/body-ownership cleanup, checked type assertions, and named-return clarity).
Remaining canonical debt is concentrated in the classification-heavy
categories (gosec, NilAway, wrapcheck, errcheck, gocognit/nestif, ireturn,
nonamedreturns, bodyclose) plus documented intentional categories (iana
protocol-table naming, public API name stutters, contract error texts).
Phase 3/4 interoperability and Windows exit evidence remains an external CI
obligation.
Assessment date: 2026-11-17.
Scope: `v8` module (`github.com/otuschhoff/gokrb5/v8`) only. Root-module v7
refactoring is out of scope; whole-project lint automation remains unchanged.
Original assessment revision: `26e11e9` plus the lint configuration and automation
changes. Phase 1 follows the committed assessment at `d24235c`; Phase 2 follows
the completed Phase 1 at `282e1bf`. Phase 3 slices follow the completed Phase 2
at `632e87e`.
The original checkout was two commits behind its existing `origin/main`
reference; this assessment does not claim to cover those commits.

Navigation: [current state](#1-high-level-current-state),
[measurements](#2-assessment-method-and-limits),
[findings](#3-prioritized-findings),
[execution phases](#4-phased-remediation-for-llm-execution),
[automation](#5-automation-policy). Appendices retain historical evidence only.

## 1. High-level current state

This roadmap covers only the active v8 development module:

| Module | Role | Declared minimum Go | Assessment |
| --- | --- | --- | --- |
| `v8`: `github.com/otuschhoff/gokrb5/v8` | Active development line | 1.26.0 | Unit/race tests pass; 1,293 canonical lint findings after Phase 5 slices 1-18 |

The active module has substantial implementation and test coverage for keytab
and ccache management, Kerberos authentication, FAST, S4U, PKINIT, GSS, SPNEGO,
NEGOEX, and PKU2U. Existing CI includes native platform tests, race tests,
coverage, cross-builds, MIT/Samba integration, and fuzz jobs. These are strengths,
not evidence that every protocol path or Windows deployment is verified.

The main code-quality risks are concentrated in authentication orchestration,
binary parsing, error propagation, nil invariants, and resource ownership.
Passing tests coexist with considerable static-analysis debt. Complexity is
particularly high in the AS exchange, NDR decoding, configuration parsing,
PAC processing, and keytab decoding. Cosmetic modernization must not precede
correctness work or change protocol compatibility.

Assessment-time v8 cross-package statement coverage was **84.4%**, versus the historical
70.9% baseline from 2026-09-07. Phase 4 remeasured coverage at **86.9%** with
the CI job's instrumentation (`-covermode=atomic -coverpkg=./...`, Go 1.26.11,
Linux/amd64) and raised the CI floor from 70.0% to **86.0%**, retaining the
historical ~0.9-point margin for Go release instrumentation drift. This
aggregate is not proof of critical branch coverage or of the historical 100%
combined-coverage goal.

### Consolidation and status rules

This document supersedes the review findings and implementation plans formerly
embedded in the [MS-KILE specification](ms-kile-compliance.md), the
[MIT compatibility specification](mit-krb5-keytab-kinit-compatibility.md), and
the former `test-coverage.md` plan. Protocol design, fixture requirements,
acceptance criteria, and compatibility decisions remain in those specifications.
The [Windows execution checklist](ms-kile-windows-checklist.md) remains the
environment-specific evidence form, not a second refactoring backlog.

Historical findings and plans are preserved below for traceability. **They are
not a list of defects known to remain open.** In particular, the MIT design
reports implementation complete, and MS-KILE contains implementation notes
alongside an old Draft label and original gap tables. Reconcile each historical
ID (`KT-*`, `KI-*`, `KS-*`, `KC-*`, `KA-*`, `KN-*`, `KP-*`) with current code,
tests, and external evidence before changing behavior. Never reimplement an
old phase merely because an old acceptance checkbox is unchecked.

## 2. Assessment method and limits

Tooling:

- golangci-lint **2.15.0**, custom build from
  [the pinned manifest](../../.custom-gcl.yml), with NilAway
  `v0.0.0-20261112030514-ccd005690d1e`.
- Go **1.26.11**, Linux/amd64, readonly module resolution.
- [Canonical policy](../../.golangci.yml) and
  [expanded advisory profile](../../.golangci-report.yml).
- Tests enabled; issue caps disabled and duplicate-line filtering disabled.
  Existing configuration exclusions are retained.
- Corrected NilAway's copied unrelated-project scope to
  `github.com/otuschhoff/gokrb5/v8` in both profiles. Without this correction the canonical v8
  scan reported 2,970 findings and silently missed 295 NilAway diagnostics.
- Import grouping uses the exact v8 module prefix; removed a copied domain-layer
  isolation rule for a directory this project does not have. Canonical and
  advisory scans explicitly include tests; NilAway includes v8 test files.

Reproduce from the repository root after the setup in
[CONTRIBUTING](../../CONTRIBUTING.md#code-quality-and-refactoring):

```sh
export GOTOOLCHAIN=go1.26.11
LINT_REPORT_DIR=lint-reports bash scripts/lint.sh full
LINT_REPORT_DIR=lint-reports bash scripts/lint.sh report
(
  cd v8
  go test -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
  go tool cover -func=coverage.out
)
```

Both v8 lint profiles completed with exit **1** (findings), not analysis failure.
The v8 unit suite passed. Full inventories are JSON/text outputs of the runner
and CI artifacts; they are not duplicated as thousands of prose tasks here.
Counts are diagnostics, not unique defects, and profiles overlap.

The shared lint runner also assesses v7 with the other configured analyzers to
preserve the whole-project quality checks; NilAway is scoped to v8 only.
The v7 findings are not part of this refactoring backlog.

Scope is every package selected by normal `./...` loading in the v8 module,
including unit tests. Integration/example/custom build-tag configurations,
other operating systems, race detection, and live KDC runs were **not** executed
as part of this local assessment. Existing jobs are not represented as newly
passing. Analyzer alerts, especially NilAway and gosec, require validation;
this is a code-quality assessment, not an exploitability or compliance
certification.

### Measured baseline

These are the original assessment counts. The phase follow-ups below record
the current counts without overwriting the baseline.

| Profile | v8 findings | Interpretation |
| --- | ---: | --- |
| Canonical | 3,265 | Policy used by the changed-code gate |
| Expanded advisory | 4,016 | Additional structural, size, and modernization signals |

Canonical totals comprise 2,471 production / 794 test diagnostics in v8.

| Canonical analyzer | v8 |
| --- | ---: |
| bodyclose | 37 |
| copyloopvar | 2 |
| depguard | 1 |
| errcheck | 159 |
| errorlint | 252 |
| exhaustive | 3 |
| forcetypeassert | 49 |
| gci | 131 |
| gochecknoglobals | 36 |
| gocognit | 79 |
| gocritic | 351 |
| gofumpt | 90 |
| gosec | 333 |
| govet | 165 |
| interfacebloat | 3 |
| ireturn | 47 |
| nakedret | 28 |
| nestif | 47 |
| nilaway | 295 |
| nonamedreturns | 136 |
| revive | 525 |
| staticcheck | 79 |
| unconvert | 10 |
| unparam | 6 |
| unused | 5 |
| wrapcheck | 396 |

Enabled analyzers absent from this table emitted no findings in this scope.
Expanded-profile v8 noise is dominated by 1,123 `lll` and 956
`exhaustruct_v5` diagnostics. Its full-struct initialization rule differs
deliberately from the canonical annotation-only rule. Do not treat it as a
requirement to initialize every zero-valued field or rewrite fixture strings.

### Phase 1 follow-up measurements

Both profiles were rerun with the same pinned toolchain, analyzer build,
scope, test inclusion, and unlimited issue settings:

| Profile/analyzer | Original | After Phase 1 | Interpretation |
| --- | ---: | ---: | --- |
| Canonical total | 3,265 | 3,251 | 2,457 production / 794 test diagnostics; no new canonical diagnostic fingerprints after normalizing source-line shifts and existing complexity scores |
| Expanded advisory total | 4,016 | 4,038 | Additional negative-test fixtures increase structural advisories; this is not a reduction in all analyzer debt |
| NilAway | 295 | 293 | Two nil-cache-input flows removed; private session-value warnings remain explicitly dispositioned |
| errcheck | 159 | 157 | Both NDR discard results are now checked |
| gosec | 333 | 331 | Corresponding unhandled-error diagnostics removed; no blanket exclusions |
| govet | 165 | 163 | Both lost replay-cache metadata writes fixed |
| bodyclose | 37 | 35 | Exactly two helper-ownership false positives suppressed at their call sites after closure/error tests |

The advisory delta includes 27 additional full-struct fixture diagnostics,
one additional cyclomatic-complexity warning for the new dimension-product
guard, and one additional package-level repeated-literal warning. Removed
error/nil findings and method-order changes offset part of that increase.
Explicitly uninitialized clients are intentional regression inputs, not a reason
to initialize every field or weaken either profile. Existing high-complexity
functions still require Phase 3; this phase does not claim lint cleanliness.

### Phase 2 follow-up measurements

The same pinned tools, full v8 scope, test inclusion, and unlimited issue settings
were used again. The actual `scripts/lint.sh new 282e1bf` gate includes all added
files and passes both modules with **zero new canonical findings**.

| Profile/analyzer | After Phase 1 | After Phase 2 | Interpretation |
| --- | ---: | ---: | --- |
| Canonical total | 3,251 | 2,963 | 2,169 production / 794 test diagnostics; reduction of 288 |
| Expanded advisory total | 4,038 | 4,077 | 1,925 production / 2,152 test diagnostics; production decreases by 45 while test advisories increase by 84 |
| errorlint | 252 | 42 | 13 production / 29 test findings remain; none in the implemented production slices |
| errcheck | 157 | 127 | Mandatory write, sync, unlock, connection/body-close, and diagnostic-output results are retained |
| NilAway | 293 | 280 | Thirteen findings removed; the remaining invariant/test-fixture alerts are not declared resolved |
| gosec | 331 | 317 | Fourteen findings removed without changing legacy algorithm policy |
| govet | 163 | 162 | Shadowing reduction; no new changed-code diagnostics |
| bodyclose | 35 | 35 | No new bodyclose suppressions |
| wrapcheck | 396 | 382 | Fourteen fewer context/propagation findings |

The advisory increase includes fixture completeness, test length/complexity,
method ordering, and repeated-literal diagnostics. It is not a regression-gate
failure or a claim that structural debt has been eliminated. The remaining
production errorlint alerts are in configuration (7), command-line tools (2),
AD test support (3), and NEGOEX (1), outside these implemented boundaries.
Broader nil invariants, integer-bound classification, and structural work remain
open under Q-02/Q-05 and Phases 3-4.

## 3. Prioritized findings

Priority denotes remediation order, not a vulnerability severity.
Counts in the original findings below refer to the preserved assessment baseline;
the follow-up measurements above are current.

| ID | Priority | Finding and evidence | Required outcome |
| --- | --- | --- | --- |
| Q-01 | P0 | NilAway was scoped to an unrelated project; root-only commands miss v8. Corrected in this change. | Keep v8 included in both profiles and the automatic quality checks. |
| Q-02 | P1 | 295 NilAway and 49 unchecked type-assertion diagnostics. Example: [v8 ccache export](../../v8/client/ccache_export.go) dereferences session map values under a lock; NilAway does not establish that values cannot be nil. | Establish producer/consumer invariants and test missing/nil states. Confirm reachability before adding guards; do not silently skip invalid credentials. |
| Q-03 | P1 | 159 unchecked errors, 252 errorlint and 396 wrapcheck reports. Examples include deferred socket closes in [v8 network code](../../v8/client/network.go) and unchecked diagnostic writes in [v8 client code](../../v8/client/client.go). | Distinguish mandatory persistence/protocol failures from best-effort cleanup; preserve typed errors and first failure, and test injected failures. |
| Q-05 | P1 | 333 gosec diagnostics, including integer narrowing in ASN.1/wire encoding. The library intentionally supports legacy Kerberos algorithms. | Classify validated bounds, required legacy interoperability, and actual defects separately. Add boundary/rejection tests before changing casts or crypto negotiation. No blanket gosec exclusion. |
| Q-06 | P1 | 37 bodyclose reports need ownership analysis. The two production alerts in [PKINIT revocation](../../v8/pkinit/kdccert.go) delegate closure to `readRevocationBody`, which closes even on read failure. | Do not label every alert a leak. Verify helper ownership, response/error paths, and tests; use only narrowly justified suppressions for demonstrated false positives. |
| Q-07 | P2 | 79 cognitive-complexity reports. v8 ASExchange scores 185, Decoder.fill 115, LibDefaults.parseLines 105, PAC processing 84, and Keytab.Unmarshal 66 (threshold 15). | Separate parsing, policy, state transitions, and side effects in small compatible steps backed by characterization tests. |
| Q-08 | P2 | 165 govet reports include shadowing; 79 staticcheck reports mix behavior issues, deprecated APIs, and simplifications. [gokinit](../../v8/cmd/gokinit/main.go) still uses deprecated encrypted-PEM helpers. | Triage correctness before suggestions. Document supported identity formats and compatibility before replacing legacy PEM behavior. |
| Q-09 | P2 | Coverage is 84.4% but the gate is 70.0%; Windows checklist run record says not executed. Historical MS-KILE notes record a targeted live Windows FAST success, not completion of the full checklist. | Ratchet the measured coverage floor and critical-path tests; retain explicit outstanding Windows/fixture/platform release gates. |
| Q-10 | P3 | Revive, gocritic, formatters, named returns, and interface rules dominate remaining debt; IANA tables and fixture-heavy tests contribute many diagnostics. | Apply package-sized mechanical changes separately from behavior fixes; retain public interfaces and wire constants unless a compatible migration is agreed. |
| Q-11 | P3 | 5 unused and 6 unparam reports, plus advisory modernize/prealloc/perfsprint findings. | Confirm build-tag and external API usage before deletion; preserve v8's declared Go minimum. Benchmark performance changes rather than assuming improvement. |

Finding IDs are stable: Q-04 was a v7-only finding and is excluded from this
v8 roadmap, not renumbered or carried forward as a remediation task.

The largest v8 canonical concentrations are `client` (446), `spnego` (350),
`types` (275), `pac` (175), `messages` (158), `iana/errorcode` (155), internal NDR
(154), and `keytab` (143). These totals include tests and style diagnostics:
package size alone does not determine priority.

## 4. Phased remediation for LLM execution

### Execution contract for every task

1. Select one phase and a package-sized slice inside v8. Record the finding IDs,
   initial diagnostics, and acceptance tests in the PR description. Do not
   refactor root-module v7 code as part of this roadmap.
2. Read current code, callers, historical IDs below, and relevant protocol
   requirements. Do not treat historical snippets or commands as current APIs.
   Run v8 commands **inside `v8`**, never `go test ./v8/...` from the root module.
3. Add a failing deterministic regression or characterization test before a
   behavioral fix. Preserve exported APIs, wire bytes, error identity,
   authentication ordering, locking, deadlines, and filesystem guarantees.
4. Make a focused change. Do not run repository-wide `--fix`, delete rejection
   branches for coverage, add silent fallback behavior, weaken policies, or
   increase complexity thresholds. A false positive needs a specific linter
   name, a reason, and evidence.
5. Run focused unit tests, then `(cd v8 && go test ./...)`.
   Run `go test -race` for concurrency/state changes and the appropriate
   integration/fuzz jobs for protocol/parser changes. External prerequisites
   must be stated when unavailable, not reported as passing.
6. Run `bash scripts/lint.sh new BASE_REV` against the real PR base and regenerate
   both full inventories. Require zero new canonical changed-line diagnostics;
   verify relevant v8 diagnostics decreased without merely moving.
7. Update this document's phase status, ID disposition, tests, and measured
   counts in the same PR. Stop if requirements conflict; do not broaden scope.

### Phase 0 - Reliable assessment and non-regression gate

Status: implemented by this assessment; hosted execution and branch protection
remain administrator/CI verification steps.

- Q-01: scoped NilAway to v8 in both profiles, set the exact v8 import-grouping
  prefix, and removed the unrelated domain-layer rule; other policy choices
  are retained.
- Added a pinned custom build, two-module runner, whole-project JSON/text
  inventories, and a canonical added/changed-line gate.
- PR base SHA covers the entire PR, not only its last commit; pushes use their
  before SHA. Scheduled/manual scans report existing debt without hiding
  analyzer/configuration failures.
- Full scans remain unfiltered. No baseline is baked into the policy file.

Exit: both profiles validate; both modules analyze; an injected changed-code
diagnostic fails the gate; tooling failures fail CI; artifacts are uploaded.
Require `golangci-lint` through repository branch protection separately.

Local verification: the custom binary rebuilt successfully from the manifest;
the shared runner reproduced all four totals; the clean revision gate passed
both modules; an injected unused function on a changed v8 line failed the actual
revision gate; a separate added-file patch with an unchecked error also failed.
Both probes were removed. Invalid revisions and missing binaries returned 2.
Hosted workflow execution and artifact delivery still require a GitHub run.

### Phase 1 - Reconcile historical claims and validate correctness alerts

Status: **complete**. The next implementation phase is Phase 2.

Depends on Phase 0. Findings: Q-02, Q-03, Q-05, Q-06, and Q-08.

Start with v8 session/cache nil invariants,
untrusted parser boundaries, response ownership, and error-loss reports.
For each historical ID in the appendices, record one of: implemented with named
test, confirmed open with regression, false positive with reasoning, or external
evidence pending. Maintain the disposition adjacent to its historical record;
do not create a second backlog.

Use focused commands such as `(cd v8 && go test ./client ./credentials ./keytab
./messages ./pac ./pkinit)`.
Audit custom-tag callers before changing shared code.

Exit: every selected v8 nil/resource/overflow/error
alert has evidence and disposition; confirmed fixes remove their diagnostics;
no unsupported claim of complete Windows compliance is introduced.

#### Completed correctness triage

| Selected alert or boundary | Disposition | Evidence |
| --- | --- | --- |
| [Client ccache export](../../v8/client/ccache_export.go): missing private state in an otherwise public `Client` value | Confirmed panic fixed: reject nil/incomplete clients explicitly, without silently dropping credentials | `TestCCacheRejectsUninitializedClient`; existing `TestClientCCacheExportRoundTrip` and PA-type export tests still pass |
| [CCache import](../../v8/client/client.go): nil input | Confirmed panic fixed before dereferencing the cache; nonnil empty-cache behavior is unchanged | `TestNewFromCCacheRejectsNil`; the two NilAway flows into `GetConfig` disappear |
| [Private session map values](../../v8/client/session.go) and sorted export lookups | Retained analyzer limitations: production writers construct nonnil sessions, the map is private, and export holds its read lock across collecting/sorting/reading keys. No invalid entry is silently skipped | Constructor/import producer audit, `TestClientCCacheExportRoundTrip`, session lifecycle tests, and the full race suite |
| [NDR arrays](../../v8/pac/internal/ndr/arrays.go): empty dimensions, product bounds, and varying offsets | Confirmed defects fixed: derive empty dimensions from reflected types, generate no indices for zero-sized dimensions, validate count products before allocation, and read `offset + actual_count` ranges | `TestDecodeEmptyMultidimensionalArrays`, `TestDecodeMultidimensionalArrayResourceLimits`, `TestDecodeConformantVaryingArrayOffsets`, and `FuzzDecodeArrays` |
| NDR `makeSubSlices` bounds reports | False positives under the private caller contract: the suffix length is derived from the same reflected slice depth, not a wire-supplied dimension-vector length | Fixed/varying/conformant array tests, zero-sized inner/outer cases, `TestDecodeThreeDimensionalConformantArray`; warnings retained rather than broadly suppressed |
| [NDR alignment](../../v8/pac/internal/ndr/primitives.go) and [union discriminant](../../v8/pac/internal/ndr/union.go) discard errors | Confirmed unchecked reads fixed: retain wrapped failures in decoder error state instead of ignoring them | `TestTruncatedAlignmentRecordsError`, `TestTruncatedUnionDiscriminantRecordsError`; both errcheck and G104 pairs disappear |
| [PKINIT response ownership](../../v8/pkinit/kdccert.go) | Demonstrated false positives: the response immediately transfers to `readRevocationBody`, which closes it on every read outcome. Only those two bodyclose reports are suppressed | `TestReadRevocationBodyOwnsClose` checks exactly-once closure, oversize rejection, error identity, and read-before-close failure precedence; OCSP/CRL tests pass |
| [PKINIT SID bounds](../../v8/pkinit/identity.go) | False positives: an eight-byte minimum and exact `8 + 4*subauthority_count` length check precede all four-byte subauthority reads; the byte-sized count cannot overflow the arithmetic | Bounds proof against the loop and the passing identity suite; no suppression or wire-format change |
| [Replay-cache metadata and locking](../../v8/service/cache.go) | Confirmed lost writes and non-atomic replay acceptance fixed under a single lock; zero-valued caches initialize safely. Re-evaluation also found and fixed cross-service eviction and cross-realm/component identity collisions | `TestReplayCacheUpdatesAuthenticatorMetadata`, `TestReplayCacheConcurrentCheckAndInsert`, `TestReplayCacheConcurrentDistinctUpdates`, `TestReplayCacheSeparatesServicesAndRealms`, `TestReplayCachePrincipalComponentsAndTimeIdentity`, expiry tests, and 100 race-enabled repetitions |

The additional replay-identity defects were reproduced after the first locking
fix, not declared complete on the first passing test run. Keys now include the
client realm and exact principal components, service identity, and normalized
authenticator time while preserving same-client/different-service acceptance.

All **83 historical IDs** now have a disposition beside their original record:
**79 implemented/documented**, **3 confirmed open with rejection regressions**,
and **1 external-evidence gate**. The open items are KC-12/KA-6 (legacy RC4 GSS
MIC/Wrap) and KA-7 (user-to-user acceptor ticket-key support). Existing RC4
primitive tests do not establish GSS token support. The new
`TestVerifyAPREQUserToUserRequiresAcceptorKeySupport` passes the explicit
realm-qualified principal policy, then demonstrates the missing acceptor key
source rather than an unrelated policy failure. KN-3's local PKU2U exchange does
not establish fixture-14 or Windows interoperability. KT-19's intentional
raw-key JSON behavior is now accompanied by an explicit disclosure warning.

#### Exit verification

- Full v8 unit suite and full v8 race suite pass.
- Affected client, service, NDR, and PKINIT suites pass on Linux/386 as well as
  amd64; focused `go vet` passes.
- Replay regressions pass 100 race-enabled repetitions, including concurrent
  insertion/cleanup and identical-authenticator acceptance.
- The new NDR array fuzz target passes two runs of at least 60 seconds with valid
  empty/nonempty and nonzero-offset seeds; the final run executes over 1.4 million
  cases without a crash.
- Both complete lint profiles were remeasured; the actual shared
  `scripts/lint.sh new d24235c` gate passes both modules with zero new canonical
  findings. Tests added in this phase are included in the diff gate.
- Semantic checks report only existing NDR simplification suggestions. No
  live MIT/Samba/Windows or hosted-workflow pass is claimed by these local runs.

Phase 1's selected correctness fixes and reconciliation are complete, not all
Q-02/Q-03/Q-05/Q-06/Q-08 debt or historical feature gaps. The remaining items are
explicit inputs to later phases rather than hidden claims of compliance.

### Phase 2 - Error contracts and deterministic failure coverage

Status: complete for the persistence, transport, decoding, and HTTP boundaries
below; this does not close every analyzer alert under Q-02/Q-03/Q-05/Q-06.

Depends on Phase 1 for the affected package. Findings: Q-02, Q-03, Q-05, Q-06.

Work in slices: keytab/ccache persistence, TCP/UDP/HTTPS transport, crypto/message
decoding, then HTTP authentication. Reuse existing bounded reads, write helpers,
typed errors, and injectable transports. Propagate mandatory errors with context;
retain errors.Is/As and existing KRB error behavior. Test read/write/close,
short-write, malformed length, timeout, and cancellation paths. Never replace
a useful error with a later cleanup error.

Compatibility follow-through from Phase 1: retain the existing explicit RC4
GSS rejection (KC-12/KA-6) and user-to-user acceptor rejection (KA-7) until
dedicated, policy-reviewed implementation slices supply the legacy token or
alternate ticket-key contracts. Do not silently enable a legacy algorithm,
repurpose a service keytab as a TGT key store, or count primitive/U2U request
tests as acceptor support. Each slice must replace its rejection characterization
with positive/negative protocol vectors before Phase 4 interoperability gates.

Exit: no unexplained correctness diagnostics in each completed slice; boundary
and injected-failure tests pass, including races for shared state. Parser fuzz
targets run at least 60 seconds with valid corpus seeds and malformed inputs.

#### Implemented slices and re-evaluation

- **Persistence:** keytab and ccache atomic replacement share
  [one internal writer](../../v8/internal/fileio/atomic.go). It enforces private
  permissions, detects short writes, syncs/closes before rename, retains cleanup
  failures behind the primary cause, and syncs the directory after replacement.
  A post-rename directory-sync failure reports an error without deleting the
  committed target. Object filenames update only on success. Keytab append also
  retains unlock and close errors in operation order. Existing platform-specific
  no-op locking/directory-sync policies are unchanged, not newly certified.
  [Fault-injection tests](../../v8/internal/fileio/atomic_test.go) cover each
  writer operation, cleanup combinations, exactly-once close, and first typed
  cause selection.
- **Transport:** TCP/UDP exchanges own and close their connection; endpoint and
  protocol failover preserve causes rather than stringify them. TCP bounds and
  short writes remain enforced; UDP can receive a full datagram rather than
  truncate at 4 KiB. KKDCP closes intermediate responses exactly once and retains
  both processing and close errors. The
  [socket](../../v8/client/network_errors_test.go) and
  [HTTPS](../../v8/client/kkdcp_errors_test.go) regressions cover short writes,
  truncated frames, typed timeout/cancellation causes, close failures, and
  failover order. Traditional TCP/UDP retain their existing five-second
  deadline; no new caller-context API is implied.
- **Decoding/error identity:** production crypto, message, PAC, service, and
  SPNEGO wrappers retain causes with `%w`. AS/TGS and ASN.1 reply classification
  recognize wrapped typed errors. Re-evaluation found that NDR's custom
  `Malformed` wrapper still erased causes: it now unwraps, including truncated
  headers/values, while retaining its classification and existing contextual
  text. Invalid decode targets/unsettable fields return errors instead of
  reflection panics. See the
  [NDR](../../v8/pac/internal/ndr/decoder_errors_test.go),
  [crypto](../../v8/crypto/common/common_errors_test.go), and
  [KRB reply](../../v8/messages/KRBError_test.go) regressions.
  `krberror.Errorf` intentionally flattens only a bare `Krberror`; a narrow
  errorlint exception and
  [wrapper-identity test](../../v8/krberror/error_test.go) prevent losing
  intervening wrappers.
- **HTTP authentication:** internal response closure preserves negotiation and
  cleanup errors, while final returned bodies stay caller-owned. Legacy
  redirects use a per-request budget instead of shared mutable history;
  authentication stops after ten round trips. Retried bodies require
  `Request.GetBody`, not partial tee-buffer replay. Real file-body tests prove
  307 redirects reopen the already-closed target body and 303 redirects do not
  restore a POST body. Nil headers/requests, absent Kerberos clients, cancellation,
  failed replay, concurrent independent redirects, and body ownership are
  covered in [HTTP error-contract tests](../../v8/spnego/http_errors_test.go).
  The G704 annotation is restricted to the general-purpose client's deliberate
  caller-selected destination, not a global SSRF exclusion.
- **Diagnostics:** re-evaluation also found writer failures hidden by the legacy
  void `Print` method. Shared rendering now retains JSON encoding errors and
  output/short-write errors. `Diagnostics` returns them alongside prior
  validation failures; signature-compatible `Print` logs a failure through the
  configured logger and stops. See
  [encoding/output regressions](../../v8/client/client_errors_test.go).

Remaining unchecked-error alerts are not silently treated as operational
success: logger output remains best effort behind existing void APIs, and
legacy RC4 `RandomToKey` copies an in-memory reader into a hash writer whose
contract cannot return a write error. Neither requires inventing a panic or
changing a public crypto signature. Configuration/CLI/test-support cleanup,
other nil invariants, and parser/state-machine complexity remain separate
backlog work; this phase does not claim a lint-clean project.

#### Exit verification

- Full v8 unit and race suites pass with Go 1.26.11.
- Affected persistence, client, crypto, message, PAC/NDR, SPNEGO, and error suites
  pass on Linux/386; affected-package `go vet` passes.
- Failure/ownership/concurrency regressions pass 100 race-enabled repetitions;
  final diagnostic encoding/output regressions also pass 100 repetitions.
- Persistence cross-builds pass for Windows/amd64, Darwin/arm64, FreeBSD/amd64,
  AIX/ppc64, Solaris/amd64, illumos/amd64, and Plan 9/amd64. These are compile
  checks, not native filesystem/interoperability evidence.
- Seeded keytab, ccache, NDR-array, and SPNEGO-token fuzz targets each complete
  at least 60 seconds. The first keytab run reported `context deadline exceeded`
  at shutdown without a failing input; two subsequent 65-second runs pass,
  each exceeding 1.6 million executions. NDR also passes a second 65-second run.
- Both complete lint profiles were remeasured, and the actual changed-code gate
  is clean without weakening analyzer configuration.

No live KDC, Windows fixture-14, hosted-workflow, RC4 GSS, or user-to-user
acceptor implementation pass is claimed. Their explicit compatibility and
external-evidence gates remain unchanged. The next implementation phase is
Phase 3, starting with ASExchange.

### Phase 3 - Decompose high-complexity state machines and parsers

Depends on Phases 1-2 for the affected surface. Finding: Q-07.

Order: ASExchange; NDR Decoder.fill; configuration parseLines; PAC processing;
keytab decoding. Treat each as a separate PR series. Extract coherent transitions
or decoding operations, not arbitrary line-count helpers. Preserve retry budgets,
FAST downgrade checks, referral handling, lock ownership, wire bounds, and
metadata. Keep original tests and add branch-level characterization as needed.

Slice 1 progress (2026-11-17): ASExchange now uses private per-exchange
preparation, transition, and reply methods. Scripted characterization passes
against both the original and decomposed implementations, including PKINIT
freshness/fallback budgets, FAST error semantics, referrals, request aliasing,
and reply-key publication. Relevant unit/race tests, build, vet, and diagnostics
pass; remaining Phase 3 slices and the interoperability exit gate remain open.

Slice 2 progress (2026-11-17): NDR `Decoder.fill` now delegates struct traversal,
union selection, parent-sized raw fields, scalars, strings, and slice dispatch to
private decoding operations. Added characterization passes against the original
implementation before extraction, including exact error text/chains, tracker
retention on errors, reflection assignment behavior, dispatch precedence, and
deferred raw pointers. Existing NDR/PAC/messages tests and their race runs,
build, vet, and error diagnostics pass; the seeded array-offset fuzz target
`FuzzDecodeArrays` passes a 65-second run. The selected-union error deliberately
retains its existing non-wrapping behavior. Remaining slices and the complete
MIT/Samba interoperability exit gate remain open.

Slice 3 progress (2026-11-17): `LibDefaults.parseLines` now delegates to private
typed boolean, duration, string, collection, and constrained-value parsers.
Characterization passed before extraction and against the original parser via
an overlay, preserving comment/equality quirks, append-versus-replace behavior,
exact errors, partial mutation, numeric limits, and deferred enctype-ID updates.
The target and all extracted helpers have 100% statement coverage; config/client
unit and race tests, repeated characterization, relevant build/vet, and error
diagnostics pass. The canonical new-code gate is clean; full zero-threshold
measurement gives target cognitive complexity 9, helpers at most 7, and actual
control-flow nesting at most 2 (limits 15/4). Other configuration parsers remain
unchanged. PAC/keytab slices remain open; the pinned MIT-KDC/Samba matrix remains
a CI obligation, separate from the approved supplied-KDC local integration gate.

Slice 4 progress (2026-11-17): `PACType.ProcessPACInfoBuffersWithCredentialKey`
now dispatches each known buffer type to a private per-type processing method,
with prior decode state reset extracted, preserving buffer order, duplicate
detection, signature zero-copy timing, skipped credential/claims buffers, exact
error chains, and partial-state retention on failure. Branch-level
characterization covers validation-before-reset immutability, per-type decoder
error chains, duplicate rejection, metadata/logging behavior, and successful
decodes against the MS test vectors. The target's cognitive complexity dropped
to 12 with helpers at most 12 and control-flow nesting at most 2 (limits
15/4). The new seeded `FuzzPACProcessingInfoBuffers` target immediately exposed
a pre-existing fatal path: PAC client/device claims routed the embedded
ClaimsSet through the unbounded upstream `github.com/jcmturner/rpc/v2` NDR
decoder, so a small malformed PAC could terminate the process with a runtime
out-of-memory error (`fatal error`, exit status 2, not recoverable). ClaimsSet
decoding now mirrors `mstypes.ClaimsSetMetadata.ClaimsSet` with the bounded
PAC-internal decoder, preserving compression handling (including Huffman
deflate), error text, and the metadata mutation contract, and promoting
`golang.org/x/net` (already in the module graph for exactly this purpose) to a
direct requirement. Regression tests cover oversized wire counts rejected
promptly, unsupported-compression and deflate errors, decode equivalence on all
claims vectors, and device-claims coverage; a 2.6-million-case mutation sweep
found no further slow or fatal inputs, and the fuzz target passes a 180-second
run (previously crashing within 35 seconds on every attempt). The legacy v7
line retains the same upstream decoder calls and is outside this roadmap.
PAC/client/service/spnego unit and race tests, full v8 unit tests, build, vet,
and the changed-code lint gate pass. The keytab slice and the pinned
MIT-KDC/Samba matrix remain open.

Slice 5 progress (2026-11-18): `Keytab.Unmarshal` now delegates header
validation, version-1 byte-order detection, record-stream iteration, hole
skipping, record decoding, and per-entry field decoding to private operations,
and `parsePrincipal` returns a value built from a shared counted-string reader
instead of mutating through the keytab. The 32-bit KVNO trailer and 8-bit key
version are read with new unsigned readers, preserving wire bit patterns
(including trailers above the int31 range) without narrowing conversions; the
then-unused signed 8-bit reader and the deprecated unexported `entry`/`principal`
aliases are removed. No exported signature, wire, error-text, or error-identity
changes. Branch-level characterization in
[unmarshal_characterization_test.go](../../v8/keytab/unmarshal_characterization_test.go)
covers header validation order and field-mutation side effects, exact hole and
record-bounds errors, per-field truncation error text and wrap behavior,
trailing-garbage termination, KVNO trailer presence/zero/override rules,
partial-state retention on failure, and ambiguous version-1 byte-order
fallback to native order; it passed against the original implementation before
extraction. The target's cognitive complexity dropped from 66 to 2, with
helpers at most 10 (`parsePrincipal`) and control-flow nesting at most 1
(limits 15/4). `ParsePrincipal` (46), `GetEntry` (29), and `AppendToFile` (24)
are principal-text parsing, lookup, and persistence rather than decoding and
remain canonical-debt candidates for Phase 5 ratcheting. The target and its
helpers have 100% statement coverage except three unreachable defensive
branches (negative-offset and post-guard read guards retained from the
original defensive style) and the big-endian-host byte-order probe line, which
requires a big-endian host like the pre-existing native-order helpers. Keytab
package canonical diagnostics fell from 123 to 104 without merely moving; the
regenerated full v8 inventories after all Phase 3 slices are 2,886 canonical
and 4,163 advisory diagnostics. Keytab unit tests pass under race detection
with 10 repetitions, the full v8 unit suite passes, Linux/386 tests pass,
Windows/Darwin/FreeBSD/s390x compile checks pass, the changed-code lint gate
is clean for both modules, and the seeded `FuzzUnmarshal` target passes a
120-second run (734,923 executions, no new interesting inputs). All five
Phase 3 slices are now implemented. The pinned MIT-KDC/Samba matrix remains a
CI obligation, separate from the approved supplied-KDC local integration gate;
Docker is unavailable in this environment, so no live interoperability pass is
claimed here.

Exit: touched functions meet canonical cognitive complexity 15 / nesting 4
thresholds, or a separately reviewed protocol-specific exception is justified;
tests, race tests, relevant fuzzing, and MIT/Samba integration pass. No exported
signature changes are needed solely to satisfy a style analyzer.

### Phase 4 - Coverage and interoperability release evidence

Depends on Phase 0; can proceed independently of Phases 1-3 on untouched areas.
Finding: Q-09. Historical coverage requirements are preserved in Appendix C.

1. Reproduce the 84.4% result with CI's Go/platform instrumentation and raise the
   70.0% floor to a justified floor close to the reproducible minimum. Never
   assume a locally measured percentage is portable or lower a floor to merge.
2. Prioritize untrusted decoders and cryptographic rejection paths to at least
   90%; authentication packages to at least 75% overall and security-sensitive
   transitions to 90%. Verify these numerically per package/function.
3. Retain all coverage workstreams: deterministic AS/TGS/FAST/PKINIT/S4U/GSS
   peers, scheduled fuzzing/corpora, MIT/Samba and Windows interoperability,
   native filesystem/network behavior, and mobile runner coverage.
4. Complete and attach the Windows checklist, including pending captured
   fixture 14 and PKU2U directions, claims, PKINIT, IIS/RPC, and KKDCP.
   Distinguish historical targeted FAST success from full-suite evidence.
5. Progress toward the historical strict **100% combined production statement
   coverage** goal using merged source-block profiles from native, integration,
   subprocess, version, and platform jobs. Track uncovered blocks and their
   executing job; do not fake profiles, reduce coverpkg, or hide rejection paths.

#### Phase 4 progress (2026-11-18, local items)

Items 1 and 2 are implemented; items 3-5 remain standing or external work.

Measured with the CI job's exact command (`go test -covermode=atomic
-coverpkg=./... -coverprofile=coverage.out ./...` inside `v8`, Go 1.26.11,
Linux/amd64, the platform family the coverage job runs on):

| Package | Target | Before | After |
| --- | ---: | ---: | ---: |
| `messages` | 90% | 82.1% | **90.9%** |
| `credentials` | 90% | 87.7% | **95.2%** |
| `asn1tools` | 90% | 100.0% | 100.0% |
| `types` | 90% | 92.6% | 92.7% |
| `pac` (incl. internal NDR) | 90% | 90.8% | 90.9% |
| `keytab` | 90% | 93.2% | 93.2% |
| `crypto` | 90% | 92.5% | 92.8% |
| `client` | 75% | 81.0% | 81.0% |
| `service` | 75% | 80.0% | 80.0% |
| `spnego` | 75% | 82.4% | 82.4% |
| **Total** | — | 85.9% | **86.9%** |

The [messages decoder coverage tests](../../v8/messages/decoder_coverage_test.go)
add truncation sweeps over every valid message vector (every strict prefix must
be rejected), byte-flip robustness sweeps, marshal round trips, msg-type and
ticket-sequence rejections, wrong-key and integrity failures, and branch-level
tests for the security-sensitive transitions: `APReq.Verify` (ticket decrypt,
validity, client-address, authenticator-integrity, CName, and skew branches),
`APRep.VerifyDCE` (sequence, subkey, and skew branches), the AS-REP
`verifyWithReplyKey` reply checks (CName/realm/nonce/SName/SRealm/addresses/
skew and the PA-REQ-ENC-PA-REP acknowledgment paths), and S4U error paths.
`APReq.Verify`, `APRep.Verify`/`VerifyDCE`, the AS-REP/TGS-REP `Verify`
families, and `Ticket.ValidAt` now report 100% statement coverage and
`verifyEncPARep` reports 94.7%. A seeded `FuzzMessageUnmarshal` target covers
every wire decoder in the package, is wired into the CI fuzz matrix, and passes
a 90-second run (13 million executions); `FuzzCCacheUnmarshal` passes a
65-second run. The
[credentials coverage tests](../../v8/credentials/ccache_coverage_test.go) add
full truncation and byte-flip sweeps, v1/v2 native-order parsing, header-field
rejections, marshal-time state validation, name-resolution rejections, and
delegated-credential deep-copy checks. Remaining uncovered blocks in both
packages are dominated by asn1.Marshal error branches that are unreachable
with valid in-memory values and by big-endian-host probe lines.

The [coverage floor](../../.github/workflows/testingv8.yml) rises from 70.0%
to **86.0%** (86.9% measured minus the historical ~0.9-point instrumentation
margin). The floor remains a single aggregate gate; per-package targets are
verified here numerically but are not yet separately enforced in CI.

Not done locally (external prerequisites, unchanged): the Windows checklist
including fixture 14, PKU2U directions, claims, PKINIT, IIS/RPC, and KKDCP;
the MIT/Samba and Windows AD interoperability matrices; native Windows/macOS
runs; and mobile-runner coverage. Merged multi-job source-block profiles for
the strict 100% goal remain future work. Docker is unavailable in this
environment, so no live interoperability evidence is claimed.

Exit: monotonically raised measured floors, critical-path targets verified,
external gaps explicitly recorded with prerequisites/owner/run evidence, and
eventual 100% combined coverage verified only when all required jobs execute.
Compile-only mobile checks must never be labeled native runtime coverage.

### Phase 5 - Mechanical quality cleanup and sustainable ratcheting

Depends on Phase 0; defer edits to functions under Phases 1-3 until they settle.
Findings: Q-08, Q-10, Q-11.

Apply formatter fixes package by package in mechanical-only PRs. Address
shadowing, naming, return clarity, deprecated APIs, and dead code with
compatibility checks. Separate protocol tables and long fixtures from ordinary
logic when judging line-length/constants suggestions. Keep advisory rules
advisory until intentionally adopted; avoid adding dependencies for style fixes.

Slice 1 (2026-11-18, formatter normalization): the pinned custom linter's
`fmt` command (gofumpt and gci with the v8 import group) was applied across
the v8 module in one mechanical-only change, clearing all 213 canonical
formatter findings (127 gci, 86 gofumpt): import grouping, comment spacing,
octal-literal prefixes, and redundant declaration forms. No code, wire, API,
or behavior changes; the full canonical scan now reports zero gofumpt/gci
diagnostics in v8.

Slice 2 (2026-11-18, keytab): the three non-decoding complexity outliers
deferred from Phase 3 now meet the canonical thresholds. `ParsePrincipal` (46)
splits into separator classification, a splitter state machine with per-role
methods, and escape writing; `GetEntry` (29) splits into an entry-lookup
accumulator with per-candidate consideration and result resolution;
`AppendToFile` (24) extracts its existing-file inspection into `appendTarget`.
All resulting functions score at most 14 cognitive complexity with no nested-if
findings (limits 15/4). Branch characterization added first pins exact parse
error texts, enterprise/escape edge cases, KVNO tie-breaks and fallback
preference, and no-entry append behavior; it passed against the original
implementation. The Yoda if-else chain in `isNativeEndianLittle` became a
switch and a dead declaration comment was removed. Keytab package canonical
findings fell from 104 to 92; the remainder are intentional wire-format
integer conversions (gosec G115/G103), Phase 2's deliberate error-propagation
deferrals (wrapcheck), and pre-existing test-file findings — all explained
categories, not new debt. The v8 canonical total is now 2,449 (from 2,886
after Phase 3). Keytab unit and race tests (5 repetitions), Linux/386 tests,
the full v8 suite, Windows/Darwin builds, and the changed-line lint gate
(0 issues, both modules) pass.

Slice 3 (2026-11-18, dead code and vestigial parameters; Q-11 cleared):
removed the unused `DomainRealm.deleteMapping` method, the misspelled unused
`verisonHex` constant, two unused gssapi test helpers, and unused parameters
that never influenced behavior: the `export` flag of the private rfc4757
`deriveKeys` (the exported `EncryptMessage`/`DecryptMessage` signatures are
unchanged; RC4-HMAC-EXP key weakening was never implemented and the flag was
already ignored), the redundant element-type parameter of the two
multi-dimensional NDR array fillers, and always-constant or unread test-helper
parameters in pac and messages tests. The v8 canonical scan now reports zero
`unused` and zero `unparam` findings, and the total is 2,435. The full v8
suite, race tests for all touched packages, a 60-second `FuzzDecodeArrays`
run (5.4 million executions), and the changed-line lint gate (0 issues, both
modules) pass.

Slice 4 (2026-11-18, mechanical clarity sweep): cleared all canonical gocritic
and mechanical staticcheck findings in v8 plus unconvert, copyloopvar, and
nakedret: comment formatting, operator-assignment forms, redundant
dereferences and conversions, loop-variable copies (safe at the Go 1.26
floor), per-call regexp compilation replacing in-loop `regexp.MatchString`,
switch rewrites of tagged if-else chains, explicit return values replacing
naked returns in long functions, `make` capacity simplifications, a typed
SPNEGO context key (SA1029), De Morgan simplification, and removal of a dead
nil check, an empty branch, a duplicated NDR pipe bounds check, and a dead
append accumulation (SA4010; the stream reads were preserved). appendAssign
sites were reviewed individually: every source slice was exact-capacity or
dead after the append, so all were rewritten as same-name assignments with
identical observable behavior. Deliberately not touched: ST1005 error texts
(several are pinned by characterization tests), SA1019 legacy cryptography
(MD4 for RC4-HMAC, the best-effort rc4 key wipe, PKCS1v15 in PKINIT, PEM
helpers deferred under Q-08, PKINIT CRL APIs needing a compatibility review),
and four pedantic govet inline reports against stdlib `reflect.Ptr` uses
(inlining the constant would harm readability; reviewed, not actionable).

Slice 5 (2026-11-18, govet shadow elimination; Q-08): eliminated all 146
shadow findings in v8 production and test code by renaming inner declarations
(script-assisted for `if`-initializers, hand-reviewed for everything else).
Notably, `client.sendToKDC`'s UDP-first block was verified self-consistent
under the shadowed name before renaming, and `GetCachedTicket`'s cache-hit
short-circuit now returns distinctly named variables. Discovered and recorded for a dedicated correctness slice (wire-acceptance
behavior change requiring characterization): NDR `readCommonHeader` read
`CharacterEncoding` from the version byte (`vb & 0xF`) instead of the
endianness/encoding byte (`eb & 0xF`), so the field always read 1 and encoding
validation never rejected. It was fixed with characterization in Slice 9
below; nothing consumes the field today.

The v8 canonical total is now 2,103 (from 2,435): gocritic 0, unconvert 0,
copyloopvar 0, nakedret 0, govet 4 (only the documented inline reports),
staticcheck 24 (all documented deferral categories above). Full v8 unit and
race suites, the changed-line lint gate (0 issues, both modules), and 45-60
second seeded fuzz runs of the touched decoders (NDR arrays, SPNEGO negtoken,
GSS wrap/MIC) pass.

Slice 6 (2026-11-18, errorlint; zero remain): non-wrapping `%v` verbs on errors
became `%w` in test support and production formatters (message text unchanged,
wrapping strictly additive), error type assertions became errors.As in config
parsing and service tests, and `err == flag.ErrHelp` became errors.Is in
goklist. The krberror wrapper-identity test's deliberate exact-type assertion
retains a narrow, reasoned `//nolint:errorlint` matching the existing Phase 2
exception style.

Slice 7 (2026-11-18, revive mechanical subset): unused parameters renamed to
`_`, including the interface-required but intentionally unused crypto
parameters (AES-SHA2 `VerifyIntegrity` plaintext, RC4-HMAC salt/s2kparams
ignored per RFC 4757, and the never-implemented RC4-HMAC-EXP `export` flag,
now documented as retained-for-compatibility in both directions), plus the
PAC logger parameter that was already unused before Phase 3 (forwarding
wrapper retains its named parameter). Package comments added to the command
packages, krbcli, and pkinit; else-after-return flattened, including the
SPNEGO AP-REP subkey/ticket-key fallback with its exact error text preserved;
`score += 1` became `score++`; and the etype interface's `string` parameter
renamed to `secret` (redefines-builtin-id). Deliberately retained as explained
debt: var-naming findings in the iana protocol constant tables (names are
public API and follow the protocol documents), revive "stutters" reports for
established public names (SPNEGOClient/SPNEGOService/SPNEGOToken et al.), and
error-strings findings pinned by error contracts and characterization tests.

Slice 8 (2026-11-18, exported documentation): added accurate doc comments to
all 144 previously undocumented exported symbols and constant/variable blocks
across types (MS-KILE, FAST), pkinit, negoex, pac, iana, service, spnego, and
test/ad, with protocol references (RFC 4556, MS-KILE, MS-PAC, MS-NEGOEX,
MS-ADA2, MS-ERREF) where applicable. No code changes.

The v8 canonical total is now 1,872. Remaining debt concentrates in gosec
(Q-05 classification), NilAway (Q-02 invariants), wrapcheck/errcheck (Q-03),
gocognit/nestif on remaining complex functions, ireturn/gochecknoglobals
(API design decisions), nonamedreturns (Phase 2 defer-join patterns), and
bodyclose (Q-06 helper ownership).

Slice 9 (2026-11-18, Phase 3 NDR carry-over and recorded header defect): fixed
`readCommonHeader` to read `CharacterEncoding` from the second header byte's
low nibble (`eb & 0xF`) instead of the version byte (`vb & 0xF`). The defect
made every valid version-1 stream report EBCDIC (1) and incorrectly accepted
invalid character-encoding nibbles. Characterization covers big/little-endian
ASCII/EBCDIC combinations, invalid endianness/encoding/length, truncation,
multidimensional varying and conformant-varying offsets/counts and resource
failures, and conformant maximum scanning. The fix exposes the actual encoding
metadata and rejects nibble values outside 0/1; the ASCII/EBCDIC value is not
yet used for string interpretation, so valid existing PAC streams are
unchanged on the wire. The complexity targets `conformantScan` (16),
`fillMultiDimensionalVaryingArray` (18), and
`fillMultiDimensionalConformantVaryingArray` (20) now dispatch to coherent
maximum-slot registration, dimension reading, nested-slice allocation, and
index traversal helpers; target/functions/helpers stay at cognitive
complexity at most 8 and nesting below 4 (canonical limits 15/4). All NDR/PAC
unit and race tests pass; `FuzzDecodeArrays` passes a 90-second run (9.39
million executions); the changed-line lint gate is clean for both modules.
The v8 canonical total is 1,869.

Slice 57 (2026-11-19, AD fixture discovery; Q-03/Q-05):
AD discovery now identifies working-directory and credential-read failures
while preserving the underlying OS errors. The portable discovery tests use
private fixture directories, restore the working directory through test
cleanup, and compare filesystem identity rather than path spelling.
Tests confirm that a valid `GITHUB_WORKSPACE` wins over a local fixture,
an invalid override falls back, and credential reads preserve spaces while
trimming trailing line endings.

Both module suites and changed-line lint gates passed, along with ten
shuffled AD package race runs, build and vet checks, and Linux/386 tests.
The AD test binaries cross-compiled for Windows amd64 and macOS arm64 but
were not run on those platforms. V8 cross-package statement coverage
remained 87.1%. Live AD interoperability was not run; Docker access was
unavailable.

All six AD canonical findings were resolved without suppressions, including
the permissions and shadowing diagnostics from the rebased tests. Canonical
v8 findings fell from 663 to 657 (`wrapcheck`: 90 to 88), and supplemental
findings fell from 3,688 to 3,685. Neither profile introduced findings, and
v8 returned to zero gosec findings.

Slice 56 (2026-11-19, RFC crypto error contracts; Q-03):
The RFC 3961, 3962, and 8009 helpers preserve causes from key derivation,
AES-CTS operations, and integrity hashing. Invalid hex string-to-key
parameters retain the decoder's typed error. RFC 4757 hashes the same bytes
directly instead of copying them through a reader; hash writes cannot fail.
Wire outputs, integrity checks, and nil, empty, or partial results on
failure remain unchanged.

Regression tests cover injected initial and feedback block failures, key
derivation and decryption causes, and malformed string-to-key parameters.
Both module suites, the RFC vectors, focused race/build/vet checks, and
Linux/386 crypto tests passed. V8 cross-package statement coverage remained
87.1%. The 60-second GSSAPI unwrap and MIC fuzz runs passed 27,555 and
1,447,769 executions, respectively. Live interoperability was not run;
Docker daemon access was denied.

All 17 remaining crypto `wrapcheck` reports and one `staticcheck` report
were resolved without suppressions. Both changed-line lint gates passed.
Canonical v8 findings fell from 681 to 663 (`wrapcheck`: 107 to 90);
the supplemental total remained 3,688, with no new findings in either
profile. The baseline includes two gosec reports and one shadowing report
from the rebased AD discovery tests; those files were not changed.

Slice 55 (2026-11-18, encryption profile error contracts; Q-03):
The top-level v8 crypto package adds operation and profile context to
key derivation, encryption, decryption, checksum, and FAST PRF failures.
It preserves the original causes and the profiles' existing return values,
including empty versus nil slices. PA-ETYPE-INFO2 salt detection retains
ASN.1 decode errors and still rejects mismatched entry counts. Error context
does not include key, password, salt, or plaintext bytes. Cryptographic
primitives, wire formats, and enctype policy are unchanged.

Regression tests cover bad key sizes and short ciphertexts across all six
profiles, string-to-key parameter errors, partial derivation results, and
typed ASN.1 failures. Both module suites, focused race/build/vet checks,
Linux/386 crypto tests, and both changed-line lint gates passed. V8
cross-package statement coverage remained 87.1%. The 60-second GSSAPI
unwrap rerun and MIC verification fuzz run passed 692,809 and 1,499,899
executions, respectively. Live interoperability was not run; Docker daemon
access was denied.

All 48 top-level crypto `wrapcheck` reports were resolved. Canonical v8
findings fell from 726 to 678 (`wrapcheck`: 155 to 107); the supplemental
total remained 3,685. Neither profile introduced findings, and v8
continued to report zero gosec findings. RFC subpackage findings are
outside this slice.

Slice 54 (2026-11-18, Kerberos message error contracts; Q-03):
AS and TGS request builders retain random-source failures with nonce
context. Ticket, KRB-PRIV, and S4U operations identify encoding, decoding,
encryption, and checksum failures without discarding their causes. Ticket
PAC errors distinguish buffer processing from verification with caller
options. The concrete no-key KRB-ERROR, validation order, and wire encodings
are unchanged.

Regression tests cover injected nonce failures, typed ASN.1 errors,
KRB-PRIV encryption failures, and PAC processing and client binding
failures. The message fuzz target sorts its decoder names so cached
inputs select the same decoder across runs. Its 60-second run passed
1,682,383 executions. Both module suites and changed-line lint gates
passed, along with focused race, build, and vet checks and Linux/386
message tests. V8 cross-package statement coverage reached 87.1%.
Live interoperability was not run; Docker daemon access was denied.

All 45 messages `wrapcheck` reports were resolved: 15 propagated errors
now wrap their causes, and 30 original `krberror.NewErrorf` constructions
have no cause to wrap. The exception matches only that constructor's
diagnostic in `v8/messages`. Canonical v8 findings fell from 772 to 726
(`wrapcheck`: 200 to 155); the supplemental total fell from 3,686 to 3,685.
Neither inventory introduced findings, and v8 gosec remained at zero.

Slice 53 (2026-11-18, Kerberos type error contracts; Q-03):
The v8 types package now identifies the failed ASN.1 operation while
preserving syntax and structural causes. Legacy decoders still accept a
valid ASN.1 prefix, while MS-KILE, FAST, and KKDCP keep their existing
trailing-data checks. The enctype-info accessors reuse their sequence
decoders without changing type checks or preauthentication preference.
Random sequence generation and network interface enumeration retain their
underlying errors. Wire encodings, key generation, and address selection
are unchanged.

Regression tests cover typed decode and encode errors, permissive and strict
trailing-data behavior, and entropy read failures that leave authenticator
state unchanged. Both module suites and changed-line lint gates passed, as
did focused race, build, and vet checks and Linux/386 tests for types and
ASN.1 helpers. Cross-package v8 statement coverage remained 87.0%.
`FuzzKDCProxyMessage`, `FuzzMSKILEUnmarshal`, and `FuzzFASTUnmarshal` passed
60-second runs with 1,526,999, 987,573, and 1,127,204 executions, respectively.
Live interoperability was not run; Docker daemon access was denied.

The canonical v8 total fell from 806 to 772 (`wrapcheck`: 234 to 200),
clearing all 34 `wrapcheck` reports in types. The supplemental v8 total
fell from 3,688 to 3,686. Neither inventory had new findings, and v8
continued to report zero gosec findings.

Slice 52 (2026-11-18, NDR signed primitive reads; Q-03):
The four signed integer readers share a fixed-width decoder that uses the
NDR byte order directly on the bounded read. Alignment and truncation
handling are unchanged. Tests cover each minimum signed value in both byte
orders and require truncated records to retain the `Malformed`
classification and the underlying `io.EOF` or `io.ErrUnexpectedEOF`.
The NDR test fixture checks the aligned length against both the wire and
platform limits before narrowing, restoring the internal NDR suite on
Linux/386 without changing the fixture bytes.

Both module suites and changed-line lint gates passed. PAC and internal NDR
tests also ran successfully on Linux/386. Focused race, build, and vet checks
passed for PAC, internal NDR, messages, service, and SPNEGO. Cross-package
v8 statement coverage was 87.0%. The 60-second `FuzzDecodeArrays` run passed
with 2,003,023 executions. The first downstream `FuzzPACProcessingInfoBuffers`
run hit a deadline without reporting a failing input; the unchanged baseline
passed and the edited decoder passed a 60-second rerun (531,600 executions).
Live interoperability was not run; Docker daemon access was denied.

The canonical v8 total fell from 810 to 806 (`wrapcheck`: 238 to 234).
All four internal NDR `wrapcheck` reports were resolved, with no new
canonical findings and zero v8 gosec findings. The supplemental v8 total
remained 3,688.

Slice 51 (2026-11-18, PAC error contracts; Q-03):
PAC headers and buffer tables use checked little-endian decoding. Credential
and signature reads retain `io.EOF` or `io.ErrUnexpectedEOF` with the failed
field identified. Credential parsing reads the entire opaque payload instead
of rejecting a large payload after a short buffered read. Decryption, decoded
credential parsing, and checksum failures identify their stage without
including credential or checksum bytes. Valid wire encodings, signature
inputs, and checksum validation order are unchanged.

Both module suites and changed-line lint gates passed. PAC, internal NDR,
messages, service, and SPNEGO passed focused race, build, and vet checks.
`FuzzPACUnmarshal` and `FuzzPACProcessingInfoBuffers` passed 60-second runs
(1,840,410 and 581,642 executions). Cross-package v8 statement coverage was
87.0%. The PAC suite passed on Linux/386, and internal NDR built on that
target; the unchanged NDR test suite did not compile on 386 because a test
compares an `int` to `math.MaxUint32`. Live interoperability was not run;
Docker daemon access was denied.

The canonical v8 total fell from 831 to 810 (`wrapcheck`: 259 to 238).
All 21 `wrapcheck` reports in the PAC package were resolved. The independent
internal NDR package was not changed. There were no new canonical findings
and zero v8 gosec findings.

Slice 50 (2026-11-18, service authentication error contracts; Q-03):
Service AP-REQ verification preserves concrete KRB-ERROR values and their
wire codes while adding context to other verification failures. Nil requests
return an error, and failed verification does not publish authenticated
credentials. AP-REQ and Kerberos Basic authentication share PAC processing:
malformed authorization data is an error, not an absent PAC. The existing
AP-REQ PAC opt-out and verification order are unchanged. Invalid Basic
authentication values retain the base64 cause without exposing the input.

Regression tests cover concrete protocol errors and wire encoding, missing
requests, verification causes, failed delegation, malformed PAC and
authorization data, and typed base64 errors. Both module suites and
changed-line lint gates passed, along with focused race, build, and vet
checks for service, SPNEGO, and PAC. `FuzzPACUnmarshal` passed a 60-second run
(1,696,754 executions). Cross-package v8 statement coverage was 86.9%.
An unchanged PKINIT wrong-password test failed once on the expected error
text, then passed ten isolated repetitions and the full rerun. Live
interoperability was not run; Docker daemon access was denied.

The canonical v8 total fell from 838 to 831 (`wrapcheck`: 265 to 259).
All six service `wrapcheck` reports and one complexity report were resolved,
with no new canonical findings and zero v8 gosec findings.

Slice 49 (2026-11-18, PKU2U error contracts; Q-03):
PKU2U now identifies the failed operation while preserving causes from AS and
AP message processing, key and context setup, certificate name mapping, and
metadata encoding. An acceptor without a local identity returns a
configuration error instead of panicking. Malformed PA-PAC-REQUEST data
retains its decode error; the requirement to suppress PAC issuance is
unchanged. Valid wire encodings, certificate trust rules, and handshake
ordering are unchanged.

Regression tests cover typed ASN.1 and certificate trust errors, ticket and
authenticator decryption failures, and retrying the handshake after malformed
AS and AP messages. Both module suites and changed-line lint gates passed.
PKU2U, PKINIT, NEGOEX, and SPNEGO passed focused race, build, and vet checks.
`FuzzTrustedCertifiersUnmarshal` passed a 60-second run (782,791 executions)
with re-encoding checks. Cross-package v8 statement coverage was 86.8%,
above the 86.0% floor. Live interoperability was not run; Docker daemon
access was denied.

The canonical v8 total fell from 874 to 838 (`wrapcheck`: 300 to 265).
All 35 PKU2U `wrapcheck` reports and the AS acceptor complexity report were
resolved, with no new canonical findings and zero v8 gosec findings.

Slice 48 (2026-11-18, NEGOEX error contracts; Q-03):
NEGOEX now identifies failures in negotiation random generation, mechanism
initialization and continuation, message encoding, and VERIFY checksum
computation without losing the underlying errors. The PKU2U adapter also
preserves causes and any values returned alongside an error. Peer-directed
error tokens, optimistic fallback, metadata pruning, sequence numbering, and
successful wire encodings are unchanged.

Regression tests cover terminal and recoverable mechanism failures, PKU2U
adapter results, message encoding errors, and checksum error classification.
Both module suites and changed-line lint gates passed, along with focused
race, build, and vet checks for NEGOEX, PKU2U, and SPNEGO.
`FuzzNegoExUnmarshal` passed a 60-second run (2,616,519 executions).
Cross-package v8 statement coverage was 86.8%, above the 86.0% floor.
Live interoperability was not run; Docker daemon access was denied.

The canonical v8 total fell from 888 to 874 (`wrapcheck`: 313 to 300).
All 13 NEGOEX `wrapcheck` reports were resolved, as was the remaining
`unparam` report: the new conversation tests use distinct target names.
There were no new canonical findings and zero v8 gosec findings.

Slice 47 (2026-11-18, GSSAPI token error contracts; Q-03):
MIC and wrap token operations now identify the failed enctype lookup,
checksum, encryption, or decryption operation while preserving its cause.
Integrity-only unwrap distinguishes a checksum computation failure from a
mismatch. Mismatch errors no longer include computed or received checksum
bytes. Token bytes, enctype policy, validation order, and sequence handling
are unchanged. Regression tests verify that failures do not advance the
sequence counters and that the same token can be retried after correcting a
local key error.

Both module suites and changed-line lint gates passed. GSSAPI, SPNEGO, PKU2U,
NEGOEX, and service packages passed race, build, and vet checks.
`FuzzSecurityContextUnwrap` and `FuzzSecurityContextVerifyMIC` each passed
60-second runs (740,831 and 1,496,727 executions). The unwrap seeds now reach
both integrity and confidentiality validation. Cross-package v8 statement
coverage was 86.7%, above the 86.0% floor. Live interoperability was not run;
Docker daemon access was denied.

The canonical v8 total fell from 901 to 888 (`wrapcheck`: 324 to 313).
All 11 GSSAPI `wrapcheck` reports and two test-helper `unparam` reports were
resolved, with no new canonical findings and zero v8 gosec findings.

Slice 46 (2026-11-18, password-change error contracts; Q-03):
The v8 password-change library now identifies the failed encoding, decoding,
request construction, or decryption operation while retaining the cause.
A decoded server KRB-ERROR is still returned as a typed error. Reply decoding
replaces the receiver only after successful parsing, so reusing a reply cannot
carry over an earlier error or password policy. Request construction rejects a
ticket with no service principal instead of panicking. Wire framing, valid
request payloads, and result and password-policy interpretation are unchanged.

Regression tests cover typed decode failures, protected and error reply reuse,
AP-REQ construction failures, and password omission from diagnostics.
Both module test suites and both changed-line lint gates passed, along with
focused build, vet, and race checks for `kadmin`, `client`, and `gokinit`.
`FuzzReplyUnmarshal` passed a 60-second run (1,300,081 executions), and v8
cross-package statement coverage was 86.7%, above the 86.0% floor. An unchanged
PKINIT clock-skew test missed its wall-clock tolerance during concurrent
validation, then passed ten isolated repetitions and the full rerun. Live
password-change interoperability was not run; Docker access was unavailable.

The canonical v8 total fell from 908 to 901 (`wrapcheck`: 330 to 324).
All six `kadmin` `wrapcheck` reports and its one nesting report were resolved.
There are no remaining canonical findings in `kadmin`, no new canonical
findings in v8, and zero v8 gosec findings.

Slice 45 (2026-11-18, PKINIT error contracts; Q-03):
PKINIT DER encoders and decoders, CMS envelope operations, and signer
public-key encoding now identify the failed operation and preserve the
underlying cause. A malformed CMS IV retains its decode error; a well-formed
IV of the wrong size is still rejected separately. An unencodable signer
key no longer looks like a certificate mismatch. Successful wire encodings,
cipher selection, and certificate selection and trust rules are unchanged.

Regression tests pin the request and both reply encodings and verify error
causes for invalid DER, invalid IVs, and unsupported signer keys. Both module
test suites and changed-line lint gates passed. The v8 PKINIT, client, PKU2U,
and `gokinit` packages passed build, vet, and race tests. `FuzzPKASRep` passed a
60-second run (751,076 executions), and v8 cross-package statement coverage
was 86.7%, above the 86.0% floor. Live KDC interoperability was not run;
Docker daemon access was denied.

The canonical v8 total fell from 927 to 908 (`wrapcheck`: 347 to 330).
All 17 PKINIT `wrapcheck` findings were resolved, with no new canonical
findings and zero gosec findings.

Slice 44 (2026-11-18, v8 command error contracts):
`gokinit`, `goklist`, and `gokdestroy` preserve flag parsing errors while
retaining help and usage exit codes and quiet and silent behavior. Shared
principal and hostname lookup, and `gokinit` keytab loading, ticket address
discovery, PKINIT identity loading, and password changes identify the failed
operation without adding password or PIN values to diagnostics. PKCS#12
loading still tries the empty password before prompting.

Password input retains its underlying I/O errors, requires explicit stdin
opt-in, and keeps terminal echo disabled. Terminal restoration and close
errors follow the primary failure, including when both Windows console
handles fail to close. Regression tests cover missing keytabs, PKINIT
decode and PIN read errors, stdin I/O failures, unterminated buffered input,
and an isolated Linux process with no controlling terminal.

Both module test suites and both changed-line lint gates passed, as did the
v8 command race tests. Cross-package statement coverage is 86.6%, above
the 86.0% floor. All four Windows/amd64 command and helper test binaries
cross-compiled but were not run on Windows. The canonical v8 total fell
from 954 to 927, including `wrapcheck` falling from 370 to 347. All 23
command `wrapcheck` findings were resolved, with zero new canonical
findings and zero gosec findings.

Slice 43 (2026-11-18, credentials and configuration serialization errors):
credential gob encoding and decoding, credential JSON encoding, and
configuration JSON encoding now identify the failed operation while preserving
the underlying error. Failed gob decoding still leaves the receiver unchanged.
Successful output and sensitive-field exclusions are unchanged; the credential
godoc distinguishes what the two formats include and limits gob decoding to
trusted payloads.

Regression tests cover gob attribute round trips and encode failures, EOF on
decode, JSON exclusions, and typed JSON errors for an unrepresentable
credential timestamp and an invalid configuration IP address. The v8 unit
suite and the focused configuration, credentials, and SPNEGO race suites
passed. Cross-package statement coverage remains 86.6%, above the 86.0% floor.
Both changed-line lint gates passed. Neither package has remaining `wrapcheck`
findings; canonical v8 totals fell from 958 to 954 (`wrapcheck`: 374 to 370),
with zero gosec findings.

Slice 42 (2026-11-18, keytab codec and remaining keytab error contracts):
fixed-width fields now use byte-order operations directly, and decoded key
bytes still belong to the keytab rather than the input buffer. Signed wire
fields retain their two's-complement interpretation, including negative
timestamps and deleted-record lengths. Version 1 byte-order probing and the
optional 32-bit KVNO trailer retain their existing behavior. Key derivation,
enctype validation, and JSON errors now identify the failed operation while
preserving their causes. Successful binary and JSON output is unchanged.

The canonical v8 total fell from 969 to 958 and `wrapcheck` from 385 to 374;
the keytab package now has no `wrapcheck` findings and v8 still has zero
gosec findings. Both module suites, the v8 race suite, both changed-line
lint gates, and all four MIT keytab interoperability tests passed. The
keytab decoder passed a 60-second fuzz run (1.47 million executions).
Cross-package statement coverage is 86.6% against the 86.0% floor. Keytab
tests ran on Linux/386 and cross-compiled for Linux/s390x; the big-endian
binary and live KDC exchanges were not run.

Slice 41 (2026-11-18, credential-file and keytab stream error contracts):
v8 keytab and FILE credential-cache loads identify the failed read operation
without losing filesystem causes. Keytab append errors identify the failed
open, lock, inspection, write, or sync operation; unlock and close errors
still follow the primary failure. Keytab stream writes preserve the reported
byte count and any writer error, and return `io.ErrShortWrite` through the
error chain when a writer reports a short count without an error. Callers
should inspect wrapped errors with `errors.Is` and `errors.As`.

The shared atomic writer now owns the directory-sync policy for both file
types, with the same platform build constraints. Open, sync, and close
failures retain their causes; a post-rename sync failure still does not
remove the replacement. File formats, successful I/O behavior, and locking
policy are unchanged. Binary codec internals, key derivation, and JSON/gob
serialization are outside this I/O slice.

The scoped I/O boundaries have no remaining `wrapcheck` findings. Without
changing lint configuration, the canonical v8 total fell from 983 to 969
and `wrapcheck` from 399 to 385; gosec remains at zero. Both module suites,
the v8 race suite, both changed-line lint gates, and all four MIT keytab
interoperability tests passed. Cross-package statement coverage is 86.5%
against the 86.0% floor. The affected test packages cross-compiled for
Windows/amd64, Solaris/amd64, and macOS/arm64; those binaries and live KDC
exchanges were not run.

Slice 40 (2026-11-18, retire deprecated client enctype defaults): v8 now
defaults to the same two RFC 3962 AES enctypes, in their original order, for
AS requests, TGS requests, and the configured permitted list. RC4 and
Triple-DES require both `allow_weak_crypto = true` and explicit names in
the relevant lists. Configuration resolves names before filtering by enctype
ID, so RC4 aliases cannot bypass the policy. Unsupported names remain
unsupported, and a filtered list does not fall back to a weaker enctype.
Directly supplied IDs, low-level primitives, acceptor behavior, and PKINIT
CMS algorithms are unchanged. The v8 README documents migration and opt-in.

Config regressions failed against the old defaults and now pass; DER
round-trip tests verify the AS and TGS offers for default, filtered, and
opted-in configurations. Both module suites, the v8 race suite, and four
MIT command-line keytab interoperability tests pass. Live KDC exchanges
were not run locally. CI-style coverage remains 86.5%; changed-line lint
passes for both modules and the canonical v8 counts remain 983 total,
zero gosec.

Slice 39 (2026-11-18, cryptography compatibility review): all 30 remaining
v8 gosec reports have a rule-specific disposition at the flagged import or
call. The exceptions retain RFC 3962 AES/HMAC-SHA1 enctypes, RFC 3961 Triple-DES
and its zero initial cipher state, RFC 4757 RC4-HMAC, the historical
`RC4HMAC.RandomToKey` result, RFC 4121 channel-binding MD5, and the RFC
4556/8636 PKINIT digest, KDF, and CMS compatibility paths. Independent test
oracles keep their specified hashes. This is classification, not a claim that
the primitives are safe: no algorithm, API, or negotiation policy changed.
The [v8 README](../../v8/README.md) records the current RC4 default exposure
and how to omit it from the configured enctype lists at the time of this
slice. Slice 40 separately retires the deprecated negotiation defaults;
that policy is not implemented by the analyzer exceptions.

The canonical v8 scan drops from 1,013 to 983 findings, with zero gosec
findings and no additions. Focused protocol tests, both module unit suites,
the v8 race suite, and both changed-line lint gates pass. CI-style atomic
coverage is 86.5% on a serial rerun after an existing client clock-skew test
exceeded its one-second tolerance during the concurrent run.

Slice 38 (2026-11-18, native byte order and credential false positives):
ccache v1/v2 and keytab v1 now use `binary.NativeEndian` instead of unsafe
pointer probes. The fixed big-endian formats and keytab v1's opposite-endian
fallback are unchanged. A regression pins native-order precedence when both
record lengths are plausible, complementing the existing both-invalid case
and byte-exact fixtures for each order. The KVNO overflow test now compiles on
32-bit hosts and skips only where the input cannot fit in `int`. Six G101
reports are classified at their individual declarations: three lookup keys,
one public SPNEGO rejection header, and two test-realm wire vectors. No
literal values changed. G101 and G103 are both zero; gosec falls from 38 to
30 and canonical findings from 1,021 to 1,013, with no added diagnostics.
Both module test suites, the v8 race suite, the Linux/386 keytab and ccache
tests, and both changed-line lint gates pass. Big-endian Linux/s390x test
binaries cross-compile; they were not run locally. CI-style cross-package
atomic coverage is 86.5%. The remaining 30 gosec findings concern
cryptographic primitives and remain open for a separate compatibility review.

Slice 37 (2026-11-18, explicit path and subprocess classification): filesystem
and subprocess diagnostics G304/G703/G204/G702 are zero. Configuration,
credential-cache, keytab, PKINIT identity, and test-fixture operations now mark
the exact calls where the path is an explicit API, CLI configuration, or
isolated-test input rather than request-derived traversal. AD fixture discovery
remains limited to an explicitly supplied CI workspace or ancestors of the
test working directory; the PTY helper executes the current test binary with a
fixed test selector. Each classification is line-scoped and records the trust
boundary instead of excluding a package or broad file. G304 falls 10 to 0,
G703 falls 11 to 0, G204/G702 fall 1 each to 0, gosec falls 61 to 38, and
canonical findings fall 1,044 to 1,021. Focused affected-package tests, the
full v8 suite, the full v8 race suite, both-module tests, the changed-line lint
gate for both modules, and `git diff --check` pass; the full `./...` coverage
profile measures 85.9% statements.

Slice 36 (2026-11-18, HTTP trust-boundary hardening): HTTP G704/G705/G120
findings are zero. The SPNEGO negotiating client documents and suppresses its
deliberate caller-selected outbound destination at the single transport
boundary, while integration tests mark their explicitly configured endpoints.
The test upload handler bounds the request body before multipart parsing, and
identity values rendered in HTTP test responses are HTML-escaped. No production
response rendering or server routing semantics change. G704 falls 8 to 0,
G705/G120 fall 3 to 0, gosec falls 72 to 61, and canonical findings fall 1,056
to 1,044; coverage remains 86.5%.

Slice 35 (2026-11-18, security hygiene): crypto-backed KDC ordering and
safe fixture permissions. KDC service ordering now uses unbiased `crypto/rand`
shuffle choices and falls back to the original ordering if the secure source
fails, without mutating config slices. RSA private-key format coverage uses
2048 bits, and temporary keytab/workspace fixtures use 0600/0700 permissions.
The random-order helper handles nil/empty slices without introducing NilAway
flows. G404/G403/G306/G301 fall from 5 to 0, gosec falls 77 to 72, and
canonical findings fall 1,062 to 1,056; coverage remains 86.5%.

Slice 34 (2026-11-18, SPNEGO exchange cookie attributes): cookie G124
findings are zero. SPNEGO exchange creation and expiration now share one
cookie constructor, consistently setting `Path=/`, `HttpOnly`, and
`SameSite=Strict`, with `Secure` tied to the actual TLS state of the request.
The dynamic transport-aware `Secure` choice is documented with a scoped G124
exception because forcing it on plaintext HTTP would prevent negotiation.
The TLS continuation test now exercises a real TLS server, and a direct
attribute test covers both HTTPS and HTTP cookies. G124 falls 3 to 0, gosec
falls 80 to 77, and canonical findings fall 1,066 to 1,062; coverage remains
86.5%.

Slice 33 (2026-11-18, bounded slice traversal): all v8 G602 findings are
zero. Multidimensional NDR allocation snapshots the next dimension only after
an explicit nonempty check, and PKINIT SID formatting walks fixed four-byte
fields with an explicit remaining-length condition. The SID's declared
subauthority count is converted to an expected total length before indexing.
The existing malformed-SID regression and a zero-dimension NDR helper
regression cover the new guards. G602 falls 5 to 0, gosec falls 85 to 80, and
canonical findings fall 1,071 to 1,066; coverage remains 86.5%.

Slice 32 (2026-11-18, final protocol wire ranges): all v8 G115 findings are
zero. Kadmin message/AP_REQ lengths and KKDCP payload framing use checked
uint16/uint32 encoders; PKINIT padding and KDF counters are bounded before
byte/uint32 encoding; PKU2U sequence numbers are validated at signed/unsigned
boundaries and converted through extracted reply/context helpers; the service
SID fixture documents its small fixed test bound. Malformed KDF lengths return
errors. Kadmin/PKINIT/PKU2U/types/service G115 falls 13 to 0, total G115 falls
13 to 0, gosec falls 98 to 85, and canonical findings fall 1,084 to 1,071;
coverage measures 86.5%.

Slice 31 (2026-11-18, ASN.1 and crypto wire ranges): ASN.1 tools and crypto
G115 findings are zero. ASN.1 length octets and n-fold bit values use proven
0..255 bounds, PKCS7 padding rejects block sizes above the byte representation,
RFC 8009 rejects invalid key-bit lengths before uint32 encoding, and crypto test
iterations use checked conversions. Oversized RFC 8009 derivation requests now
return an empty byte slice instead of truncating the key length or propagating a nil value. ASN.1/crypto G115 falls 7 to 0,
total G115 falls 20 to 13, gosec falls 105 to 98, and canonical findings fall
1,091 to 1,084; coverage remains 86.6%.

Slice 30 (2026-11-18, GSS token wire ranges): GSSAPI G115 findings are zero.
Authenticator extension, channel-binding, delegation, checksum, rotation,
and wrap-token lengths use checked uint16/uint32 helpers. Context flags are
accepted only within the uint32 protocol range. Invalid oversized lengths now
return errors where public marshal APIs permit it; channel-binding hash
construction fails closed to an empty digest if an input somehow exceeds the
wire length. Regressions preserve existing byte-exact token vectors. GSSAPI
G115 falls 8 to 0, total G115 falls 28 to 20, gosec falls 112 to 104, and
canonical findings fall 1,098 to 1,091; coverage remains 86.6%.

Slice 29 (2026-11-18, message and client wire ranges): messages/client G115
findings are zero. Authenticator key usages use uint32 protocol constants
directly; S4U and FAST nonce values are checked before protocol conversion;
and KDC TCP/KKDCP lengths use checked 32/16-bit encoders. S4U checksum name
types are serialized directly as signed little-endian values, avoiding a cast
while preserving the wire form. Test fixtures use shared checked nonce helpers
or explicitly proven byte-bounded values. Messages/client G115 falls 20 to 0,
total G115 falls 48 to 28, gosec falls 132 to 112, and canonical findings fall
1,118 to 1,098; coverage remains 86.6%.

Slice 28 (2026-11-18, SPNEGO sequence ranges): SPNEGO G115 findings are
zero. Sequence numbers remain signed while parsed from Kerberos messages and
are converted only when constructing the GSS security context or mechListMIC.
A centralized 30-bit validation helper rejects negative and out-of-range peer
values; locally generated acceptor sequences retain an audited nonnegative
30-bit conversion. Boundary regressions cover the full accepted endpoints and
both rejected sides. SPNEGO G115 falls 12 to 0, total G115 falls 60 to 48,
gosec falls 144 to 132, and canonical findings fall 1,131 to 1,118; coverage
remains 86.6%.

Slice 27 (2026-11-18, NEGOEX wire ranges): NEGOEX G115 findings are zero.
Message and vector lengths now use checked uint32/uint16 and platform-int
helpers before allocation or encoding; malformed descriptor offsets remain
bounded by message size. Checksum types are checked against signed int32 and
nonnegative hash identifiers before protocol conversion. Marshal helpers
return size errors consistently, including ALERT and extension vectors, and
fixtures use checked conversion helpers. NEGOEX G115 falls 13 to 0, total G115
falls 73 to 60, gosec falls 157 to 144, and canonical findings fall 1,143 to
1,130; coverage measures 86.6%.

Slice 26 (2026-11-18, PAC/NDR wire ranges): PAC G115 findings are zero.
PAC buffer offsets, allocation sizes, signature ranges, checksum identifiers,
UPN/DNS lengths, and client-name lengths now use checked platform or wire-width
conversions. NDR pipe and multidimensional counts are bounded by input size
and converted to platform `int` through explicit helpers; decoder-size and
reflect-length conversions are documented at their proven nonnegative bounds.
Malformed ranges return errors rather than truncating offsets. Checked helpers
replace fixture-only casts, preserving byte-exact PAC vectors and existing
error contracts. PAC G115 falls 51 to 0, total G115 falls 124 to 73, gosec
falls 208 to 157, and canonical findings fall 1,196 to 1,143; coverage measures 86.8%.

Slice 25 (2026-11-18, credential-cache wire ranges): credentials G115
findings are zero. Cache unmarshalling now decodes signed fields directly and
marshalling uses checked int32/uint16 helpers for header, principal, key,
timestamp, address, authorization-data, and payload lengths. Invalid values
return errors; KDC offset seconds saturate at the signed 32-bit wire boundary
while preserving the representable microsecond remainder. A regression covers
both positive and negative duration extremes. The cache version marker is
compared as a byte, and test fixtures use checked wire encodings with a single
range-justified annotation. Credentials G115 falls 18 to 0, total G115 falls
142 to 124, gosec falls 226 to 208 (with credential path/file diagnostics retained as
intentional caller-selected cache access), and canonical findings fall 1,216
to 1,196; coverage measures 86.9%.

Slice 24 (2026-11-18, keytab wire-range classification): keytab G115 findings
are zero. Marshal paths now validate every narrowed signed timestamp, component count,
string/key length, record length, enctype, and principal-name field before
encoding; invalid values produce errors instead of wrapping. Signed keytab
fields are decoded directly as signed values with `binary.Read`, preserving
all valid v1/v2 on-wire representations without unsafe reinterpretation.
KVNO lookup rejects values outside the uint32 wire range, while the intended
low-byte KVNO field is encoded through its four-byte representation. Boundary
regressions cover signed timestamp boundaries, out-of-range enctypes,
key/string lengths, name types, and lookup KVNOs; decoding rejects negative
protocol identifiers and a 60-second fuzz run remains round-trip clean. All
existing byte-exact fixtures remain
unchanged. Keytab G115 falls 18 to 0, total G115 falls 160 to 142, gosec falls
244 to 226, and canonical findings fall 1,231 to 1,216. Aggregate coverage
measures 87.0%. The remaining keytab
gosec findings are intentional user-selected file access and the documented
native-byte-order probe, not unchecked wire narrowing.

Slice 23 (2026-11-18, PAC and PKU2U nil invariants): all v8 NilAway
findings are zero. NDR dimension parsing handles invalid and nil reflect values
without method dispatch on missing types, fixed-array decoding checks for an
unknown element type, and UTF-16 conversion explicitly handles a nil slice.
Tests now construct nonnil NDR bodies, check dimension and checksum helper
results before method calls, and validate GSS contexts before wrap/unwrap.
These final call-site and helper checks cover the remaining analyzer paths
without changing valid PAC or PKU2U behavior. PAC/PKU2U NilAway falls 9 to 0,
total NilAway falls 9 to 0, and canonical findings fall 1,241 to 1,231;
aggregate coverage remains 86.9%.

Slice 22 (2026-11-18, protocol type nil invariants): types NilAway is zero.
`PADataSequence.Contains` returns false for a nil receiver, PA-FX-ERROR
unmarshal rejects a nil destination, and host-address conversion always
returns an allocated sequence including the established zero entry for an
invalid IP. Regressions cover nil sequence lookup, nil PA-FX-ERROR decode,
and empty IP conversion. These changes establish useful zero-input behavior
without changing valid decoding or PA-DATA membership semantics. Types
NilAway falls 9 to 0, total NilAway falls 18 to 9, and canonical findings fall
1,250 to 1,241; aggregate coverage remains 86.9%.

Slice 21 (2026-11-18, command configuration nil invariants): command NilAway
is zero. `LoadConfig` rejects a nil configuration returned without an error,
and `gokinit`'s PKINIT and AS request-option helpers reject nil configuration
inputs before dereferencing defaults. A direct regression exercises both
helpers, while the shared config loader test now verifies a successful load
never returns a nil configuration. This closes the config-to-command flow
that NilAway could not prove from the loader's error return alone. Command
NilAway falls 9 to 0, total NilAway falls 27 to 18, and canonical findings
fall 1,256 to 1,250; aggregate coverage remains 86.9%.

Slice 20 (2026-11-18, crypto nil and derivation invariants): crypto NilAway
is zero. Password-derived-key selection now explicitly rejects an unavailable
encryption implementation before method dispatch. N-fold rejects empty input
and non-byte-aligned or nonpositive output widths instead of dividing or
indexing invalid slices; RFC 3961 derivation callers convert those rejected
inputs into descriptive errors before passing data to cipher implementations.
AES-SHA2 vector tests check decryption failures and output length before
removing the confounder, and key-derivation tests check selected enctype
results before use. Regressions cover empty and malformed n-fold requests and
empty RFC 3961 derivation inputs. Crypto NilAway falls 17 to 0, total NilAway
falls 44 to 27, and canonical findings fall 1,273 to 1,256. Aggregate coverage
remains 86.9%, above the 86.0% floor.

Slice 19 (2026-11-18, NEGOEX nil invariants): NEGOEX NilAway is zero.
Conversation accessors return their zero values for a nil receiver, while
`Step` reports the new `ErrInvalidConversationState` error before reading
state. Tests cover the nil receiver contract, check constructor failures
before dereferencing conversations, and verify that decoded messages and
protocol tokens have the lengths they are about to consume. Full NilAway
falls from 65 to 44 and full canonical diagnostics fall from 1,293 to 1,273;
aggregate coverage measures 87.0%. The next remaining concentrations are `crypto`,
`cmd`, `types`, and PAC NDR rather than NEGOEX.

Slice 18 (2026-11-18, SPNEGO nil invariants): production and test SPNEGO
NilAway is zero. `cloneNegotiationRequest`, `setRequestSPN`, header-setting,
and response-token parsing reject nil request/URL/response inputs. Acceptor
state validation rejects typed-nil SPNEGO/KRB5 tokens and a verified but
missing Kerberos mechanism token. HTTP and protocol tests now use checked
request/config fixture helpers and guard expected-error values before method
calls. A new regression covers nil request, nil URL, nil header input, and
nil response cases. SPNEGO NilAway falls 39 to 0; full NilAway falls 107 to 65,
and canonical findings fall 1,335 to 1,293. Full and focused race suites pass;
coverage remains 86.9%.

Slice 17 (2026-11-18, client nil invariants): client NilAway is zero. Session
store `get` now considers a nil map entry a miss; destroy skips nil entries,
update ignores nil stores/sessions and replaces a nil prior value, and JSON
omits nil sessions. Session accessors/destroy/valid/update return useful zero
or no-op behavior for nil receivers. CCache export rejects a nil session entry
instead of locking/dereferencing it and validates the session/client passed
to `sessionCredential`. FAST entry points reject nil state and, where
required, nil client/request/reply; the tests cover each public operation.
KKDCP URL validation also requires a non-nil parsed URL. Client tests now use
checked config and FAST/enctype/OS-user constructors before dereferencing
their results. Coverage remains 86.9%; client NilAway falls to zero, total
NilAway falls from 215 to 107, and the canonical total falls from 1,441 to
1,335.

Slice 16 (2026-11-18, config nil invariants): config NilAway is zero. The
section line buffer is initialized, duration colon fields are parsed into a
length-checked allocated array, and empty server-order input returns the empty
result before indexing. These are zero-value/analysis-proof invariants; valid
config parsing and random ordering are unchanged. Tests now make the
partial-config contract explicit: fatal load errors cannot be followed by
access, while the intentional UnsupportedDirective path proves the returned
config is non-nil before field and realm assertions. Config NilAway falls 60
to 0; full NilAway falls 275 to 215 and canonical findings from 1,501 to 1,441.
Full v8 and config/client/credentials/keytab race suites pass; coverage remains
87.0%.

Slice 15 (2026-11-18, credentials/PKINIT/PKU2U nil invariants): the three
remaining small NilAway package slices are clean. `CCache` accessors now
provide useful zero values on a nil receiver, skip nil credential entries,
and preserve all non-nil behavior; privileged integration tests use fatal
constructor checks and `user.Current` errors are propagated. PKINIT
`Exchange.ProcessReply` rejects a nil receiver before any reply-field access;
PKU2U `TrustedCertifiers.Unmarshal` rejects a nil destination. Regressions
cover nil CCache access/lookup/enumeration, nil PKINIT exchange with a validly
encoded DH reply, and nil trusted-certifier decode destination. Target-package
NilAway findings fall to zero, the full NilAway total falls from 286 to 275,
and the canonical total falls from 1,511 to 1,501. Target and client race
suites pass; full v8 coverage remains 87.0%.

Slice 14 (2026-11-18, gssapi nil invariants): the gssapi NilAway slice is
zero. Every successful `NewSecurityContext` use in unit/fuzz tests now checks
its constructor error through `mustSecurityContext(testing.TB, ...)`; token
fixture decoders check fixed-hex failures and constructor error paths before
slicing/dereferencing results. Production `SecurityContext.Wrap`, `Unwrap`,
`GetMIC`, and `VerifyMIC` return a typed safety error on a nil receiver;
`NegoExKey` and `NegoExVerifyKey` return `(zero, false)`. This closes the
nil-constructor-to-method dereference flows without changing successful
per-message behavior, key selection, or sequence handling. A regression tests
all six nil-receiver operations. Full v8 and focused gssapi/spnego/client/negoex
race suites pass; cross-package coverage remains 87.0%. GSS NilAway findings
fall from 40 to 0 and the canonical total from 1,549 to 1,511.

Slice 13 (2026-11-18, exhaustive enum handling): cleared all four exhaustive
diagnostics. TLS signature-algorithm selection now explicitly enumerates every
x509.SignatureAlgorithm required by exhaustive and retains a SHA-256 default
for future enum values; the test replaces its enum switch with a
map expectation (so it tests digest length without duplicating production
dispatch). NDR `noteConformantValue` and `fill` explicitly handle every
reflect.Kind, preserving the existing no-op and `unsupported type` behavior.
Review found NilAway treating the TLS digest as potentially nil despite the
complete cases; adding the future-value default also makes the hash invariant
explicit. Full v8 race tests and 87.0% coverage pass. Canonical findings are
1,549; interfacebloat remains intentionally open because the flagged public
interfaces describe protocol capabilities rather than accidental optional
mixins.

Slice 12 (2026-11-18, return clarity): all 68 functions carrying 134 named
result diagnostics now use unnamed signatures while preserving the original
locals and explicit return order. Bare returns that were below the nakedret
length threshold were expanded into explicit value lists; local declarations
were retained only where used. The transform intentionally left no public
signature type change and no behavior change: named result identifiers are
not part of Go's public API. Review caught and repaired four doc-comment
attachments exposed by the AST transform (session timing/SPN realm, basic
credential parser format, and ADAuthDataAPOptions Marshal). The canonical scan
reports zero nonamedreturns; total findings are 1,552. Full unit/race suites
and 87.0% coverage remain green.

Slice 11 (2026-11-18, checked type assertions): all 41 forcetypeassert
findings are cleared. Seven production SPNEGO assertions now fail closed or
return an internal error when state has the wrong concrete type: pending
mutual-authentication entries, authenticated credential context values,
multi-round HTTP exchange map values, negotiation-token init/resp values,
and `InitSecContext`'s mechanism token. The exchange cleanup loop deletes
invalid map entries rather than panicking. Tests use package-local generic
`mustXTestType` helpers to turn expected fixture assertions into explicit
fatal type mismatches; this preserves the exact-value checks without unchecked
panics. `decoderUnion.SwitchFunc` uses a normal checked assertion because it
is a union-discriminant test implementation with no testing handle. A new
regression verifies that a pending mutual-authentication entry of the wrong
type is rejected. SPNEGO/client/PKINIT/PKU2U/NEGOEX/NDR focused race suites pass,
and the changed-line lint gate is clean. The canonical total is 1,658.

Slice 10 (2026-11-18, Q-03/Q-06 I/O and body ownership): production errcheck
is zero. CLI diagnostics that already select a failing exit code remain
best-effort with explicit discards; successful-output writes now propagate
through the command exit status, verbose cache output fails the command, and
password input joins prompt/newline, terminal-restore, and close failures in
operation order. `config.Load` returns the partial config on parse errors while
joining parse and close causes. RC4-HMAC `RandomToKey` explicitly documents the
infallible `hash.Hash` writer contract, and existing void logger APIs remain
best-effort with explicit discards. Test setup now checks keytab/token decode,
authenticator generation, buffer writes, file writes, and closes; integration
subprocess pipes and HTTP response bodies have deterministic ownership. All
35 bodyclose findings are resolved through real closes; the retained HTTP
method test closes each response immediately after status inspection rather
than storing responses in a slice. The full canonical scan now reports zero
errcheck and zero bodyclose findings. The v8 canonical total is 1,691. Full v8 unit and
race suites pass; the changed-line lint gate is clean for both modules;
cross-package coverage remains 87.0%, above the 86.0% floor.

Preserve v8's Go 1.26.0 floor. Validate proposed modernizations on the supported
module toolchain and retain tagged/platform code. Measure optimizations before
and after with existing benchmarks. Gradually reduce canonical debt to zero;
then switch the full canonical scan from inventory-only to a blocking gate.

Exit: each completed slice has no unexplained canonical findings; counts fall
under unchanged scope; no public/wire behavior regressions; full-project zero
debt eventually enables an unfiltered required lint check.

## 5. Automation policy

[The runner](../../scripts/lint.sh) is shared by local work and the
[Lint workflow](../../.github/workflows/lint.yml). Use `full` for canonical
inventory, `report` for advisory inventory, and `new BASE_REV` for a blocking
canonical changed-line check. Both modules always run. Findings return 1;
configuration, package-loading, timeout, or tool failures must not be accepted
as existing debt.

The diff gate intentionally permits pre-existing debt on untouched lines. It
does not prove an unchanged caller is safe after a callee change, enforce a
monotonic total count automatically, or assess advisory rules as mandatory.
Review full artifacts for behavioral changes. Stage new files for local diff
checks; CI sees committed files. No runtime source was refactored in this
assessment.

## Appendix A - Historical MS-KILE review and implementation plan

Historical snapshot, not an executable open-issue queue. Original section and
phase numbers below refer to the MS-KILE specification. Reconcile IDs under
Phase 1 above before acting; retain its implementation notes and external gates.

### 2. Current Implementation — Findings

Sources reviewed: `v8/client/*.go`, `v8/messages/*.go`, `v8/types/*.go`, `v8/pac/*.go`, `v8/gssapi/*.go`, `v8/spnego/*.go`, `v8/service/*.go`, `v8/crypto/*.go`, `v8/kadmin/*.go`, `v8/config/*.go`, `v8/iana/**`.

#### 2.1 What exists and is compliant

| Capability | Location |
| --- | --- |
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

#### 2.2 Defects and gaps — protocol structures (`KS-n`)

| ID | Historical finding | Historical severity | Phase 1 disposition and local evidence |
| --- | --- | --- | --- |
| KS-1 | No ASN.1 types for KERB-PA-PAC-REQUEST (128), PA-PAC-OPTIONS (167), KERB-ERROR-DATA / KERB-EXT-ERROR, KERB-AD-RESTRICTION-ENTRY (141) with LSAP_TOKEN_INFO_INTEGRITY, KERB-LOCAL (142), AD-AUTH-DATA-AP-OPTIONS (143), PA-FOR-USER (129), PA-S4U-X509-USER (130), PA-SUPPORTED-ENCTYPES (165), KERB-KEY-LIST-REQ/REP (161/162), PA-SVR-REFERRAL-INFO (20, RFC 6806 Appendix A), KERB-SUPERSEDED-BY-USER (170), KERB-DMSA-KEY-PACKAGE (PA-DATA 171). Only the `patype` constants up to 166 exist; 167, 161, 162, 170, 171 are missing. | High | Implemented; [`TestMSKILEPADataWrappers`](../../v8/types/mskile_test.go). Local evidence is not a live interoperability claim. |
| KS-2 | `iana/adtype` lacks 141, 142, 143; `iana/nametype` lacks `KRB_NT_WELLKNOWN` (11), `KRB_NT_MS_PRINCIPAL` (-128), `KRB_NT_MS_PRINCIPAL_AND_ID` (-129), `KRB_NT_ENT_PRINCIPAL_AND_ID` (-130); no constants for `KERB_AP_OPTIONS_CBT` (0x4000), `KERB_AP_OPTIONS_UNVERIFIED_TARGET_NAME` (0x8000), PA-PAC-OPTIONS flag bits, PA-SUPPORTED-ENCTYPES bit field, `KDC_OPT_CNAME_IN_ADDL_TKT` (bit 14), key usages 26/27 (PA-S4U-X509-USER), NTSTATUS values commonly surfaced in KERB-EXT-ERROR. | Medium | Implemented; [`TestMSKILESemanticValidation`](../../v8/types/mskile_test.go). Local evidence is not a live interoperability claim. |
| KS-3 | `messages.KRBError.EData` is only parsed as METHOD-DATA in specific retry paths. KERB-ERROR-DATA (data-type 3 `KERB_ERR_TYPE_EXTENDED` carrying an NTSTATUS, data-type 2 `KERB_AP_ERR_TYPE_SKEW_RECOVERY`) and TYPED-DATA are never decoded, so AD-specific failure reasons (e.g. `STATUS_ACCOUNT_DISABLED`, `STATUS_PASSWORD_MUST_CHANGE`) are lost. | Medium | Implemented; [`TestKRBErrorMethodData`](../../v8/messages/KRBError_test.go). Local evidence is not a live interoperability claim. |
| KS-4 | `PACType.ProcessPACInfoBuffers` slices `pac.Data[Offset:Offset+Size]` without bounds checks; a malformed PAC panics the service. `UPNDNSInfo.Unmarshal` slices by untrusted offsets similarly. No PAC fuzz target. | High (security) | Implemented; [`TestPACBoundsChecks`](../../v8/pac/pac_type_test.go). Local evidence is not a live interoperability claim. |
| KS-5 | PAC buffer types 16 (PAC_TICKET_CHECKSUM), 17 (PAC_ATTRIBUTES_INFO), 18 (PAC_REQUESTOR), 19 (PAC_FULL_CHECKSUM) are not recognised and are silently dropped. | Medium | Implemented; [`TestPACMarshalReencodesTypedBuffers`](../../v8/pac/marshal_test.go). Local evidence is not a live interoperability claim. |
| KS-6 | `UPNDNSInfo` flag handling is wrong: `upnNoUPNAttr = 31` is used as a bit index where MS-PAC defines flag `U` = 0x00000001; flag `S` = 0x00000002 (SamName/Sid extension) is not parsed. | Medium | Implemented; [`TestUPNDNSInfoExtendedRoundTrip`](../../v8/pac/upn_dns_info_test.go). Local evidence is not a live interoperability claim. |
| KS-7 | No PAC marshalling; fixtures cannot be synthesised and negative tests (tampered checksums, duplicate buffers, misaligned offsets) are impossible to construct programmatically. | Medium | Implemented; [`TestPACMarshalRejectsInvalidMetadata`](../../v8/pac/marshal_test.go). Local evidence is not a live interoperability claim. |
| KS-8 | `AuthorizationData` walking is ad hoc (`Ticket.GetPACType` only looks for `AD-IF-RELEVANT[0] == AD-WIN2K-PAC`). There is no generic visitor that returns all entries of a given type from nested AD-IF-RELEVANT containers in either ticket or authenticator authorization data. | Medium | Implemented; [`TestMSKILEExtendedErrorAndAuthorizationDataHelpers`](../../v8/types/mskile_test.go). Local evidence is not a live interoperability claim. |

#### 2.3 Defects and gaps — client behaviour (`KC-n`)

| ID | Historical finding | Historical severity | Phase 1 disposition and local evidence |
| --- | --- | --- | --- |
| KC-1 | AS-REQ never includes KERB-PA-PAC-REQUEST. AD includes a PAC by default, but MS-KILE §3.2.5 clients send `include-pac` and RODC/branch scenarios depend on it; services that want PAC-less tickets cannot ask. | Medium | Implemented; [`TestNewASReqIncludesPACRequest`](../../v8/messages/KDCReq_test.go). Local evidence is not a live interoperability claim. |
| KC-2 | `ASRep.Verify`/`TGSRep.Verify` reject any `cname` that differs from the request. When `canonicalize` is set or the request used `KRB_NT_ENTERPRISE`, AD legitimately returns the canonical `cname`; RFC 6806 §11 / MS-KILE require acceptance (protected by PA-REQ-ENC-PA-REP when present). Enterprise logons to AD currently fail. | High | Implemented; [`TestRequestAllowsCanonicalName`](../../v8/messages/KDCRep_test.go). Local evidence is not a live interoperability claim. |
| KC-3 | PA-SUPPORTED-ENCTYPES in the reply `encrypted-pa-data` is ignored, so the client cannot learn that the target supports AES-SK, claims, FAST, or compound identity, and cannot restrict TGS etypes accordingly. | Medium | Implemented; [`TestGetSupportedEncTypes`](../../v8/client/session_test.go). Local evidence is not a live interoperability claim. |
| KC-4 | No PA-PAC-OPTIONS in TGS-REQ: Claims, Branch-Aware, Forward-to-Full-DC and RBCD flags cannot be set. | Medium | Implemented; [`TestTGSReqMSKILEOptions`](../../v8/messages/KDCReq_test.go). Local evidence is not a live interoperability claim. |
| KC-5 | No S4U2self (PA-FOR-USER, PA-S4U-X509-USER) and no S4U2proxy (`cname-in-addl-tkt` with evidence ticket), so constrained delegation and protocol transition are impossible. | High | Implemented; [`TestNewPAForUserPAData`](../../v8/messages/s4u_test.go). Local evidence is not a live interoperability claim. |
| KC-6 | No FAST (RFC 6113) armoring: PA-FX-FAST, PA-FX-COOKIE, PA-FX-ERROR, PA-ENCRYPTED-CHALLENGE are absent. `DisablePAFXFAST` actually toggles PA-REQ-ENC-PA-REP. AD policies "Fail unarmored authentication requests" and compound identity cannot be satisfied. | High | Implemented; [`TestFASTASRequestEncryptsInnerRequest`](../../v8/client/fast_test.go). Local evidence is not a live interoperability claim. |
| KC-7 | Realm comparisons are case-sensitive string equality throughout (`Ticket.Realm`, `CRealm`, cache keys). MS-KILE realm names are case-insensitive; AD emits upper-case, `krb5.conf` and users often supply mixed case. | Medium | Implemented; [`TestNewFromCCacheMatchesTGTRealmCaseInsensitively`](../../v8/client/asexchange_phase5_test.go). Local evidence is not a live interoperability claim. |
| KC-8 | Delegation: GSS `ContextFlagDeleg` extends the 0x8003 checksum to 28 bytes but never populates `Dlgth`/`Deleg` with a KRB-CRED; the `ok-as-delegate` ticket flag is not consulted. | High | Implemented; [`TestGetDelegatedCredentialRoundTrip`](../../v8/client/tgsexchange_coverage_test.go). Local evidence is not a live interoperability claim. |
| KC-9 | 0x8003 checksum `Bnd` is always 16 zero bytes; no API to supply GSS channel bindings (tls-server-end-point, tls-unique). No AD-AUTH-DATA-AP-OPTIONS with `KERB_AP_OPTIONS_CBT`, so Windows services with Extended Protection "Required" reject gokrb5 clients. | High | Implemented; [`TestChannelBindingsMD5Hash`](../../v8/gssapi/authenticatorChecksum_test.go). Local evidence is not a live interoperability claim. |
| KC-10 | Authenticator does not carry `KERB-LOCAL` or `KERB-AD-RESTRICTION-ENTRY`; Windows clients do, servers must ignore. Client-side emission is optional but the acceptor must tolerate it (see KA-4). | Low | Implemented; [`TestVerifyAPREQIgnoresKerbLocalAndRestrictionEntry`](../../v8/service/APExchange_test.go). Local evidence is not a live interoperability claim. |
| KC-11 | No DCE-style (`GSS_C_DCE_STYLE` 0x1000) three-leg exchange and no `GSS_C_EXTENDED_ERROR_FLAG` (0x4000); required for RPC/SMB-style acceptors and Windows error propagation. | Medium | Implemented; [`TestDCEContextExchange`](../../v8/spnego/context_exchange_test.go). Local evidence is not a live interoperability claim. |
| KC-12 | No legacy RFC 4757 §7 / RFC 1964 per-message tokens (TOK_ID 0x0101 MIC, 0x0201 Wrap, SGN_ALG 0x1100, SEAL_ALG 0x1000). Windows uses them whenever the session key is RC4-HMAC; gokrb5 wraps with 0x0504 regardless of key type, which Windows rejects. | High | Confirmed open with regression: legacy RC4 GSS MIC/Wrap unsupported; [`TestNewSecurityContextRejectsUnsupportedKeys`](../../v8/gssapi/security_context_test.go) verifies explicit rejection. Phase 2 compatibility slice; not Windows-verified. |
| KC-13 | No KKDCP (Kerberos over HTTPS) transport; `kdc = https://host/KdcProxy` in `krb5.conf` is not understood. | Medium | Implemented; [`TestKKDCPTransport`](../../v8/client/kkdcp_test.go). Local evidence is not a live interoperability claim. |
| KC-14 | No PKINIT: see §2.6 (`KP-n`) for the MS-PKCA breakdown. | Medium | Implemented; [`TestPKINITFreshnessTokenAbsent`](../../v8/client/pkinit_test.go). Local evidence is not a live interoperability claim. |
| KC-15 | KDC discovery does not use AD-specific SRV names (`_kerberos._tcp.dc._msdcs.<domain>`, site-aware variants) or `_kpasswd`; falls back only to `_kerberos._tcp.<realm>`. | Low | Implemented; [`TestGetKDCsUsesADSiteDiscoveryOrder`](../../v8/config/hosts_test.go). Local evidence is not a live interoperability claim. |
| KC-16 | `PA-SVR-REFERRAL-INFO` in `EncKDCRepPart.EncPAData` is ignored; the referral realm is inferred from the `krbtgt/REALM` sname only. | Low | Implemented; [`TestReferralRealmUsesReplyMetadata`](../../v8/client/session_test.go). Local evidence is not a live interoperability claim. |
| KC-17 | kpasswd result strings from AD carry a 30-byte password-policy blob after the text; it is exposed as raw bytes with no decoder. | Low | Implemented; [`TestParseResponsePasswordPolicy`](../../v8/kadmin/message_test.go). Local evidence is not a live interoperability claim. |

#### 2.4 Defects and gaps — application-server behaviour (`KA-n`)

| ID | Historical finding | Historical severity | Phase 1 disposition and local evidence |
| --- | --- | --- | --- |
| KA-1 | PAC validation stops at server-checksum verification. MS-PAC/MS-KILE application-server rules not applied: PAC_CLIENT_INFO `Name` must equal the ticket `cname` (case-insensitive) and `ClientId` must equal ticket `authtime`; PAC_REQUESTOR SID (when present) must equal KERB_VALIDATION_INFO `UserId` under `LogonDomainId`; UPN_DNS_INFO `S` extension SAM name/SID (when present) must match; duplicate buffer types must be rejected rather than ignored where MS-PAC says "MUST NOT". | High | Implemented; [`TestPACTypeVerify`](../../v8/pac/pac_type_test.go). Local evidence is not a live interoperability claim. |
| KA-2 | Only `GroupMembershipSIDs`, logon times and a few names are exposed in `credentials.ADCredentials`. UPN, DNS domain, SAM account name, user SID, extra SIDs with attributes, resource group SIDs, client/device claims, device info, S4U delegation chain, PAC attributes flags and `UserAccountControl` are parsed but not surfaced. | Medium | Implemented; [`TestADCredentialsFromPAC`](../../v8/service/pac_credentials_test.go). Local evidence is not a live interoperability claim. |
| KA-3 | Acceptor ignores the 0x8003 checksum entirely: no channel-binding comparison, no reading of `Flags`, no delegation (`Deleg` KRB-CRED) extraction, no DCE-style AP-REP handling, no `KERB_AP_OPTIONS_CBT` detection for Extended Protection policy. | High | Implemented; [`TestExtendedProtectionPolicy`](../../v8/service/APExchange_test.go). Local evidence is not a live interoperability claim. |
| KA-4 | Acceptor does not tolerate/ignore authenticator authorization data (`KERB-LOCAL`, `KERB-AD-RESTRICTION-ENTRY`, `AD-AUTH-DATA-AP-OPTIONS`); presence is not fatal today only because the field is never inspected — confirm and lock with tests. | Low | Implemented; [`TestVerifyAPREQIgnoresKerbLocalAndRestrictionEntry`](../../v8/service/APExchange_test.go). Local evidence is not a live interoperability claim. |
| KA-5 | No AP-REP generation with subkey/sequence number when the client requests mutual authentication (`ContextFlagMutual`); SPNEGO acceptor returns `accept-completed` without a `responseToken`. Windows clients with mutual auth fail. | High | Implemented; [`TestAPRepRoundTripAndVerify`](../../v8/messages/APRep_test.go). Local evidence is not a live interoperability claim. |
| KA-6 | Legacy RC4 per-message tokens cannot be verified/unwrapped on the acceptor (mirror of KC-12). | High | Confirmed open with regression: legacy RC4 GSS MIC/Wrap unsupported; [`TestNewSecurityContextRejectsUnsupportedKeys`](../../v8/gssapi/security_context_test.go) verifies explicit rejection. Phase 2 compatibility slice; not Windows-verified. |
| KA-7 | User-to-user tickets (`enc-tkt-in-skey`) cannot be accepted; `APReq.Verify` only tries keytab keys. | Low | Confirmed open with regression: no acceptor TGT-session-key input; [`TestVerifyAPREQUserToUserRequiresAcceptorKeySupport`](../../v8/service/u2u_characterization_test.go) verifies keytab-only rejection. Phase 2 compatibility slice. |
| KA-8 | The acceptor does not validate the ticket `sname` against the service's own principal names when the keytab contains several principals unless `KeytabPrincipal` is set — MS-KILE §3.4.5 requires the ticket be for this service. | Medium | Implemented; [`TestVerifyAPREQWithPrincipalOverride`](../../v8/service/APExchange_test.go). Local evidence is not a live interoperability claim. |
| KA-9 | SPNEGO acceptor does not emit or verify `mechListMIC` per MS-SPNG rules (required when the negotiated mech is not the initiator's first preference, or when the client sends one). | Medium | Implemented; [`TestNegTokenInitMechListMIC`](../../v8/spnego/negotiationToken_test.go). Local evidence is not a live interoperability claim. |

#### 2.5 Defects and gaps — NEGOEX and PKU2U (`KN-n`)

| ID | Historical finding | Historical severity | Phase 1 disposition and local evidence |
| --- | --- | --- | --- |
| KN-1 | No NEGOEX mechanism (`1.3.6.1.4.1.311.2.2.30`): no message framing (`MESSAGE_HEADER`, `NEGO_MESSAGE`, `EXCHANGE_MESSAGE`, `VERIFY_MESSAGE`, `ALERT_MESSAGE`), no auth-scheme GUID negotiation, no conversation state machine. | High | Implemented; [`TestMessageHeaderRoundTrip`](../../v8/negoex/negoex_test.go). Local evidence is not a live interoperability claim. |
| KN-2 | SPNEGO acceptor behaviour when the initiator's optimistic `mechToken` is NEGOEX (the Windows default) is unverified: it must answer `accept-incomplete` selecting KRB5 (or NEGOEX once implemented) instead of failing. SPNEGO initiator cannot offer NEGOEX. | Medium | Implemented; [`TestNegotiatorUnsupportedOptimisticFallback`](../../v8/spnego/mechanism_test.go). Local evidence is not a live interoperability claim. |
| KN-3 | No PKU2U mechanism (`1.3.6.1.5.2.7`): no `WELLKNOWN:PKU2U` realm handling, no acceptor-as-KDC AS exchange, no PKU2U metadata (trusted-certifier) exchange, no certificate-to-principal mapping. | High | External evidence pending: [`TestEndToEndOverSPNEGO`](../../v8/pku2u/pku2u_test.go) verifies local peers only; fixture 14 and bidirectional Windows runs remain Phase 4 gates. |
| KN-4 | No GSS context key export equivalent to `GSS_C_INQ_NEGOEX_KEY` / `GSS_C_INQ_NEGOEX_VERIFY_KEY`, which NEGOEX needs to compute and verify the `VERIFY` checksum over the conversation. | Medium | Implemented; [`TestSecurityContextNegoExKeysAreCloned`](../../v8/gssapi/security_context_test.go). Local evidence is not a live interoperability claim. |
| KN-5 | `gssapi` has no OID constants for NEGOEX or PKU2U and no generic mechanism interface; `spnego` hard-codes KRB5 as the only negotiable mechanism. | Medium | Implemented; [`TestOID`](../../v8/gssapi/gssapi_test.go). Local evidence is not a live interoperability claim. |

#### 2.6 Defects and gaps — PKINIT / MS-PKCA (`KP-n`)

| ID | Historical finding | Historical severity | Phase 1 disposition and local evidence |
| --- | --- | --- | --- |
| KP-1 | No PA-PK-AS-REQ (16) / PA-PK-AS-REP (17) ASN.1 (`AuthPack`, `PKAuthenticator`, `DHRepInfo`, `KDCDHKeyInfo`, `ReplyKeyPack`, `TD-*` typed data) and no CMS `SignedData`/`EnvelopedData` codec; the `patype` constants 14–18 exist but nothing consumes them. The legacy Windows 2000 PA-PK-AS-REQ-OLD (14/15) must be recognised and rejected with a clear error, not treated as unknown PA-DATA. | High | Implemented; [`TestAuthPackRoundTrip`](../../v8/pkinit/asn1_test.go). Local evidence is not a live interoperability claim. |
| KP-2 | No Diffie-Hellman (MODP 2/14/16) or RSA (`encKeyPack`) reply-key path; `octetstring2key` (RFC 4556 §3.2.3.1) and the RFC 8636 KDF (`id-pkinit-kdf-ah-sha256/384/512`) that Windows Server 2012+ negotiates via `supportedKDFs`/`kdfId` are absent. | High | Implemented; [`TestProcessDHReply`](../../v8/pkinit/client_test.go). Local evidence is not a live interoperability claim. |
| KP-3 | No client certificate selection/validation per MS-PKCA §3.1.5: EKU `id-kp-clientAuth` or `Smart Card Logon` (`1.3.6.1.4.1.311.20.2.2`), UPN in `otherName` SAN (`1.3.6.1.4.1.311.20.2.3`) or `id-pkinit-san`, the strong-mapping SID extension (`1.3.6.1.4.1.311.25.2`) for diagnostics, `pkinit_identities` sources (PEM, PKCS#12, `crypto.Signer` for PKCS#11/TPM). | High | Implemented; [`TestBeginExchangeRejectsUntrustedIdentityName`](../../v8/pkinit/client_test.go). Local evidence is not a live interoperability claim. |
| KP-4 | No KDC certificate validation per MS-PKCA §3.2.5.2: chain to `pkinit_anchors`, `KDC Authentication` EKU (`id-pkinit-KPKdc`, `1.3.6.1.5.2.3.5`) or, for legacy DCs, `Server Authentication` with the DC template, `dNSName` SAN matching the realm's DNS domain or `pkinit_kdc_hostname`, `id-pkinit-san` `krbtgt/REALM` for non-MS KDCs, CRL/OCSP revocation checking (`pkinit_require_crl_checking`), signature verification of `dhSignedData`/`signedAuthPack`, `dhKeyExpiration` handling and DH key reuse. | High | Implemented; [`TestValidateKDCCertificate`](../../v8/pkinit/kdccert_test.go). Local evidence is not a live interoperability claim. |
| KP-5 | PKINIT KRB-ERROR handling absent: `KDC_ERR_CLIENT_NOT_TRUSTED`, `KDC_ERR_KDC_NOT_TRUSTED`, `KDC_ERR_INVALID_SIG`, `KDC_ERR_DH_KEY_PARAMETERS_NOT_ACCEPTED` (+ `TD-DH-PARAMETERS` retry), `KDC_ERR_CANT_VERIFY_CERTIFICATE`, `KDC_ERR_INVALID_CERTIFICATE`, `KDC_ERR_REVOKED_CERTIFICATE`, `KDC_ERR_REVOCATION_STATUS_UNKNOWN`, `KDC_ERR_CLIENT_NAME_MISMATCH`, `KDC_ERR_KDC_NAME_MISMATCH`, `KDC_ERR_INCONSISTENT_KEY_PURPOSE`, `KDC_ERR_DIGEST_IN_CERT_NOT_ACCEPTED`, `KDC_ERR_PA_CHECKSUM_MUST_BE_INCLUDED`, `KDC_ERR_DIGEST_IN_SIGNED_DATA_NOT_ACCEPTED`, `KDC_ERR_PUBLIC_KEY_ENCRYPTION_NOT_SUPPORTED`, `KDC_ERR_NO_ACCEPTABLE_KDF`, with `TD-TRUSTED-CERTIFIERS`/`TD-INVALID-CERTIFICATES`/`TD-CERTIFICATE-INDEX` decoding and the NTSTATUS from KERB-ERROR-DATA. | Medium | Implemented; [`TestAcceptExchangeRejectsInvalidRequests`](../../v8/pkinit/client_test.go). Local evidence is not a live interoperability claim. |
| KP-6 | No PKINIT freshness (RFC 8070, PA-AS-FRESHNESS 150) which Windows Server 2016+ KDCs offer and can require ("KDC support for PKInit Freshness Extension"); no PA-PK-OCSP-RESPONSE (18) stapling in either direction. | Medium | Implemented; [`TestPKINITFreshnessTokenAbsent`](../../v8/client/pkinit_test.go). Local evidence is not a live interoperability claim. |
| KP-7 | `PAC_CREDENTIAL_INFO` (buffer 2) is skipped; with a PKINIT reply key it must be decrypted (usage 16) into `PAC_CREDENTIAL_DATA` → `NTLM_SUPPLEMENTAL_CREDENTIAL` for the client (MS-PAC §2.6, MS-PKCA §3.2.5.2). `credentials_info.go`/`supplemental_cred.go` parse the plaintext but nothing decrypts. | Medium | Implemented; [`TestPKINITCredentialsReturnsDefensiveCopy`](../../v8/client/pkinit_test.go). Local evidence is not a live interoperability claim. |
| KP-8 | No support for PKINIT with self-signed keys used by Windows Hello for Business key trust (client certificate without a chain; KDC maps via `msDS-KeyCredentialLink`) — requires an explicit "no chain, KDC-mapped" identity mode. | Low | Implemented; [`TestPrivateKeyFormatsAndIdentityPolicies`](../../v8/pkinit/identity_test.go). Local evidence is not a live interoperability claim. |
| KP-9 | `gokinit` has no `-X X509_user_identity=`/`-X X509_anchors=` options and `krb5.conf` `pkinit_*` keys are not parsed. | Low | Implemented; [`TestParseArgsAcceptsPKINITOptions`](../../v8/cmd/gokinit/main_test.go). Local evidence is not a live interoperability claim. |

---

### 6. Phased Implementation Plan (LLM-executable)

Conventions for every phase:

- Read the cited spec sections first; where this document and the spec disagree, the spec wins — record the discrepancy in §7.
- Each phase is independently mergeable and ends with a check that must pass before the next phase starts.
- Follow repository conventions: `testify/assert`, fixtures as hex constants in `v8/test/testdata/`, integration tests call `test.Integration(t)`/`test.AD(t)` first, no new third-party dependencies beyond those listed in the phase.
- Keep changes within the listed files unless compilation forces otherwise; run `gofmt`, `go vet ./...`, `go test ./...` from `v8/` after each step.
- Never weaken an existing check to make a test pass; add options with safe defaults instead.
- Do not commit captured material containing real credentials or non-test keys.

#### Phase 0 — Constants, ASN.1 structures, fixtures (KS-1, KS-2, parts of KS-3)

Files: `v8/iana/patype/constants.go`, `v8/iana/adtype/constants.go`, `v8/iana/nametype/constants.go`, `v8/iana/flags/constants.go`, `v8/iana/keyusage/constants.go`, new `v8/iana/msflags/constants.go`, new `v8/iana/ntstatus/constants.go`, new `v8/types/mskile.go`, new `v8/types/fast.go`, new `v8/types/mskile_test.go`, new `v8/test/testdata/mskile_vectors.go`, new `v8/test/testdata/gen/mskile_capture.md`.

Steps:

1. Add every constant listed in §3.1. Keep existing names; add new aliases rather than renaming.
2. Implement the structures in §3.1 with `Marshal`/`Unmarshal`, mirroring the style of `types/PAData.go` (`gofork/encoding/asn1`, `generalstring` tags). Little-endian binary structures (`KerbExtError`, `LSAPTokenInfoIntegrity`, `ADAuthDataAPOptions`, `PASupportedEncTypes`) use `encoding/binary` with strict length checks.
3. Add constructors: `NewKerbPAPACRequestPAData(include bool)`, `NewPAPACOptionsPAData(bits ...int)`, `NewADAuthDataAPOptionsEntry(opts uint32)`, `(PAData).GetPAPACOptions()`, etc.
4. Capture or spec-derive fixtures 1–3, 5 (structures only), 6 (PAC 17/18 payloads), 12 from §4.2. Fixtures that cannot be captured now are marked `// SPEC-DERIVED — replace with Windows capture` exactly as the MIT spec does.
5. Write round-trip tests and fixture-decode tests; add `TestFixturesDecode` entries in `test_vectors_test.go` style.

Check: `go test ./iana/... ./types/... ./test/testdata` green; `go vet ./...` clean; no behavioural change (`go test ./...` unchanged).

#### Phase 1 — Parser hardening and generic authorization-data access (KS-3, KS-4, KS-8, KA-4)

Files: `v8/pac/pac_type.go`, `v8/pac/upn_dns_info.go`, `v8/pac/*_test.go`, new `v8/pac/fuzz_test.go`, `v8/types/AuthorizationData.go`, `v8/messages/Ticket.go`, `v8/messages/KRBError.go`, `v8/krberror/error.go`, `v8/service/APExchange.go`, tests alongside.

Steps:

1. In `ProcessPACInfoBuffers` validate each `InfoBuffer` (`Offset+Size <= len(Data)`, `Offset % 8 == 0`, no overlap with the header table or other buffers, `CBuffers` sane); return `ErrPACMalformed` wrapping the detail. Copy slices via a checked helper.
2. Bounds-check `UPNDNSInfo.Unmarshal` (and audit `client_info.go`, `s4u_delegation_info.go`, `credentials_info.go`, `signature_data.go` for unchecked slicing).
3. Add `FuzzPACUnmarshal` seeded with all `MarshaledPAC_*` fixtures; property: never panics.
4. Implement `AuthorizationData.Walk`/`EntriesOfType`; refactor `Ticket.GetPACType` to use it; add `TestAuthorizationDataWalkDepthLimit`.
5. Implement `KRBError.MethodData()`, `KerbErrorData()`, `NTStatus()`; make `krberror.Krberror` expose the underlying `KRBError` (`errors.As`) and print the NTSTATUS name when present.
6. Add `TestVerifyAPREQIgnoresKerbLocalAndRestrictionEntry` using fixture 5 structures injected into an authenticator built by the existing service tests.

Check: `go test ./pac/... ./types/... ./messages/... ./service/...` green; `go test -run XXX -fuzz FuzzPACUnmarshal -fuzztime 30s ./pac` no crashes.

#### Phase 2 — Client AS/TGS MS-KILE behaviour (KC-1, KC-2, KC-3, KC-4, KC-7, KC-16, KC-15, KC-17)

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

#### Phase 3 — GSS initiator/acceptor core: channel bindings, delegation, mutual auth, DCE style (KC-8, KC-9, KC-10, KC-11, KA-3, KA-5, KA-8)

Files: new `v8/gssapi/channelBindings.go`, new `v8/gssapi/authenticatorChecksum.go`, `v8/gssapi/contextFlags.go`, `v8/spnego/krb5Token.go`, `v8/spnego/negotiationToken.go`, `v8/spnego/http.go`, `v8/service/settings.go`, `v8/service/APExchange.go`, `v8/messages/APReq.go`, `v8/messages/APRep.go`, `v8/messages/KRBCred.go`, `v8/client/client.go` (forwarded-TGT request helper), `v8/credentials/credentials.go`, tests alongside.

Steps:

1. Implement `ChannelBindings`, `MD5Hash`, `TLSServerEndPoint`, `TLSUnique`.
2. Replace `newAuthenticatorChksum` with a typed `AuthenticatorChecksum{Bnd, Flags, Deleg}` marshaller/unmarshaller (RFC 4121 §4.1.1) including `Exts`.
3. `NewKRB5TokenAPREQ` options: bindings, flags, delegate. Delegation: request a forwarded TGT via TGS-REQ (`forwarded`, `forwardable`, acceptor addresses optional), build KRB-CRED (usage 14, session key), honour `ok-as-delegate` unless forced. Add `AD-IF-RELEVANT[AD-AUTH-DATA-AP-OPTIONS{CBT}]` to the authenticator when bindings are given.
4. Acceptor: parse the checksum; enforce `Settings.ExtendedProtection` policy; extract delegated KRB-CRED into `Credentials.DelegatedCredentials()`; verify `sname` against `Settings.ServicePrincipals()` (default: all keytab principals) — KA-8.
5. Mutual auth: build AP-REP (`ctime`, `cusec`, `subkey`, `seq-number`) and return it as SPNEGO `responseToken` with `accept-completed`; client verifies AP-REP and stores subkey/seq for per-message tokens. DCE style: acceptor keeps state for the third leg; client sends it.
6. Tests: §4.3 gssapi/spnego/service items with fixture 5; policy matrix test.

Check: `go test ./gssapi/... ./spnego/... ./service/... ./client/...` green; Samba integration items 5–7 green.

#### Phase 4 — PAC completeness and application-server validation (KS-5, KS-6, KS-7, KA-1, KA-2)

Files: `v8/pac/pac_type.go`, `v8/pac/upn_dns_info.go`, new `v8/pac/attributes_info.go`, new `v8/pac/requestor.go`, new `v8/pac/marshal.go`, new `v8/pac/verify_options.go`, `v8/pac/*_test.go`, `v8/credentials/credentials.go`, `v8/service/APExchange.go`, `v8/spnego/http.go`, `USAGE.md`.

Steps:

1. Add buffers 16–19 and the `ZeroSigData` handling for 16/19 per MS-PAC §2.8.
2. Fix `UPNDNSInfo` flags; add `S` extension fields.
3. Implement `PACType.Marshal`, per-buffer `Marshal`, `Sign(serverKey, kdcKey, ticketKey?)`; if `rpc/v2/ndr` lacks an encoder, add a minimal one under `v8/pac/internal/ndrw` for the types used (document in §7).
4. Implement `Verify(key, VerifyOptions)` with the KA-1 rules; default options replicate current behaviour plus client-info checks (fail closed on mismatch), `RequestorSID` enforced when present.
5. Expand `credentials.ADCredentials`; populate in `VerifyAPREQ`; document context access in `USAGE.md`.
6. Negative tests built with the marshaller: tampered server checksum, duplicate KERB_VALIDATION_INFO, misaligned offset, requestor mismatch, client-info name mismatch, `S`-extension SID mismatch; `FuzzPACUnmarshal` reseeded with marshalled outputs.

Check: `go test ./pac/... ./service/... ./credentials/...` green; fixture 6 PACs verify; `go test -fuzz FuzzPACUnmarshal -fuzztime 30s ./pac` clean.

Implementation note: `rpc/v2` provides an NDR decoder but no general encoder.
Phase 4 therefore preserves existing complex NDR buffer payloads byte-for-byte
when rebuilding or re-signing a PAC, and provides typed marshalers for the
simple PAC buffers changed in this phase. This avoids emitting partial or
non-conformant NDR while retaining lossless PAC re-signing.

#### Phase 5 — SPNEGO mechListMIC and negotiation extensions (KA-6, KA-9)

Files: `v8/spnego/negotiationToken.go`, `v8/spnego/spnego.go`, `v8/spnego/krb5Token.go`, tests alongside, `v8/USAGE.md`.

Steps:

1. Compute and verify `mechListMIC` over the DER-encoded `MechTypeList` using the established Kerberos context and RFC 4121 direction, subkey, key-usage, and sequence semantics.
2. Implement the RFC 4178 `request-mic` continuation in both directions, including fail-closed handling for missing, altered, or unexpected mechanism-list MICs.
3. Parse and marshal NegTokenInit2 `negHints`; make standard versus Microsoft legacy Kerberos OID ordering configurable without enabling legacy RC4 encryption.
4. Tests: mutual and non-mutual MIC exchanges, mechanism downgrade and MIC tampering, NegTokenInit2 round trips, legacy-OID-first negotiation, and negotiation-token fuzzing.

Check: `go test ./spnego/...` green; race detector and negotiation-token fuzzing clean; existing Kerberos GSS tests unchanged.

#### Phase 6 — S4U2self, S4U2proxy, RBCD (KC-5, MS-SFU)

Files: new `v8/client/s4u.go`, `v8/messages/KDCReq.go` (`NewS4U2SelfTGSReq`, `NewS4U2ProxyTGSReq`), `v8/messages/KDCRep.go` (verify PA-S4U-X509-USER reply checksum), `v8/client/TGSExchange.go` (referral handling for S4U per MS-SFU §3.1.5), `v8/krberror/error.go` (`ErrDelegationNotPermitted`, `ErrProtocolTransitionNotPermitted`), `v8/credentials/credentials.go` (`S4UDelegationInfo` exposure already from Phase 4), tests alongside, `USAGE.md`.

Steps:

1. PA-FOR-USER builder with HMAC-MD5 checksum exactly per MS-SFU §2.2.1 (byte order and concatenation), keyed with the TGT session key, usage 17.
2. PA-S4U-X509-USER builder (usage 26) and reply verification (usage 27); send both when the KDC advertises support (Windows 2008+); fall back to PA-FOR-USER only on `KDC_ERR_PADATA_TYPE_NOSUPP`.
3. S4U2self flow including cross-realm user (obtain referral TGT for the user's realm, retry there, then present to own realm per MS-SFU §3.1.5.1.1); expose whether the ticket is `forwardable`.
4. S4U2proxy flow: `cname-in-addl-tkt`, evidence ticket in `additional-tickets`, RBCD bit in PA-PAC-OPTIONS on request; cross-realm target via referral TGT (MS-SFU §3.1.5.2.2); map KDC errors + NTSTATUS to typed errors.
5. Cache S4U tickets under `(user, spn)` keys separate from the client's own tickets.
6. Tests: unit with fixture 4; Samba integration item 4 (classic, RBCD, protocol transition on/off, unauthorised target).

Check: `go test ./client/... ./messages/...` green; `TESTAD=1` S4U suite green against Samba; MIT suite unchanged.

#### Phase 7 — FAST armoring, encrypted challenge, compound identity, claims (KC-6)

Files: new `v8/messages/fast.go`, new `v8/client/fast.go`, `v8/client/ASExchange.go`, `v8/client/TGSExchange.go`, `v8/client/settings.go`, `v8/crypto/crypto.go` (`KRBFXCF2` — check `v8/crypto/common` first), `v8/messages/KDCRep.go`, `v8/messages/KRBError.go`, tests alongside, `USAGE.md`.

Steps:

1. Implement `KRB-FX-CF2` (RFC 6113 §5.1) with test vectors from RFC 6113 appendix / MIT `t_cf2`.
2. Armor acquisition: explicit `(ticket, key)` option or keytab-based armor AS exchange; armor key derivation; `FX_FAST_ARMOR_AP_REQUEST`.
3. Wrap AS-REQ/TGS-REQ into PA-FX-FAST; implement PA-ENCRYPTED-CHALLENGE pre-auth; carry PA-FX-COOKIE; unwrap PA-FX-FAST replies (strengthen key, `KrbFastFinished` ticket checksum) and PA-FX-ERROR.
4. `RequireFAST` fail-closed; auto-FAST when armor is available and the KDC advertised `FAST_SUPPORTED` (from Phase 2 metadata) or returned PA-FX-FAST in the preauth-required error.
5. Claims: request via PA-PAC-OPTIONS; compound identity verified through PAC_DEVICE_INFO presence in integration tests.
6. Tests: round-trips with fixture 9; `TestFASTEncryptedChallenge`, `TestFASTErrorUnwrap`, `TestFASTStrengthenKey`; Samba integration items 8–9; MIT `kdc-latest` FAST regression (MIT supports FAST — reuse containers).

Check: `go test ./...` green; MIT FAST test green; Samba FAST/claims tests green.

#### Phase 8 — KKDCP transport (KC-13)

Files: new `v8/client/kkdcp.go`, `v8/client/network.go`, `v8/config/krb5conf.go` (`kdc = https://…`, `kpasswd_server = https://…`), `v8/config/hosts.go`, `v8/kadmin/passwd.go` / `v8/client/passwd.go`, `v8/client/settings.go` (`HTTPClient`), tests with `httptest`, `USAGE.md`.

Steps:

1. `KDC-PROXY-MESSAGE` ASN.1 type in `v8/types` (Phase 0 may pre-add it) with marshal/unmarshal.
2. When a resolved KDC entry has scheme `https`, send via POST with 4-byte-length-prefixed message, `Content-Type: application/kerberos`, `target-domain` = realm; parse reply; map HTTP errors to `NetworkingError`.
3. Apply the same path to kpasswd when `kpasswd_server` is `https://`.
4. Tests: `TestKKDCPTransport` with an `httptest` server that unwraps and forwards to a fake KDC responder; config parsing tests; Samba integration item 10 with a `kdcproxy` sidecar.

Check: `go test ./client/... ./config/...` green; integration item 10 green.

#### Phase 9 — PKINIT compliant with MS-PKCA (KC-14, KP-1 … KP-9)

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

#### Phase 10 — Mechanism abstraction and NEGOEX (KN-1, KN-2, KN-4, KN-5)

Files: new `v8/gssapi/mechanism.go` (`ContextMechanism`, `Context` interfaces), `v8/gssapi/gssapi.go` (OIDs `OIDNegoEx`, `OIDPKU2U`), new package `v8/negoex/` (`message.go`, `vectors.go`, `conversation.go`, `verify.go`, `negoex_test.go`, `fuzz_test.go`), new `v8/spnego/mechanism.go` and tests, `v8/iana/keyusage/constants.go`; fixture and user documentation work completes with the PKU2U integration in Phases 11–12.

Steps:

1. Preserve `gssapi.Mechanism`; define the compatibility-safe byte-oriented `gssapi.ContextMechanism`/`gssapi.Context` boundary. Auth schemes provide their own directional NEGOEX keys; do not add a Kerberos-specific derivation or GUID because neither is standardized or implemented by MIT Kerberos.
2. Implement NEGOEX structures and vector encoding with strict bounds checks; `FuzzNegoExUnmarshal` seeded with fixture 13.
3. Implement the conversation state machine for initiator and acceptor (scheme intersection, optimistic `AP_REQUEST`, `CHALLENGE` loop, `VERIFY` computation/validation over the message log, `ALERT` handling, NTSTATUS mapping).
4. Add `spnego.Negotiator` over ordered `ContextMechanism` values; make the acceptor ignore an optimistic token for an unselected mechanism, continue with its preferred common mechanism, and protect a non-preferred selection with `mechListMIC`.
5. Tests: §4.3 `negoex` and `spnego` items, including a complete NEGOEX exchange inside SPNEGO and scenarios equivalent to MIT `negoextest`. Real Windows interop follows when PKU2U is registered in Phase 11.

Check: `go test ./gssapi/... ./negoex/... ./spnego/...` green; `go test -fuzz FuzzNegoExUnmarshal -fuzztime 30s ./negoex` clean; existing SPNEGO tests unchanged.

#### Phase 11 — PKU2U (KN-3)

Status: implemented for gokrb5-to-gokrb5 operation. Windows fixture 14 and the
two directional Windows interoperability runs remain external release gates;
no synthetic bytes are accepted as substitutes for those captures.

Files: new package `v8/pku2u/` (`names.go`, `metadata.go`, `initiator.go`, `acceptor.go`, `ticket.go`, `pku2u_test.go`, `fuzz_test.go`), `v8/pkinit` (export the AS-REQ/AS-REP PKINIT builders and reply-key derivation for reuse), `v8/negoex/scheme_pku2u.go`, `v8/credentials/credentials.go` (`CertificateIdentity` on the acceptor side), `v8/spnego/http.go` (acceptor option to enable PKU2U), `v8/test/testdata/mskile_vectors.go` (fixture 14), tests alongside, `USAGE.md`.

Steps:

1. Implement `WELLKNOWN:PKU2U` realm handling and certificate-to-principal mapping (UPN SAN, subject fallback) with unit tests.
2. Implement metadata encoding/decoding (trusted certifiers) and selection of a certificate acceptable to the peer.
3. Initiator: build the PKINIT AS-REQ for the acceptor name, process AS-REP, send AP-REQ with mutual flag; complete on AP-REP; derive the context key from the AP-REP subkey.
4. Acceptor: validate the initiator certificate (anchors + metadata), act as KDC — generate the ticket key, issue AS-REP with PA-PK-AS-REP (DH), retain the key for the conversation, verify AP-REQ, return AP-REP.
5. Register PKU2U as a NEGOEX scheme and as a standalone SPNEGO mechanism; expose `CertificateIdentity` in the HTTP context.
6. Tests: §4.3 `pku2u` items; gokrb5↔gokrb5 end-to-end over NEGOEX in CI; fixture 14 decode tests; Windows manual checklist entries.

Check: `go test ./pku2u/... ./negoex/... ./spnego/...` green; fuzz clean; end-to-end CI test green.

Implementation audit: PKU2U rejects non-AES AS offers and AP subkeys, requires
explicit PAC suppression and mutual authentication, validates both certificate
chains and mapped names, and uses the acceptor-asserted AP-REP subkey for RFC
4121 and NEGOEX. RFC 4121 coverage includes integrity and confidentiality,
MICs, replay rejection, arbitrary RRC values, reserved flag tolerance, and
AES-SHA1/AES-SHA2 enctypes. Generic HTTP continuation state uses random,
HttpOnly, two-minute exchange cookies rather than client network addresses.

#### Phase 12 — Samba AD DC CI, Windows manual suite, fuzz jobs, documentation (all EC items)

Status: implemented for locally testable and automated surfaces. CI provisions
a digest-pinned Samba AD DC and exercises password and machine logon, PAC
validation, disabled-account rejection, S4U2self, classic/RBCD S4U2proxy,
negative delegation, S4U delegation PAC data, and SPNEGO. All 13
parser/security-context fuzz targets run for 60 seconds in a matrix. On
2026-09-06 the pinned image was built locally and the full race-enabled,
`adintegration`-tagged suite passed against a freshly provisioned domain. The
pinned Samba image rejects disabled logon without Windows KERB-EXT-ERROR data
and does not provide interoperable required FAST. Those checks, Windows
IIS/RPC/CA, bidirectional PKU2U, fixture 14, claims, PKINIT, and KKDCP remain
external release gates and must not be represented as completed by synthetic
tests.

Required FAST was validated against live Windows AD with a keytab armor TGT:
the encrypted-challenge AS exchange and the subsequent armored TGS exchange
both pass under the race detector. FAST armor AP-REQ authenticators use key
usage 11, and RFC 6806 PA-REQ-ENC-PA-REP verification covers the exact outer
AS-REQ bytes sent on the wire with the strengthened reply key and usage 56.

Files: new `v8/test/testdata/docker/samba-ad-dc/` (Containerfile and provisioning script creating the automated accounts and exporting `krb5.keytab`, `user`, `pw`, and `environment` for `test/ad`), `.github/workflows/testingv8.yml` (quality, cross-platform unit, race, MIT integration, Samba AD, and 60-second fuzz jobs for every fuzz target), `v8/test/ad/ad.go` (environment kind and deterministic KDC/SPN/delegator overrides), new `v8/test/adintegration/ad_test.go` (build tag `adintegration`) implementing the automated subset of §4.4, `v8/USAGE.md`, `v8/README.md`, `v8/CHANGELOG.md`, this document (§7 resolutions, status → Implemented).

Steps:

1. Build and pin the Samba container; provision users, service accounts, delegation attributes, and the computer account; export test-only keytabs and credentials as runtime artifacts.
2. Implement §4.4 tests; each skips without the gate.
3. Add CI jobs; ensure runtime < 15 min.
4. Document every new API/setting; update feature tables; write the Windows manual-run checklist (`docs/design/ms-kile-windows-checklist.md`) including NEGOEX and PKU2U scenarios.
5. Re-audit: rerun the survey in §2 against the final code; every finding must map to a passing test or a §7 resolution.

Check: all §5 checkboxes ticked; CI green; Windows checklist executed once and recorded.

Implementation note: no `negoex-mit` job was added. MIT Kerberos does not
publish a standardized Kerberos NEGOEX auth-scheme GUID or the NEGOEX metadata
and key inquiry SPIs needed by such a harness. Kerberos remains directly
interoperable through SPNEGO; NEGOEX is automated through PKU2U's registered
scheme. Naming ordinary NEGOEX unit tests "MIT interoperability" would not add
an independent peer and would overstate coverage.

---

## Appendix B - Historical MIT compatibility review and implementation plan

Historical snapshot from the implemented MIT compatibility design. Original
section and phase numbers below refer to that specification. Its resolved
compatibility decisions take precedence over speculative original steps.

### 2. Current Implementation — Findings

Sources reviewed: [v8/keytab/keytab.go](../../v8/keytab/keytab.go), [v8/keytab/keytab_test.go](../../v8/keytab/keytab_test.go), [v8/credentials/ccache.go](../../v8/credentials/ccache.go), [v8/credentials/credentials.go](../../v8/credentials/credentials.go), [v8/client/client.go](../../v8/client/client.go), [v8/client/ASExchange.go](../../v8/client/ASExchange.go), [v8/client/session.go](../../v8/client/session.go), [v8/client/settings.go](../../v8/client/settings.go), [v8/crypto/crypto.go](../../v8/crypto/crypto.go), [v8/messages/KDCReq.go](../../v8/messages/KDCReq.go), [v8/messages/KDCRep.go](../../v8/messages/KDCRep.go), [v8/config/krb5conf.go](../../v8/config/krb5conf.go), [v8/types/PrincipalName.go](../../v8/types/PrincipalName.go).

#### 2.1 Keytab — what exists

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

#### 2.2 Keytab — defects and gaps to fix

Numbered for traceability (`KT-n`).

| ID | Historical finding | Historical severity | Phase 1 disposition and local evidence |
| --- | --- | --- | --- |
| KT-1 | `Unmarshal` discards the error returned by `parsePrincipal` (`parsePrincipal(eb, &p, kt, &ke, &endian)` with no assignment). A truncated principal silently yields a garbage entry. | High | Implemented; [`TestUnmarshalTruncatedPrincipalReturnsError`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-2 | `GetEncryptionKey` with `kvno == 0` selects the entry with the **newest timestamp**, not the **highest kvno**. MIT (`krb5_ktfile_get_entry`, `kt_file.c`) selects the highest kvno when kvno is unspecified. Merged keytabs with out-of-order timestamps produce different keys. | High | Implemented; [`TestGetEntryMITSemantics`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-3 | `GetEncryptionKey` requires an exact `etype` match; no wildcard (`etype == 0` → any) as in MIT. MIT also treats "similar" enctypes (e.g. DES variants) as matching — document as unsupported (DES not implemented). | Medium | Implemented; [`TestGetEntryMITSemantics`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-4 | `GetEncryptionKey` requires exact realm match. MIT matches any realm when the lookup principal's realm is empty. | Medium | Implemented; [`TestGetEntryMITSemantics`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-5 | `GetEncryptionKey` has no 8-bit kvno wrap-around handling. After failing to find an exact match, MIT accepts an entry whose parsed kvno is `kvno & 0xff`, regardless of whether the optional 32-bit field was present. | Low | Implemented; [`TestGetEntryKVNO8Fallback`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-6 | 32-bit kvno trailer handling is not recorded explicitly. MIT reads the optional trailer for both v1 and v2, using native byte order for v1, and ignores a zero trailer value. | Low | Implemented; [`TestUnmarshalV1KVNO32`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-7 | v1 round-trip is broken: `parsePrincipal` decrements `NumComponents` on read, `principal.marshal` writes it back unchanged, so v1 → marshal → v1 writes the wrong count. `NumComponents` should be derived from `len(Components)` at marshal time, not stored. | Medium | Implemented; [`TestUnmarshalV1RoundTrip`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-8 | `AddEntry` accepts `KVNO uint8`. kvnos > 255 are common (AD, long-lived service principals). MIT writes `vno & 0xff` to the 8-bit field and the full value to the 32-bit trailer. | High | Implemented; [`TestAddEntryHighKVNO`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-9 | `entry.String()` prints `KVNO8`, not `KVNO`. For kvno ≥ 256 the display is wrong (MIT `klist -k` shows the 32-bit value). | Medium | Implemented; [`TestAddEntryHighKVNO`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-10 | `AddEntry` derives the key with the RFC 4120 default salt only. No way to (a) supply a salt (AD host principals, `ktutil addent -salt`), (b) supply s2kparams/iterations, or (c) add an entry from raw key bytes (what `kadmin ktadd` does — it never has the password). | High | Implemented; [`TestAddKeyAndEntryWithSalt`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-11 | No API to **modify**: remove an entry, remove all entries for a principal, remove entries with kvno < N (`kadmin ktremove princ old`), keep-only-latest-kvno, or merge two keytabs (`ktutil rkt`+`wkt`). `Entries` is exported but its element type `entry` is unexported, so callers cannot construct or filter entries themselves. | High | Implemented; [`TestRemoveAndMerge`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-12 | No file-level write helper. MIT creates keytabs `0600`, uses `krb5_lock_file` while appending, and appends (never rewrites) on `ktadd`. gokrb5 needs `WriteFile(path)` with atomic write (temp + `rename`), `0600`, and an `Append`-safe path, otherwise concurrent `ktadd` from MIT tools can corrupt the file. | Medium | Implemented; [`TestWriteFileAtomicAndMode0600`](../../v8/keytab/file_test.go). Local evidence is not a live interoperability claim. |
| KT-13 | `Unmarshal` on a keytab that already has entries appends to `Entries` (no reset). Calling `Unmarshal` twice duplicates entries. | Low | Implemented; [`TestUnmarshalResetsEntries`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-14 | Error messages format raw bytes with `%s` (`fmt.Errorf("%s's length is less than %d", b, …)`), dumping binary key material into logs. | Medium (security) | Implemented; [`TestErrorsDoNotContainKeyMaterial`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-15 | Zero-length record (`l == 0`) terminates parsing. MIT and its file-format documentation define a zero-length record as EOF. | Low | Implemented; [`TestUnmarshalZeroLengthRecordIsEOF`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-16 | No default keytab resolution: `KRB5_KTNAME`, `KRB5_CLIENT_KTNAME`, `[libdefaults] default_keytab_name`, `default_client_keytab_name`, `FILE:`/`WRFILE:` prefix stripping, `%{euid}`/`%{uid}`/`%{username}` parameter expansion. `config.LibDefaults.DefaultKeytabName` is parsed but never used. | Medium | Implemented; [`TestResolveNameAndLoadDefault`](../../v8/keytab/file_test.go). Local evidence is not a live interoperability claim. |
| KT-17 | No `klist -kte`-compatible text rendering. Useful for diff-based interoperability tests and for a `gokrb5 klist -k` tool. | Low | Implemented; [`TestKlistMatchesCapturedOutput`](../../v8/keytab/klist_test.go). Local evidence is not a live interoperability claim. |
| KT-18 | No exported accessor for the keytab version, and no way to request writing v1 (MIT can still read v1; writing v1 is not required — read-only support is sufficient). | Low | Implemented; [`TestVersionAndPrincipals`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KT-19 | `JSON()` serialises raw key material. Acceptable but should be documented, and a redacted mode is preferable for logging. | Low | Implemented/documented: intentional raw-key JSON remains covered by [`TestStringJSONAndWrite`](../../v8/keytab/keytab_test.go); godoc now explicitly warns against logging or disclosure. |

#### 2.3 `kinit` — what exists

| Capability | Status | Location |
|---|---|---|
| AS exchange with password | Works: PA-ENC-TIMESTAMP, `KDC_ERR_PREAUTH_REQUIRED` retry, salt and s2kparams from ETYPE-INFO2 | `Client.Login`, `ASExchange`, `setPAData`, `crypto.GetKeyFromPassword` |
| AS exchange with keytab | Works when the keytab contains the etype the KDC selects | same, `Client.Key`, `ASRep.DecryptEncPart` |
| Client referrals (`KDC_ERR_WRONG_REALM`) | Works (max 5) | `ASExchange` |
| Load client state from a ccache | Works (v1–v4 read) | `credentials.LoadCCache`, `client.NewFromCCache` |
| TGT renewal | Works (TGS renew), auto-renew goroutine | `renewTGT`, `enableAutoSessionRenewal` |
| Options from krb5.conf | `forwardable`, `proxiable`, `canonicalize`, `ticket_lifetime`, `renew_lifetime`, `noaddresses`, `default_tkt_enctypes`, `kdc_default_options` | `messages.NewASReq` |
| Change password | `Client.ChangePasswd` (RFC 3244) | `client/passwd.go` |

#### 2.4 `kinit` — defects and gaps to fix

Numbered `KI-n`.

| ID | Historical finding | Historical severity | Phase 1 disposition and local evidence |
| --- | --- | --- | --- |
| KI-1 | **No ccache writer.** `credentials.CCache` has `Unmarshal` only. A `kinit` cannot exist without `Marshal`/`WriteFile` producing MIT FILE ccache v4 (header with KDC time-offset tag, default principal, credentials, `X-CACHECONF:` config entries). This is the largest gap. | Blocker | Implemented; [`TestCCacheMarshalByteExactFixtures`](../../v8/credentials/ccache_phase4_test.go). Local evidence is not a live interoperability claim. |
| KI-2 | `ccache.Unmarshal` and its `read*` helpers do no bounds checking; truncated or malicious ccache files panic. `parseHeader` compares an absolute offset (`*p`) with a relative length (`h.length`) — correct only by coincidence for the standard 12-byte header. | High | Implemented; [`TestCCacheReadHelpersBoundsAndValues`](../../v8/credentials/ccache_phase4_test.go). Local evidence is not a live interoperability claim. |
| KI-3 | `messages.NewASReq` overwrites `RTime`: `a.ReqBody.RTime = t.Add(c.LibDefaults.RenewLifetime)` is immediately followed by `a.ReqBody.RTime = t.Add(48 * time.Hour)`. `renew_lifetime`/`kinit -r` is ignored. | High | Implemented; [`TestNewASReqRenewLifetimeHonoured`](../../v8/messages/KDCReq_test.go). Local evidence is not a live interoperability claim. |
| KI-4 | `setPAData` derives the pre-auth etype from `LibDefaults.PreferredPreauthTypes[0]`. In MIT `preferred_preauth_types` is a list of **PA-DATA types** (17=PKINIT…, 16, 15, 14), not enctypes; it only "works" because 17 happens to be `aes128-cts-hmac-sha1-96`. Must use the first `DefaultTktEnctypeIDs` entry that the credential can produce a key for (for a keytab: an etype present in the keytab). | High | Implemented; [`TestFirstAvailablePreAuthKeyFallback`](../../v8/client/asexchange_phase5_test.go). Local evidence is not a live interoperability claim. |
| KI-5 | `crypto.GetKeyFromPassword` uses `ETYPE-INFO2[0]` / `ETYPE-INFO[0]` unconditionally and, when that etype differs from the requested one, derives the key with the **other** etype but labels the result with the requested `etypeID` (`key.KeyType = etypeID`). Must select the ETYPE-INFO2 entry whose etype equals the one being used, and set `KeyType` from the etype actually used. `client.preAuthEType` has the same `[0]` assumption. | High | Implemented; [`TestPreAuthETypeUsesFirstRequestedKDCOffer`](../../v8/client/asexchange_phase5_test.go). Local evidence is not a live interoperability claim. |
| KI-6 | With a keytab, the AS-REQ `etype` list is `DefaultTktEnctypeIDs` from config regardless of what keys the keytab holds. MIT (`krb5_get_init_creds_keytab`, `get_in_tkt.c`) restricts the request enctypes to those present in the keytab for the client principal, so the KDC never issues a reply the client cannot decrypt. | High | Implemented; [`TestETypesForPrincipal`](../../v8/keytab/keytab_test.go). Local evidence is not a live interoperability claim. |
| KI-7 | No interactive password prompt, no CLI. Need a `kinit`-equivalent command (proposed `v8/cmd/gokinit`) using `golang.org/x/term.ReadPassword` on `/dev/tty`, honouring `KRB5CCNAME`, `KRB5_CONFIG`, `KRB5_KTNAME`, `KRB5_CLIENT_KTNAME`. | High | Implemented; [`TestParseArgsMapsMITFlags`](../../v8/cmd/gokinit/main_test.go). Local evidence is not a live interoperability claim. |
| KI-8 | No default ccache name resolution: `KRB5CCNAME` → `[libdefaults] default_ccache_name` (with `%{uid}`, `%{euid}`, `%{username}`, `%{TEMP}` expansion) → `FILE:/tmp/krb5cc_%{uid}`. `FILE:` prefix must be accepted and stripped; other types must be rejected with a clear error. | High | Implemented; [`TestDefaultCCacheNameResolution`](../../v8/credentials/ccache_phase4_test.go). Local evidence is not a live interoperability claim. |
| KI-9 | Principal defaulting differs from MIT `kinit`: no principal → default principal of existing ccache, else `$USER@default_realm`; `-k` with no principal → `host/<canonical fqdn>@default_realm`; principal without `@REALM` → `default_realm`. `client.New*` documentation says an empty realm uses the default realm but `IsConfigured` rejects it. | Medium | Implemented; [`TestPrincipalDefaulting`](../../v8/client/client_test.go). Local evidence is not a live interoperability claim. |
| KI-10 | Clock skew: MIT retries the AS exchange once after `KRB_AP_ERR_SKEW`/`KDC_ERR_PREAUTH_FAILED` using the KDC time from the KRB-ERROR (`kdc_timesync`), and stores the offset in the ccache header (tag 1). gokrb5 has `KDCTimeSync` config but no implementation. | Medium | Implemented; [`TestClockSkewRetry`](../../v8/client/asexchange_phase5_test.go). Local evidence is not a live interoperability claim. |
| KI-11 | `KDC_ERR_KEY_EXPIRED`: MIT `kinit` prompts for a new password and retries. gokrb5 returns the error. Implement in the CLI using `Client.ChangePasswd`. | Low | Implemented; [`TestRenewAndPasswordChangeFailures`](../../v8/cmd/gokinit/main_test.go). Local evidence is not a live interoperability claim. |
| KI-12 | Enterprise principals (`kinit -E`, `KRB_NT_ENTERPRISE`): `credentials.New` splits the username on `/`; `types.ParseSPNString` splits on the last `@`. An enterprise name `user@corp.example@REALM` must become a single component with name type 10. | Low | Implemented; [`TestPrincipalDefaulting`](../../v8/client/client_test.go). Local evidence is not a live interoperability claim. |
| KI-13 | `Settings.DisablePAFXFAST` actually controls `PA_REQ_ENC_PA_REP` (RFC 6806 §11), not FAST. Rename/document; keep the old name as a deprecated alias. | Low | Implemented; [`TestFASTASExchangeRejectsUnarmoredReplyAfterActivation`](../../v8/client/fast_test.go). Local evidence is not a live interoperability claim. |
| KI-14 | Ticket-flag handling for `-f/-F`, `-p/-P`, `-a/-A`, `-C` (canonicalize), `-l`, `-r`, `-s` (start time / postdated), `-S service`, `-v` (validate) is only reachable via `config.LibDefaults`. The CLI needs per-invocation overrides that take precedence over krb5.conf. `-s` and `-v` may be deferred. | Medium | Implemented; [`TestParseArgsMapsMITFlags`](../../v8/cmd/gokinit/main_test.go). Local evidence is not a live interoperability claim. |
| KI-15 | ccache `GetEntries` filters `X-CACHECONF:` entries when loading; the writer must preserve MIT metadata semantics for `pa_type`, `fast_avail`, and `start_realm`. `refresh_time` belongs to GSS client-keytab refresh, not ordinary `kinit -k` output. | Medium | Implemented; [`TestCCacheCapturedConfigEntry`](../../v8/credentials/ccache_phase4_test.go). Local evidence is not a live interoperability claim. |
| KI-16 | Password-keytab preference: `Credentials.WithPassword` clears the keytab and vice versa. MIT `kinit -k` with a password-less principal must still work; `kinit` without `-k` must never read the keytab. Behaviour is compatible; add tests to lock it. | Low | Implemented; [`TestCredentialsPrincipalAndKeySources`](../../v8/credentials/credentials_test.go). Local evidence is not a live interoperability claim. |

---

### 6. Phased Implementation Plan (LLM-executable)

Each phase is independently mergeable, lists exact files, and ends with a verifiable check. Do not start a phase before the previous phase's check passes. Keep changes minimal and within the listed files unless a compile error forces otherwise. Follow repository conventions: tests use `testify/assert`, fixtures live in `v8/test/testdata/test_vectors.go` as string constants, integration tests call `test.Integration(t)` first.

#### Phase 0 — Fixture capture (no library code changes)

Files: `v8/test/testdata/test_vectors.go`, `v8/test/testdata/README.md` (new; documents generation commands and MIT version).

Steps:
1. Write a shell script `v8/test/testdata/gen/mit_fixtures.sh` that, given `ktutil`, `kadmin.local`, `kinit`, `klist`, `kvno` on PATH and the `kdc-centos-default` container, produces every fixture in §4.2 as hex, plus captured `klist -kte` text.
2. Run it (or, if MIT tools are unavailable in the current environment, hand-assemble fixtures strictly per the keytab/ccache format specifications and mark them `// SPEC-DERIVED — replace with MIT capture`).
3. Add constants `KEYTAB_*`, `CCACHE_*`, `KLIST_*` to `test_vectors.go`.

Check: `go vet ./v8/...` passes; each constant decodes from hex without error in a trivial test `TestFixturesDecode`.

#### Phase 1 — Keytab read correctness (KT-1, KT-6, KT-7, KT-13, KT-14, KT-15)

Files: `v8/keytab/keytab.go`, `v8/keytab/keytab_test.go`.

Steps:
1. Capture and return the error from `parsePrincipal` in `Unmarshal`.
2. Read the optional 32-bit kvno trailer for both versions, in the version's byte order; record on the entry (unexported bool `kvno32Present`) whether it was present.
3. Stop storing `NumComponents`; compute in `principal.marshal` (`len(Components)`, `+1` if v1). Keep the struct field for one release but ignore it (`json:"-"`), or remove if no external usage — check with `grep -r NumComponents` in the module.
4. `Unmarshal` sets `kt.Entries = nil` before parsing.
5. Replace every `%s` of a byte slice in error messages with the length or offset only.
6. Zero-length record: after verifying MIT behaviour in `kt_file.c`, either continue (skip 4 bytes) or stop; encode the decision in a test with the fixture from §4.2 item 5.
7. Add tests: `TestUnmarshal_AllFixtures`, `TestUnmarshal_TruncatedPrincipalReturnsError`, `TestUnmarshal_V1RoundTrip`, `TestUnmarshal_ResetsEntries`, `TestUnmarshal_HoleSkipping`, `TestUnmarshal_HoleAtEOF`, `TestErrorsDoNotContainKeyMaterial`, `FuzzUnmarshal`.

Check: `go test ./v8/keytab/...` green; `go test -run XXX -fuzz FuzzUnmarshal -fuzztime 30s ./v8/keytab` no crashes.

#### Phase 2 — Exported model and MIT lookup semantics (KT-2, KT-3, KT-4, KT-5, KT-8, KT-9)

Files: `v8/keytab/keytab.go`, `v8/keytab/keytab_test.go`, callers: `v8/credentials/credentials.go`, `v8/client/client.go`, `v8/messages/KDCRep.go`, `v8/service/*.go` (grep `GetEncryptionKey` and `kt.Entries`).

Steps:
1. Rename `entry` → `Entry`, `principal` → `Principal`; add `type entry = Entry`, `type principal = Principal` aliases marked deprecated.
2. Remove `KVNO8` from `Entry`; derive in marshal/unmarshal. Fix `Entry.String()` to print `KVNO`.
3. Widen `AddEntry`'s `KVNO` parameter to `uint32`. (Breaking for callers passing `uint8` literals? Untyped constants still compile; typed `uint8` variables need a cast — acceptable, document in CHANGELOG.)
4. Implement `GetEntry` with rules §3.1.5, define `ErrNotFound`, `ErrKVNONotFound`; rewrite `GetEncryptionKey` to delegate.
5. Add `Version()`, `Principals()`, `ParsePrincipal`, `Principal.String()` with MIT escaping (`\/`, `\@`, `\\`, `\n`, `\t`, `\b`, `\0`).
6. Tests listed in §4.3 for `GetEntry_*`, `TestMarshal_ByteExactVsKtutil` extended to kvno 300 (fixture 2) and all etypes (fixture 1).

Check: `go build ./v8/... && go test ./v8/...` green (non-integration); `grep -rn "KVNO8" v8/ | grep -v _test.go` returns nothing.

#### Phase 3 — Keytab create/modify/write API (KT-10, KT-11, KT-12, KT-16, KT-17)

Files: `v8/keytab/keytab.go`, new `v8/keytab/file.go` (WriteFile/AppendToFile/locking), new `v8/keytab/file_unix.go` + `file_windows.go` (flock shim), new `v8/keytab/default.go` (name resolution), new `v8/keytab/klist.go`, tests alongside.

Steps:
1. Implement `AddKey`, `AddEntryWithSalt`, `RemoveEntry`, `RemovePrincipal`, `RemoveOldKVNO`, `Merge`.
2. Implement `WriteFile` (temp+rename, 0600, fsync) and `AppendToFile` (O_APPEND|O_CREATE 0600, flock on Unix, header written if file size is 0).
3. Implement `LoadDefault`, `LoadDefaultClient`, `ResolveName(name string, cfg *config.Config) (path string, writable bool, err error)` with prefix handling and `%{euid}`/`%{uid}`/`%{username}` expansion. Add `DefaultClientKeytabName` parsing to `config.LibDefaults` (`default_client_keytab_name`) in `v8/config/krb5conf.go` if absent.
4. Implement `Klist(showTimestamps, showKeys, showEtypes bool)`; etype names must come from a single table — add `iana/etypeID.ETypeToString`-style map if none exists (check `v8/iana/etypeID`).
5. Tests: §4.3 keytab items for add/remove/merge/write/append/default/klist.

Check: `go test ./v8/keytab/...` green including `TestAppendToFile_ConcurrentWriters`; `TestKlist_MatchesCapturedOutput` byte-equal against fixture 15.

#### Phase 4 — CCache hardening and writer (KI-1, KI-2, KI-8, KI-15)

Files: `v8/credentials/ccache.go`, new `v8/credentials/ccache_marshal.go`, new `v8/credentials/ccache_default.go`, `v8/credentials/ccache_test.go`, `v8/config/krb5conf.go` (`default_ccache_name` parsing if missing).

Steps:
1. Make all `read*` helpers return `error`; propagate; fix `parseHeader` offset arithmetic; skip unknown header tags.
2. Implement `Marshal` (v3 and v4), `WriteFile`, `NewCCache`, `AddCredential`, `SetConfig`/`GetConfig`, `KDCTimeOffset`/`SetKDCTimeOffset`.
3. Implement `DefaultCCacheName(cfg)`.
4. Tests: §4.3 credentials items; `FuzzCCacheUnmarshal`.

Check: `go test ./v8/credentials/...` green; round-trip of fixtures 10–14 byte-identical.

#### Phase 5 — AS exchange corrections (KI-3, KI-4, KI-5, KI-6, KI-9, KI-10, KI-13)

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

#### Phase 6 — `gokinit`, `goklist`, `gokdestroy` commands (KI-7, KI-11, KI-12, KI-14)

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

#### Phase 7 — Interop test suite and CI (all EC items)

Files: new `v8/test/interop/*_test.go` (build tag `interop`), `.github/workflows/testingv8.yml`.

Steps:
1. Implement interop tests §4.4 items 1–9; each `t.Skip`s when a required binary is missing.
2. CI: install `krb5-user`/`krb5-workstation` on the runner; add a job step `INTEGRATION=1 go test -tags interop ./v8/test/interop/...`.
3. Add `-fuzztime 60s` fuzz jobs for the two fuzz targets.
4. Update `v8/USAGE.md` (keytab management, ccache export, `gokinit`) and `v8/README.md` feature table; add CHANGELOG entry listing deprecated aliases and the `AddEntry` kvno type change.

Check: all §5 checkboxes ticked; CI green on every Go version in the matrix.

---

## Appendix C - Consolidated historical test coverage plan

Historical baseline and workstream detail. The current measured baseline and
active execution order are Sections 1-4 above; the strict combined coverage
goal remains a goal, not a claim of completion.

### Test Coverage Plan

**Status:** Active

**Scope:** `v8` module (`github.com/otuschhoff/gokrb5/v8`)

**Baseline:** 70.9% cross-package statement coverage on 2026-09-07, measured with:

```sh
go test -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

#### Goals

Coverage work must reduce protocol, security, interoperability, and portability risk. A higher aggregate percentage is not sufficient if authentication state machines, untrusted decoders, cryptographic failure paths, or persistent writes remain untested.

Completion requires:

1. 100% combined repository-wide statement coverage across unit, integration, subprocess, version-specific, and supported-platform test jobs.
2. At least 90% statement coverage for security-critical parsers, cryptographic message operations, network framing, and authentication state transitions.
3. No untested rejection branch for attacker-controlled lengths, tags, checksums, signatures, or message ordering.
4. Native Linux, Windows, and macOS tests; compile checks for supported mobile targets; and documented platform-specific exclusions.
5. MIT Kerberos, Samba AD, and Windows AD interoperability coverage for behavior that cannot be represented faithfully by unit fixtures.

Generated constants, platform-inapplicable branches, and wrappers that only delegate may be excluded from local targets, but exclusions must be documented and must not hide protocol behavior.

#### Phase 1: Guard the Current Baseline

Status: implemented.

- Collect coverage with `-coverpkg=./...` so calls through public wrappers count toward internal packages.
- Publish `coverage.out` from CI for function-level inspection.
- Fail CI below 70.0%. The floor is intentionally below the 70.9% baseline to tolerate minor instrumentation differences across Go releases.
- Cover hardened TCP and UDP framing, endpoint failover, malformed ciphertext, scanner failures, HTTP body failures, atomic persistence, FAST hint parsing, and PKINIT revocation evidence.

Exit gate: CI cannot merge a material aggregate coverage regression, and every defect fixed by the error-hardening initiative has a regression test where failure can be injected deterministically.

#### Phase 2: Untrusted Decoders and Cryptography

- Raise `asn1tools`, `messages`, `types`, `pac/internal/ndr`, `keytab`, and `credentials` parser coverage with table-driven truncation, oversized-length, trailing-data, invalid-tag, and integer-boundary cases.
- Exercise each supported enctype through encrypt/decrypt round trips, known-answer vectors, integrity corruption, wrong key usage, short ciphertext, and injected primitive failures.
- Seed every parser fuzz target with valid minimal and representative AD/MIT messages, then assert that malformed input never panics or allocates beyond established limits.
- Add corpus minimization and a scheduled fuzz workflow with retained crash artifacts.

Exit gate: security-critical decoder and crypto operations reach 90%; every wire-format decoder has unit tests and a fuzz target or a documented reason it cannot be fuzzed independently.

#### Phase 3: Authentication State Machines

- Introduce scripted in-process KDC transports for AS, TGS, referrals, FAST, PKINIT, S4U, password expiry, clock skew, UDP-to-TCP fallback, and retry exhaustion.
- Cover valid and invalid transition ordering, replay, nonce mismatch, downgrade attempts, missing required padata, and typed KRB errors.
- Exercise SPNEGO, NEGOEX, PKU2U, GSS MIC/wrap, channel bindings, delegation, and mutual-authentication success and rejection paths with deterministic peers.
- Test cancellation and deadlines at each network and HTTP boundary.

Exit gate: `client`, `service`, and `spnego` each reach 75% overall; security-sensitive state-transition functions reach 90%; all retry loops have success, terminal-error, and exhaustion tests.

#### Phase 4: KDC Interoperability

- Run the existing MIT and Samba AD suites for every protocol-affecting pull request.
- Add a maintained Windows AD matrix covering AES-SHA1/SHA2, FAST AS/TGS, PKINIT, referrals, S4U2self/S4U2proxy/RBCD, PAC validation, KKDCP, and password-change flows.
- Capture sanitized protocol fixtures from successful interoperability runs for deterministic offline regression tests.
- Test mixed-version and policy failures, including disabled enctypes, required FAST, revoked certificates, clock skew, and constrained-delegation denial.

Exit gate: all documented features have at least one automated interoperability path; Windows-only manual cases are tracked with an owner, environment requirements, and last successful date.

#### Phase 5: Platform Behavior

- Keep native unit and race tests on Linux, Windows, and macOS.
- Add platform-specific filesystem tests for locking, atomic replacement, permissions, path expansion, and credential cache conventions.
- Add Android emulator tests for DNS, TCP/UDP, HTTPS proxying, and application-provided credential storage.
- Add iOS simulator/device builds on a macOS runner with Xcode, then test networking and application-container file behavior.

Exit gate: every claimed runtime platform has native execution coverage. Compile-only targets remain explicitly labeled until a suitable runner exists.

#### Phase 6: Ratchet and Maintenance

- Raise the aggregate CI floor in small increments as each phase lands; never lower it to merge a change.
- Review function-level coverage for every security-sensitive change and require a regression test for every fixed defect.
- Track unit, integration, fuzz, and interoperability results separately so one category cannot mask regressions in another.
- Periodically remove obsolete exclusions and stale fuzz corpus entries.

Exit gate: repository coverage is at least 80%, critical paths remain at least 90%, and CI reports each test category independently.

#### Phase 7: Strict 100% Combined Coverage

- Maintain a machine-readable inventory of every uncovered statement, its owning package, and the job expected to execute it. The inventory must fail CI when a new uncovered block has no owner.
- Refactor command entry points into testable `run` functions that accept arguments, streams, environment access, and exit-code reporting; retain `main` only as a minimal `os.Exit(run(...))` wrapper and cover wrappers with subprocess tests.
- Inject terminal, clock, randomness, filesystem, DNS, network, and process dependencies where deterministic failure or cancellation cannot otherwise be induced.
- Collect coverage from Linux unit tests, CLI subprocess tests, MIT and Samba integration suites, Windows AD release tests, supported Go-version jobs, and native Windows and macOS jobs. Merge profiles by source block before enforcing the combined threshold.
- Exercise each build-tagged implementation on a matching runner. A file absent from one platform's build is not considered excluded when another supported runner can compile it.
- Remove unreachable error branches only when the underlying operation is provably infallible and the public API remains compatible. Do not use coverage-ignore comments, generated profiles, empty assertions, or reduced `-coverpkg` scope.
- Raise package and aggregate floors monotonically after each deterministic, integration, subprocess, and platform tranche reaches its target.

Exit gate: every instrumentable production statement is executed by at least one required CI job, the merged profile reports 100.0%, every package reports 100.0%, and all platform-specific implementations meet the same standard on their native runner.
