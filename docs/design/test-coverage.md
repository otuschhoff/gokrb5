# Test Coverage Plan

**Status:** Active

**Scope:** `v8` module (`github.com/otuschhoff/gokrb5/v8`)

**Baseline:** 68.5% cross-package statement coverage on 2026-09-07, measured with:

```sh
go test -covermode=atomic -coverpkg=./... -coverprofile=coverage.out ./...
go tool cover -func=coverage.out
```

## Goals

Coverage work must reduce protocol, security, interoperability, and portability risk. A higher aggregate percentage is not sufficient if authentication state machines, untrusted decoders, cryptographic failure paths, or persistent writes remain untested.

Completion requires:

1. 100% combined repository-wide statement coverage across unit, integration, subprocess, version-specific, and supported-platform test jobs.
2. At least 90% statement coverage for security-critical parsers, cryptographic message operations, network framing, and authentication state transitions.
3. No untested rejection branch for attacker-controlled lengths, tags, checksums, signatures, or message ordering.
4. Native Linux, Windows, and macOS tests; compile checks for supported mobile targets; and documented platform-specific exclusions.
5. MIT Kerberos, Samba AD, and Windows AD interoperability coverage for behavior that cannot be represented faithfully by unit fixtures.

Generated constants, platform-inapplicable branches, and wrappers that only delegate may be excluded from local targets, but exclusions must be documented and must not hide protocol behavior.

## Phase 1: Guard the Current Baseline

Status: implemented.

- Collect coverage with `-coverpkg=./...` so calls through public wrappers count toward internal packages.
- Publish `coverage.out` from CI for function-level inspection.
- Fail CI below 67.0%. The floor is intentionally below the 68.5% baseline to tolerate minor instrumentation differences across Go releases.
- Cover hardened TCP and UDP framing, endpoint failover, malformed ciphertext, scanner failures, HTTP body failures, atomic persistence, FAST hint parsing, and PKINIT revocation evidence.

Exit gate: CI cannot merge a material aggregate coverage regression, and every defect fixed by the error-hardening initiative has a regression test where failure can be injected deterministically.

## Phase 2: Untrusted Decoders and Cryptography

- Raise `asn1tools`, `messages`, `types`, `pac/internal/ndr`, `keytab`, and `credentials` parser coverage with table-driven truncation, oversized-length, trailing-data, invalid-tag, and integer-boundary cases.
- Exercise each supported enctype through encrypt/decrypt round trips, known-answer vectors, integrity corruption, wrong key usage, short ciphertext, and injected primitive failures.
- Seed every parser fuzz target with valid minimal and representative AD/MIT messages, then assert that malformed input never panics or allocates beyond established limits.
- Add corpus minimization and a scheduled fuzz workflow with retained crash artifacts.

Exit gate: security-critical decoder and crypto operations reach 90%; every wire-format decoder has unit tests and a fuzz target or a documented reason it cannot be fuzzed independently.

## Phase 3: Authentication State Machines

- Introduce scripted in-process KDC transports for AS, TGS, referrals, FAST, PKINIT, S4U, password expiry, clock skew, UDP-to-TCP fallback, and retry exhaustion.
- Cover valid and invalid transition ordering, replay, nonce mismatch, downgrade attempts, missing required padata, and typed KRB errors.
- Exercise SPNEGO, NEGOEX, PKU2U, GSS MIC/wrap, channel bindings, delegation, and mutual-authentication success and rejection paths with deterministic peers.
- Test cancellation and deadlines at each network and HTTP boundary.

Exit gate: `client`, `service`, and `spnego` each reach 75% overall; security-sensitive state-transition functions reach 90%; all retry loops have success, terminal-error, and exhaustion tests.

## Phase 4: KDC Interoperability

- Run the existing MIT and Samba AD suites for every protocol-affecting pull request.
- Add a maintained Windows AD matrix covering AES-SHA1/SHA2, FAST AS/TGS, PKINIT, referrals, S4U2self/S4U2proxy/RBCD, PAC validation, KKDCP, and password-change flows.
- Capture sanitized protocol fixtures from successful interoperability runs for deterministic offline regression tests.
- Test mixed-version and policy failures, including disabled enctypes, required FAST, revoked certificates, clock skew, and constrained-delegation denial.

Exit gate: all documented features have at least one automated interoperability path; Windows-only manual cases are tracked with an owner, environment requirements, and last successful date.

## Phase 5: Platform Behavior

- Keep native unit and race tests on Linux, Windows, and macOS.
- Add platform-specific filesystem tests for locking, atomic replacement, permissions, path expansion, and credential cache conventions.
- Add Android emulator tests for DNS, TCP/UDP, HTTPS proxying, and application-provided credential storage.
- Add iOS simulator/device builds on a macOS runner with Xcode, then test networking and application-container file behavior.

Exit gate: every claimed runtime platform has native execution coverage. Compile-only targets remain explicitly labeled until a suitable runner exists.

## Phase 6: Ratchet and Maintenance

- Raise the aggregate CI floor in small increments as each phase lands; never lower it to merge a change.
- Review function-level coverage for every security-sensitive change and require a regression test for every fixed defect.
- Track unit, integration, fuzz, and interoperability results separately so one category cannot mask regressions in another.
- Periodically remove obsolete exclusions and stale fuzz corpus entries.

Exit gate: repository coverage is at least 80%, critical paths remain at least 90%, and CI reports each test category independently.

## Phase 7: Strict 100% Combined Coverage

- Maintain a machine-readable inventory of every uncovered statement, its owning package, and the job expected to execute it. The inventory must fail CI when a new uncovered block has no owner.
- Refactor command entry points into testable `run` functions that accept arguments, streams, environment access, and exit-code reporting; retain `main` only as a minimal `os.Exit(run(...))` wrapper and cover wrappers with subprocess tests.
- Inject terminal, clock, randomness, filesystem, DNS, network, and process dependencies where deterministic failure or cancellation cannot otherwise be induced.
- Collect coverage from Linux unit tests, CLI subprocess tests, MIT and Samba integration suites, Windows AD release tests, supported Go-version jobs, and native Windows and macOS jobs. Merge profiles by source block before enforcing the combined threshold.
- Exercise each build-tagged implementation on a matching runner. A file absent from one platform's build is not considered excluded when another supported runner can compile it.
- Remove unreachable error branches only when the underlying operation is provably infallible and the public API remains compatible. Do not use coverage-ignore comments, generated profiles, empty assertions, or reduced `-coverpkg` scope.
- Raise package and aggregate floors monotonically after each deterministic, integration, subprocess, and platform tranche reaches its target.

Exit gate: every instrumentable production statement is executed by at least one required CI job, the merged profile reports 100.0%, every package reports 100.0%, and all platform-specific implementations meet the same standard on their native runner.
