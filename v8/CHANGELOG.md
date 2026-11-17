# Changelog

## Unreleased

### Added

- MIT-compatible keytab creation, modification, lookup, default-path, locking,
  and display APIs.
- Hardened MIT FILE ccache parsing plus creation, configuration metadata,
  KDC-time-offset, atomic writing, and client export support.
- Per-request AS exchange options, keytab enctype negotiation, KDC clock-skew
  recovery, typed principal construction, service-only cache round trips, and
  explicit TGT renewal.
- `gokinit`, `goklist`, and `gokdestroy` command-line tools.
- MIT Kerberos interoperability and parser fuzz test suites.
- Complete PAC buffer 16-19 parsing, deterministic PAC marshaling and signing,
  UPN/DNS SAM and SID extensions, and options-aware checksum verification.
- Ticket-bound PAC identity validation and expanded Active Directory
  credentials for claims, device, delegation, requestor, and SID metadata.
- MS-SFU S4U2self, S4U2proxy, resource-based constrained delegation, referral
  handling, user-specific ticket caching, and typed policy errors.
- FAST armor settings `FASTArmor`, `FASTArmorWithIdentity`,
  `FASTArmorFromKeytab`, and `RequireFAST`, including encrypted challenge,
  armored errors, cookies, and reply-key strengthening.
- MS-KKDCP HTTPS transport and the `KKDCPClient` setting.
- PKINIT DH and RSA authentication with certificate policy, KDF negotiation,
  freshness, OCSP, and the `PKINITIdentity`, `PKINITAnchors`,
  `PKINITKDCCertificatePolicy`, `PKINITMode`, `PKINITMinimumDHBits`,
  `PKINITRequireFreshness`, and `PKINITOCSPResponse` settings.
- GSS channel bindings, extended-protection policy, service-principal binding,
  delegation, mutual authentication, DCE style, and RFC 4121 security contexts.
- Generic multi-round SPNEGO, NEGOEX, and AES-only PKU2U certificate
  authentication for initiators and acceptors.
- A pinned Samba AD integration environment, `adintegration` test suite,
  `TESTAD_KIND` environment classification, deterministic KDC/SPN overrides,
  and 60-second CI jobs for every fuzz target.

### Changed

- Legacy HTTP authentication now requires `Request.GetBody` to replay a request
  body, matching the generic negotiating client; unsafe partial tee-buffer
  replay is no longer attempted. Authentication is limited to ten round trips,
  with redirect budgets isolated per request.
- Error chains preserve underlying causes across crypto, protocol decoding,
  endpoint failover, and cleanup, allowing `errors.Is`/`errors.As` inspection.
- Client diagnostics return JSON encoding and output failures, including short
  writes. The signature-compatible `Print` method stops and logs failures
  through the configured logger.
- The minimum Go version is now 1.18, matching the supported CI matrix and
  native parser fuzz tests.
- `keytab.Keytab.AddEntry` now accepts a `uint32` KVNO so values greater than
  255 can be represented. Calls using typed `uint8` values require conversion.

### Fixed

- Preserve primary and cleanup failures during atomic keytab/ccache replacement,
  keytab append/unlock, KDC connection closure, and HTTPS response closure.
- Receive UDP KDC replies larger than 4 KiB without silently truncating them.
- Retain NDR malformed-stream classification and underlying truncation errors,
  and reject invalid decode targets or unsettable fields without reflection
  panics.
- Close intermediate HTTP negotiation responses on failure without taking
  ownership of final returned bodies; reopen redirected file bodies correctly.
- Return explicit errors when exporting an incompletely initialized client or
  importing a nil credential cache.
- Decode empty multidimensional NDR arrays without indexing element zero, bound
  dimension products before allocation, and honor conformant-varying offsets.
- Retain NDR alignment and union-discriminant read errors instead of discarding
  them.
- Make replay-cache checks and updates atomic, retain updated authenticator
  metadata, and isolate records by client realm, exact principal components,
  service, and authenticator time.

### Deprecated

- The unexported compatibility aliases `keytab.entry` and `keytab.principal`
  remain available inside the package while callers migrate to `keytab.Entry`
  and `keytab.Principal`.
- `client.DisablePAFXFAST` remains as an alias for
  `client.DisablePAReqEncPARep`.