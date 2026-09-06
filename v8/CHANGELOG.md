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

### Changed

- The minimum Go version is now 1.18, matching the supported CI matrix and
  native parser fuzz tests.
- `keytab.Keytab.AddEntry` now accepts a `uint32` KVNO so values greater than
  255 can be represented. Calls using typed `uint8` values require conversion.

### Deprecated

- The unexported compatibility aliases `keytab.entry` and `keytab.principal`
  remain available inside the package while callers migrate to `keytab.Entry`
  and `keytab.Principal`.
- `client.DisablePAFXFAST` remains as an alias for
  `client.DisablePAReqEncPARep`.