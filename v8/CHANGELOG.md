# Changelog

## [v8.6.0] - 2026-11-21

### Upgrade notes

- The minimum Go version remains **1.26.0**. The module path is
  `github.com/otuschhoff/gokrb5/v8`.
- The built-in client enctype lists now contain only AES. If your deployment
  still needs RC4 or Triple-DES, explicitly list the required enctypes and set
  `allow_weak_crypto = true` in `[libdefaults]`. The flag alone does not add
  them. The exported `config.WeakETypeList` constant retains its v8.5.4 value.
- The legacy SPNEGO HTTP client requires `http.Request.GetBody` when it needs
  to replay a nonempty body during authentication. The authentication exchange
  is limited to ten round trips, with a separate redirect budget per request.

### Added

- `client.KDCTimeOffset` sets an initial client offset for KDC clock skew.
- New GSS interfaces describe token-based contexts, message protection, and
  NEGOEX key export. NEGOEX exports `ErrInvalidConversationState`.
- CI verifies certificate-only PKINIT against a pinned Samba AD fixture with
  MIT Kerberos. The test requires an RFC 8636 KDF and has verified SHA-256;
  it does not cover native Windows AD or Samba with Heimdal.

### Changed

- KDC and password-change SRV discovery uses Go's standard resolver instead
  of `dnsutils/v2`. Gorilla session support remains in the checkout examples,
  outside the v8 library module.
- Selected DER encoders, including RFC 8636 KDF principal encoding, now use
  the standard library. `gofork` remains for public types, legacy decoding,
  and other compatibility requirements.
- More crypto, protocol, and I/O errors preserve their causes for
  `errors.Is` and `errors.As`, including failures during cleanup.

### Fixed

- Receive UDP KDC replies larger than 4 KiB without silently truncating them.
- Close intermediate HTTP negotiation responses without taking ownership of
  the final response body. Reopen replayable bodies when following redirects.
- Make replay-cache checks and updates atomic and distinguish exact client
  principals, realms, and services.
- Bound PAC/NDR multidimensional array handling and return errors for invalid
  decode targets rather than panicking in reflection.
- Return errors when exporting an incompletely initialized client or
  importing a nil credential cache.

For earlier changes, see the [changelog at v8.5.4].

[v8.6.0]: https://github.com/otuschhoff/gokrb5/compare/v8.5.4...v8.6.0
[changelog at v8.5.4]: https://github.com/otuschhoff/gokrb5/blob/v8.5.4/v8/CHANGELOG.md
