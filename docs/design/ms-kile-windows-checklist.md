# MS-KILE Windows interoperability checklist

Record the Windows build, gokrb5 commit, certificate templates, test CA
thumbprints, DNS names, and capture file names with every run. Use disposable
keys and sanitize captures before committing fixtures.

## PKU2U prerequisites

- Two identities chain to an explicitly configured test CA.
- The initiator certificate contains a UPN SAN.
- The acceptor certificate contains the target host in a DNS SAN.
- Both peers have synchronized clocks.
- RC4 is disabled; AES 17, 18, 19, or 20 is negotiated.
- Packet capture and application logs are enabled on both peers.

## Windows initiator to gokrb5 acceptor

1. Configure the gokrb5 HTTP handler with `SPNEGOContextAuthenticate`, NEGOEX,
   and a fresh `pku2u.NewAcceptor` from its mechanism factory.
2. Access the handler from Windows using Negotiate authentication.
3. Confirm SPNEGO selects NEGOEX and auth scheme
   `235f69ad-73fb-4dbc-8203-0629e739339b`.
4. Confirm both trusted-certifier metadata messages decode and identify the
   configured test CA.
5. Confirm AS-REQ uses `WELLKNOWN:PKU2U`, contains one `PA-PK-AS-REQ`, and
   contains exactly one `KERB-PA-PAC-REQUEST` with `include-pac = false`.
6. Confirm AS-REP uses DH PKINIT and an AES reply/session key.
7. Confirm AP-REQ requests mutual authentication and contains the RFC 4121
   authenticator checksum and an AES subkey.
8. Confirm AP-REP is accepted, NEGOEX VERIFY succeeds, and the HTTP request
   context exposes the Windows certificate UPN and verified chain.
9. Exchange RFC 4121 integrity, confidentiality, and MIC tokens in both
   directions and verify replay and tamper rejection.

## gokrb5 initiator to Windows acceptor

1. Configure `NewNegotiatingClient` with NEGOEX and a fresh
   `pku2u.NewInitiator` from its mechanism factory.
2. Authenticate to a Windows Negotiate endpoint using the certificate target
   name from its DNS SAN.
3. Repeat the metadata, AS, AP, NEGOEX VERIFY, and RFC 4121 checks above.
4. Record whether Windows emits an AP-REP acceptor subkey. If present, confirm
   subsequent tokens set `AcceptorSubkey`; if absent, preserve the capture for
   an implementation decision before changing gokrb5 behavior.
5. Repeat with AES-SHA1 and AES-SHA2 certificate exchanges where Windows policy
   permits both.

## Negative scenarios

Each scenario must fail authentication without NTLM fallback or an authenticated
application request:

- Untrusted initiator certificate.
- Untrusted acceptor certificate.
- Acceptor certificate DNS SAN does not match the target.
- Initiator UPN does not match the PKU2U client principal.
- Expired or revoked certificate with revocation checking enabled.
- Missing, duplicate, malformed, or true PAC request.
- Wrong realm, stale authenticator, missing mutual flag, missing GSS checksum,
  missing AP subkey, RC4-only AS request, or RC4 AP subkey.
- Tampered metadata, AS-REP, ticket, authenticator, AP-REP, NEGOEX VERIFY, wrap
  token, or MIC token.
- Two simultaneous exchanges from the same client address remain isolated;
  an abandoned HTTP exchange expires after two minutes.

## Fixture 14 capture

Capture and sanitize these exact artifacts for `v8/test/testdata`:

- `PKU2U_WIN_METADATA_INITIATOR`
- `PKU2U_WIN_METADATA_ACCEPTOR`
- `PKU2U_WIN_AS_REQ`
- `PKU2U_WIN_AS_REP`
- `PKU2U_WIN_AP_REQ`
- `PKU2U_WIN_AP_REP`
- NEGOEX conversation messages and the context key needed to recompute VERIFY
- Certificate chain, DH private values or deterministic test keys, and expected
  mapped principals

Fixtures must decode and re-encode byte-for-byte and permit independent reply
key, AP-REP, NEGOEX VERIFY, and RFC 4121 token verification.
