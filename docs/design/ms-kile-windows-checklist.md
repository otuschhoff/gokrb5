# MS-KILE Windows interoperability checklist

Record the Windows build, gokrb5 commit, certificate templates, test CA
thumbprints, DNS names, and capture file names with every run. Use disposable
keys and sanitize captures before committing fixtures.

## Run record

- Date: not executed
- Windows build and domain functional level: not recorded
- gokrb5 commit: not recorded
- Domain, KDC, IIS, RPC, KKDCP, and service host names: not recorded
- Test CA and certificate templates: not recorded
- Capture and log files: not recorded

Do not change the run record to "passed" until every applicable item below has
an attached log or sanitized capture.

## Kerberos and account policy

1. Run the `adintegration` suite with `TESTAD=1`, `TESTAD_KIND=windows`, an
   explicit realm/KDC, and the Windows test credential files.
2. Confirm enterprise-name logon accepts the canonicalized reply name and the
   resulting TGT obtains a usable service ticket.
3. Run disabled, locked, expired-password, and expired-account identities.
   Record the KDC error and verify each exposed `NTStatus()` value.
4. Obtain and validate an AES service ticket and PAC. Record effective name,
   UPN, user SID, group SIDs, requestor SID, attributes, and checksum types.
5. Confirm mixed-case realm configuration behaves identically.

## S4U and delegated credentials

1. Run S4U2self for an arbitrary user and verify the evidence ticket identity,
   realm, forwardable state, and cache key.
2. Run classic S4U2proxy and RBCD to separate target accounts. Validate the
   target ticket and its `S4U_DELEGATION_INFO` proxy target and transited list.
3. Request an unauthorized target and verify `ErrDelegationNotPermitted` plus
   any attached NTSTATUS.
4. Exercise cross-realm referrals when the lab has a trusted child or resource
   domain.
5. Request GSS delegation only for an `ok-as-delegate` target. Confirm the
   acceptor extracts KRB-CRED, constructs a client from the forwarded TGT, and
   obtains a second-hop service ticket. Confirm a target without
   `ok-as-delegate` does not forward credentials.

## IIS extended protection

1. Configure an HTTPS IIS Negotiate endpoint with Extended Protection set to
   Required and a certificate whose final TLS certificate is available to the
   client.
2. Authenticate with `tls-server-end-point` channel bindings and verify HTTP
   success and the authenticated PAC identity.
3. Repeat with absent and tampered bindings. Verify authentication fails with
   `KRB_AP_ERR_BAD_INTEGRITY` and no application request is served.
4. Repeat through any production TLS terminator to establish whether channel
   binding must use the frontend or backend certificate.

## RPC mutual and DCE style

1. Exchange a context with mutual authentication and DCE style against the
   target Windows RPC service.
2. Record all three legs, AP-REP subkey and sequence numbers, negotiated flags,
   and first protected request/response.
3. Verify replayed, out-of-order beyond-window, truncated, and tampered tokens
   fail without advancing the receive sequence.

## FAST and claims

1. Use a device keytab as FAST armor and require FAST for password logon.
2. Confirm encrypted challenge, cookie persistence, armored errors, and
   fail-closed behavior when an unarmored response is injected.
3. Request a service ticket for a claims-enabled user. Verify user claims and
   device claims/PAC_DEVICE_INFO for compound identity.
4. Apply a KDC policy requiring armor and confirm an unarmored client fails
   while the required-FAST client succeeds.

## KKDCP

1. Configure only an HTTPS KDC proxy URL for AS, TGS, and kpasswd traffic; do
   not leave a direct KDC fallback in the client configuration.
2. Verify password logon, service-ticket acquisition, and password change.
3. Record proxy TLS validation, HTTP status/content type, target-domain field,
   and behavior for malformed framing and unavailable backend KDCs.

## PKINIT

1. Issue user certificates with the required UPN and EKUs from the test CA.
2. Obtain TGTs using DH and RSA key delivery and validate the Windows KDC
   certificate chain, KDC Authentication EKU, and DNS name.
3. On Windows Server 2012 or newer, capture RFC 8636 SHA-2 KDF negotiation. On
   Windows Server 2016 or newer, capture and verify freshness-token echo.
4. Verify an untrusted client certificate returns typed
   `KDC_ERR_CLIENT_NOT_TRUSTED` data, including trusted certifiers when sent.
5. Decrypt PAC_CREDENTIAL_INFO with the reply key and compare the NT hash to
   the disposable account's independently recorded value.
6. Run `gokinit -X X509_user_identity=... -X X509_anchors=...`, then confirm
   MIT `klist` reads the produced ccache.

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
