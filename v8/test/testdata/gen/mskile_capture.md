# MS-KILE fixture capture

Only capture traffic in a disposable test domain. Never commit production
passwords, private keys, keytabs, ticket caches, session keys, or unsanitized
PAC identity data.

## Capture environment

1. Create test-only user, computer, service, disabled, locked, expired, and
   password-change-required accounts in a Samba AD DC and a Windows AD lab.
2. Register an HTTP SPN and delegation targets for classic constrained
   delegation and resource-based constrained delegation.
3. Start Wireshark with the Kerberos dissector enabled. Export only test keys
   required to decrypt the capture and destroy them after fixture extraction.
4. Record the DC product/version, domain functional level, client build,
   account encryption-type settings, and capture date in the fixture review.

## Exchanges

1. Purge tickets with `klist purge` and, for Local System captures,
   `klist -li 0x3e7 purge`.
2. Trigger password and certificate AS exchanges, enterprise-name
   canonicalization, service-ticket requests, S4U2self, classic S4U2proxy,
   RBCD, FAST, claims, channel bindings, delegation, mutual authentication,
   DCE style, and password change.
3. Capture disabled, locked, expired, invalid-logon-hours, password-change,
   and skew errors separately.
4. Use `Get-KerberosTicket`, `impacket-getST`, and Samba `krb5_pac` tooling to
   cross-check decoded fields where appropriate.

## Sanitization and extraction

1. Export only the DER value of the structure under test, not a reusable
   credential-bearing packet, unless the enclosing packet is required by a
   later phase.
2. Replace names, realms, SIDs, keys, ciphertext, checksums, timestamps, and
   nonces with test-only values, then recompute dependent encryption and
   integrity fields using committed test-only keys.
3. Convert bytes to uppercase hexadecimal and verify Wireshark and gokrb5
   decode the same field values.
4. Add the vector to `mskile_vectors.go`, remove its `SPEC-DERIVED` marker,
   and record the sanitized capture provenance in the review.

The Phase 0 constants remain structure-only, spec-derived vectors until this
procedure is completed on the Windows manual runner.
