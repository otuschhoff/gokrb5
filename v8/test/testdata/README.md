# MIT krb5 compatibility fixtures

These fixtures support `docs/design/mit-krb5-keytab-kinit-compatibility.md`.
The committed keytab captures were generated with MIT Kerberos 1.21.3 using
`testuser1@TEST.GOKRB5` and the repository's public test password. Entry
timestamps are normalized to Unix time 1700000000 so regeneration is
byte-reproducible. `klist` output is captured with `LC_ALL=C` and `TZ=UTC`.

Generate the keytab and text fixtures from the `v8` module directory:

```sh
test/testdata/gen/mit_fixtures.sh /tmp/gokrb5-mit-fixtures
```

To capture ccaches against the test KDC, pass its MIT krb5 configuration:

```sh
MIT_FIXTURE_KRB5_CONFIG=/path/to/krb5.conf \
  test/testdata/gen/mit_fixtures.sh /tmp/gokrb5-mit-fixtures
```

The generator invokes `ktutil addent -password` for enctypes 17, 18, 19, 20,
23, and 16, plus separate kvno 300, multi-kvno, multi-principal, explicit-salt,
and enterprise-principal captures. It invokes `kinit`, `kvno`, and a
`ccache_type = 3` configuration for the five ccache variants when a test KDC
configuration is supplied.

MIT `ktutil` does not expose a name-type option, so the enterprise fixture's
name-type field is changed to `KRB_NT_ENTERPRISE` (10) after capture. MIT no
longer emits v1 keytabs. The v1 little- and big-endian fixtures are
specification-derived. The deleted-record holes and missing KVNO32 trailer are
derived from MIT v2 captures by changing only record framing. The committed v3
cache is a minimal specification-derived cache. Keytab-login and renewable
forwardable caches are tested by the live interop suite instead of claiming
password-login bytes as captures.

Never use production credentials when generating committed fixtures. The
script writes key material and tickets to its output directory.
