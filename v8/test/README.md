Source for integration test dependencies can be found at https://github.com/jcmturner/gokrb5-test

## Active Directory integration tests

AD tests are gated by `TESTAD=1`. Credential files default to `krb5.keytab`,
`user`, and `pw` in the repository root. `TESTAD_DIR` selects another
directory, while `TESTAD_KEYTAB`, `TESTAD_USER_FILE`, and
`TESTAD_PASSWORD_FILE` override individual files.

Use `TESTAD_KIND=samba` or `TESTAD_KIND=windows` to identify the domain
implementation. Containerized environments should also set `TESTAD_REALM`,
`TESTAD_KDC`, and `TESTAD_SERVICE_SPN`; these avoid assumptions about the test
runner's hostname and DNS domain. Delegation tests use `TESTAD_TARGET_SPN` and
`TESTAD_DENIED_SPN`; `TESTAD_DELEGATOR` selects a dedicated keytab principal,
falling back to the machine account when unset. The disabled-account test uses
`TESTAD_DISABLED_USER` and `TESTAD_DISABLED_PASSWORD`. Tests skip only the
scenario whose optional setting is absent.

The pinned Samba lab under `test/testdata/docker/samba-ad-dc` writes all files
and settings needed by CI. After starting it as described in that directory:

```sh
set -a
. /tmp/gokrb5-ad/environment
set +a
TESTAD_DIR=/tmp/gokrb5-ad go test -race -tags adintegration ./...
```

The same command runs against a live Windows domain when its credential files
and explicit `TESTAD_KIND=windows` are supplied. Windows-only release checks
are listed in `docs/design/ms-kile-windows-checklist.md`.