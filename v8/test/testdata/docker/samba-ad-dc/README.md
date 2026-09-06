# Samba AD integration image

This image provisions the deterministic `SAMBA.GOKRB5.TEST` domain used by the
`adintegration` test suite. It is based on the Samba project's `v0.9` AD server
image (`sha256:81110901f7e7e6af2e80581611729fb99a54522bd500065002550f2f5e1b38f9`),
pinned for reproducibility. The output directory contains `krb5.keytab`,
`user`, `pw`, and an `environment` file with the matching `TESTAD_*` settings.
All credentials and keys are public, disposable test data and must never be
used outside this isolated lab.

Build and run from the repository root:

```sh
docker build -f v8/test/testdata/docker/samba-ad-dc/Containerfile \
  -t gokrb5-samba-ad v8/test/testdata/docker/samba-ad-dc
mkdir -p /tmp/gokrb5-ad
docker run --rm --privileged --name gokrb5-samba-ad \
  -v /tmp/gokrb5-ad:/artifacts \
  -p 53:53/tcp -p 53:53/udp -p 88:88/tcp -p 88:88/udp \
  -p 464:464/tcp -p 464:464/udp gokrb5-samba-ad
```

After the health check succeeds, run the suite in another shell:

```sh
set -a
. /tmp/gokrb5-ad/environment
set +a
TESTAD_DIR=/tmp/gokrb5-ad go test -tags adintegration ./v8/test/adintegration
```

The container must be privileged because Samba AD uses filesystem extended
attributes. Override the `SAMBA_*` environment variables only when testing a
non-default realm or credentials.

The automated image provisions logon, account-policy, PAC, classic/RBCD S4U,
SPNEGO, and FAST coverage. It does not provision an AD CS-compatible CA,
claims policy, KKDCP proxy, or an independent RPC `gss-server`; those scenarios
remain in the Windows/manual release checklist.