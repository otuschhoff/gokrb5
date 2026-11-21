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
  --hostname dc.samba.gokrb5.test \
  -v /tmp/gokrb5-ad:/artifacts \
  -p 127.0.0.1:88:88/tcp -p 127.0.0.1:88:88/udp \
  -p 127.0.0.1:464:464/tcp -p 127.0.0.1:464:464/udp gokrb5-samba-ad
```

After the health check succeeds, run the suite in another shell:

```sh
set -a
. /tmp/gokrb5-ad/environment
set +a
TESTAD_DIR=/tmp/gokrb5-ad go -C v8 test -tags adintegration ./test/adintegration
```

### Certificate-only PKINIT

The GitHub Actions Samba job also requires the pinned KDC to issue a TGT
using certificate-only DH PKINIT and negotiate an RFC 8636 KDF. The test
checks the selected OID in the verified AS reply; a legacy KDF does not pass.
The image uses Samba's MIT Kerberos backend, so this covers Samba/MIT, not
Samba/Heimdal or native Windows AD.

To run this check locally, use OpenSSL to generate a private fixture:

```sh
fixture=$(mktemp -d)
bash v8/test/testdata/docker/samba-ad-dc/pkinit-certs.sh "$fixture/pkinit"
```

Start a fresh container using the command above, adding
`--mount "type=bind,source=$fixture/pkinit/kdc,target=/pkinit,readonly"`
and `-e SAMBA_PKINIT_DIR=/pkinit` before the image name. Use the default
domain, hostname and user; the generated certificates are scoped to them.
Then run:

```sh
TESTAD_KDC=127.0.0.1:88 TESTAD_PKINIT_DIR="$fixture/pkinit/client" \
  go -C v8 test -race -count=1 -v -tags adintegration \
    -run '^TestSambaPKINITRFC8636$' ./test/adintegration
```

Stop the container and remove the temporary fixture when finished. Do not
commit or upload its private keys.

The container must be privileged because Samba AD uses filesystem extended
attributes. Override the `SAMBA_*` environment variables only when testing a
non-default realm or credentials.

The automated image provisions password and machine logon, disabled-account
rejection, PAC, classic/RBCD S4U, and SPNEGO coverage. Samba does not return the
Windows KERB-EXT-ERROR status for the disabled account, and the pinned image
does not provide interoperable required FAST. Those checks, along with AD CS,
claims policy, KKDCP, and an independent RPC `gss-server`, remain in the
Windows/manual release checklist.