#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -eq 0 ] || [ -z "${DNS_IP:-}" ]; then
  echo "Usage: DNS_IP=ADDRESS bash scripts/with-integration-dns.sh COMMAND [ARG ...]" >&2
  exit 2
fi

resolver=$(mktemp)
trap 'rm -f -- "$resolver"' EXIT
printf 'nameserver %s\n' "$DNS_IP" > "$resolver"

# Limit the fixture resolver to the test process tree, and run tests as the caller.
sudo -n --preserve-env /usr/bin/unshare --mount --propagation private -- /bin/bash -peuc '
  /usr/bin/mount --bind "$1" /etc/resolv.conf
  shift
  exec /usr/bin/setpriv --reuid "$SUDO_UID" --regid "$SUDO_GID" --init-groups -- /usr/bin/env "$@"
' integration-dns "$resolver" "HOME=$HOME" "PATH=$PATH" "$@"
