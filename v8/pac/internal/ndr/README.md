# Bounded NDR decoder

This package is a PAC-internal copy of `github.com/jcmturner/rpc/v2/ndr` at
version `v2.0.3`, distributed under the repository's Apache-2.0 license.

The local copy bounds input and reflected slice allocations before decoding.
The upstream decoder allocates conformant and varying arrays directly from
untrusted wire counts, which permits a small malformed PAC to terminate the
process through memory exhaustion.
