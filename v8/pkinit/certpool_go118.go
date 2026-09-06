//go:build !go1.19
// +build !go1.19

package pkinit

import "crypto/x509"

func cloneCertPool(pool *x509.CertPool) *x509.CertPool {
	// Go 1.18 does not expose certificates or support cloning a CertPool.
	return pool
}
