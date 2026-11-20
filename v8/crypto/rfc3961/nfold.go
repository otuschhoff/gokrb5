package rfc3961

// Implementation of the n-fold algorithm as defined in RFC 3961.

/* Credits
This golang implementation of nfold used the following project for help with implementation detail.
Although their source is in java it was helpful as a reference implementation of the RFC.
You can find the source code of their open source project along with license information below.
We acknowledge and are grateful to these developers for their contributions to open source

Project: Apache Directory (http://http://directory.apache.org/)
Source: https://svn.apache.org/repos/asf/directory/apacheds/tags/1.5.1/
File: kerberos-shared/src/main/java/org/apache/directory/server/kerberos/shared/crypto/encryption/NFold.java
License: http://www.apache.org/licenses/LICENSE-2.0
*/

const (
	bitsPerByte = 8
	lowBitMask  = 1
)

// Nfold expands the key to ensure it is not smaller than one cipher block.
// Defined in RFC 3961.
//
// m input bytes that will be "stretched" to the least common multiple of n bits and the bit length of m.
// It returns nil if m is empty or n is not a positive, byte-aligned bit length.
func Nfold(m []byte, n int) []byte {
	if len(m) == 0 || n <= 0 || n%bitsPerByte != 0 {
		return nil
	}
	k := len(m) * bitsPerByte

	// Get the lowest common multiple of the two bit sizes
	lcm := lcm(n, k)
	replications := lcm / k
	var sumBytes []byte

	const rotationBits = 13
	for i := range replications {
		rotation := rotationBits * i
		sumBytes = append(sumBytes, rotateRight(m, rotation)...)
	}

	foldBytes := n / bitsPerByte
	nfold := make([]byte, foldBytes)
	sum := make([]byte, foldBytes)
	if len(sumBytes) < foldBytes {
		return nil
	}
	for i := 0; i < lcm/n; i++ {
		for j := range foldBytes {
			sum[j] = sumBytes[j+(i*len(sum))]
		}
		nfold = onesComplementAddition(nfold, sum)
	}
	return nfold
}

func onesComplementAddition(n1, n2 []byte) []byte {
	numBits := len(n1) * bitsPerByte
	out := make([]byte, len(n1))
	carry := 0
	for i := numBits - 1; i > -1; i-- {
		n1b := getBit(&n1, i)
		n2b := getBit(&n2, i)
		s := n1b + n2b + carry

		setBit(&out, i, s&lowBitMask)
		carry = s >> 1
	}
	if carry == 1 {
		carryArray := make([]byte, len(n1))
		carryArray[len(carryArray)-1] = 1
		out = onesComplementAddition(out, carryArray)
	}
	return out
}

func rotateRight(b []byte, step int) []byte {
	out := make([]byte, len(b))
	bitLen := len(b) * bitsPerByte
	for i := range bitLen {
		v := getBit(&b, i)
		setBit(&out, (i+step)%bitLen, v)
	}
	return out
}

func lcm(x, y int) int {
	return (x * y) / gcd(x, y)
}

func gcd(x, y int) int {
	for y != 0 {
		x, y = y, x%y
	}
	return x
}

func getBit(b *[]byte, p int) int {
	pByte := p / bitsPerByte
	pBit := uint(p % bitsPerByte)
	vByte := (*b)[pByte]
	vInt := int(vByte >> (bitsPerByte - (pBit + 1)) & lowBitMask)
	return vInt
}

func setBit(b *[]byte, p, v int) {
	pByte := p / bitsPerByte
	pBit := uint(p % bitsPerByte)
	oldByte := (*b)[pByte]
	newByte := byte(v<<(bitsPerByte-(pBit+1))) | oldByte // #nosec G115 -- v is one bit and the shift is 0..7.
	(*b)[pByte] = newByte
}
