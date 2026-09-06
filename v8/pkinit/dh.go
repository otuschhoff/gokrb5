package pkinit

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/jcmturner/gofork/encoding/asn1"
)

var OIDDHPublicNumber = asn1.ObjectIdentifier{1, 2, 840, 10046, 2, 1}

const (
	MODPGroup2  = 2
	MODPGroup14 = 14
	MODPGroup16 = 16
)

type dhDomainParameters struct {
	P *big.Int
	G *big.Int
	Q *big.Int
}

// DHKey is an ephemeral finite-field Diffie-Hellman key.
type DHKey struct {
	group   int
	params  dhDomainParameters
	private *big.Int
	public  *big.Int
}

// SelectDHGroup returns the first exact, locally supported KDC parameter set.
func SelectDHGroup(parameters TDDHParameters, minimumBits int) (int, error) {
	for _, algorithm := range parameters {
		if !algorithm.Algorithm.Equal(OIDDHPublicNumber) {
			continue
		}
		var offered dhDomainParameters
		if err := strictUnmarshal(algorithm.Parameters.FullBytes, &offered); err != nil || offered.P == nil || offered.G == nil || offered.Q == nil {
			continue
		}
		for _, group := range []int{MODPGroup16, MODPGroup14, MODPGroup2} {
			known, _ := dhParameters(group)
			if known.P.BitLen() >= minimumBits && offered.P.Cmp(known.P) == 0 && offered.G.Cmp(known.G) == 0 && offered.Q.Cmp(known.Q) == 0 {
				return group, nil
			}
		}
	}
	return 0, fmt.Errorf("KDC did not offer an acceptable PKINIT DH group")
}

// GenerateDHKey creates a PKINIT DH key in a supported RFC MODP group.
func GenerateDHKey(group, minimumBits int, random io.Reader) (*DHKey, error) {
	params, err := dhParameters(group)
	if err != nil {
		return nil, err
	}
	if params.P.BitLen() < minimumBits {
		return nil, fmt.Errorf("PKINIT DH group %d has %d bits, below policy minimum %d", group, params.P.BitLen(), minimumBits)
	}
	if random == nil {
		random = rand.Reader
	}
	maximum := new(big.Int).Sub(params.Q, big.NewInt(3))
	private, err := rand.Int(random, maximum)
	if err != nil {
		return nil, fmt.Errorf("generate PKINIT DH private exponent: %w", err)
	}
	private.Add(private, big.NewInt(2))
	public := new(big.Int).Exp(params.G, private, params.P)
	return &DHKey{group: group, params: params, private: private, public: public}, nil
}

// PublicKey returns the RFC 3279 SubjectPublicKeyInfo representation.
func (key *DHKey) PublicKey() (SubjectPublicKeyInfo, error) {
	parameters, err := asn1.Marshal(key.params)
	if err != nil {
		return SubjectPublicKeyInfo{}, fmt.Errorf("marshal PKINIT DH parameters: %w", err)
	}
	public, err := asn1.Marshal(key.public)
	if err != nil {
		return SubjectPublicKeyInfo{}, fmt.Errorf("marshal PKINIT DH public value: %w", err)
	}
	return SubjectPublicKeyInfo{
		Algorithm: AlgorithmIdentifier{
			Algorithm:  OIDDHPublicNumber,
			Parameters: asn1.RawValue{FullBytes: parameters},
		},
		SubjectPublicKey: asn1.BitString{Bytes: public, BitLength: len(public) * 8},
	}, nil
}

// SharedSecret validates a peer SPKI and returns the fixed-width PKINIT secret.
func (key *DHKey) SharedSecret(peer SubjectPublicKeyInfo) ([]byte, error) {
	if !peer.Algorithm.Algorithm.Equal(OIDDHPublicNumber) {
		return nil, fmt.Errorf("unsupported PKINIT DH algorithm OID %v", peer.Algorithm.Algorithm)
	}
	var params dhDomainParameters
	if err := strictUnmarshal(peer.Algorithm.Parameters.FullBytes, &params); err != nil {
		return nil, fmt.Errorf("decode PKINIT DH parameters: %w", err)
	}
	if params.P == nil || params.G == nil || params.Q == nil ||
		params.P.Cmp(key.params.P) != 0 || params.G.Cmp(key.params.G) != 0 || params.Q.Cmp(key.params.Q) != 0 {
		return nil, fmt.Errorf("PKINIT DH peer used different domain parameters")
	}
	if peer.SubjectPublicKey.BitLength%8 != 0 {
		return nil, fmt.Errorf("PKINIT DH public value is not byte-aligned")
	}
	var public *big.Int
	if err := strictUnmarshal(peer.SubjectPublicKey.RightAlign(), &public); err != nil {
		return nil, fmt.Errorf("decode PKINIT DH public value: %w", err)
	}
	upper := new(big.Int).Sub(key.params.P, big.NewInt(2))
	if public == nil || public.Cmp(big.NewInt(2)) < 0 || public.Cmp(upper) > 0 {
		return nil, fmt.Errorf("PKINIT DH public value is outside the valid range")
	}
	if new(big.Int).Exp(public, key.params.Q, key.params.P).Cmp(big.NewInt(1)) != 0 {
		return nil, fmt.Errorf("PKINIT DH public value is outside the prime-order subgroup")
	}
	secret := new(big.Int).Exp(public, key.private, key.params.P).Bytes()
	width := (key.params.P.BitLen() + 7) / 8
	padded := make([]byte, width)
	copy(padded[width-len(secret):], secret)
	return padded, nil
}

func dhParameters(group int) (dhDomainParameters, error) {
	var prime string
	switch group {
	case MODPGroup2:
		prime = `FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
			29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
			EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
			E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
			EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE65381
			FFFFFFFF FFFFFFFF`
	case MODPGroup14:
		prime = `FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
			29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
			EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
			E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
			EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
			C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
			83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
			670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
			E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
			DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
			15728E5A 8AACAA68 FFFFFFFF FFFFFFFF`
	case MODPGroup16:
		prime = `FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
			29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
			EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
			E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
			EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
			C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
			83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
			670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
			E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
			DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
			15728E5A 8AAAC42D AD33170D 04507A33 A85521AB DF1CBA64
			ECFB8504 58DBEF0A 8AEA7157 5D060C7D B3970F85 A6E1E4C7
			ABF5AE8C DB0933D7 1E8C94E0 4A25619D CEE3D226 1AD2EE6B
			F12FFA06 D98A0864 D8760273 3EC86A64 521F2B18 177B200C
			BBE11757 7A615D6C 770988C0 BAD946E2 08E24FA0 74E5AB31
			43DB5BFC E0FD108E 4B82D120 A9210801 1A723C12 A787E6D7
			88719A10 BDBA5B26 99C32718 6AF4E23C 1A946834 B6150BDA
			2583E9CA 2AD44CE8 DBBBC2DB 04DE8EF9 2E8EFC14 1FBECAA6
			287C5947 4E6BC05D 99B2964F A090C3A2 233BA186 515BE7ED
			1F612970 CEE2D7AF B81BDD76 2170481C D0069127 D5B05AA9
			93B4EA98 8D8FDDC1 86FFB7DC 90A6C08F 4DF435C9 34063199
			FFFFFFFF FFFFFFFF`
	default:
		return dhDomainParameters{}, fmt.Errorf("unsupported PKINIT DH group %d", group)
	}
	p, ok := new(big.Int).SetString(strings.Join(strings.Fields(prime), ""), 16)
	if !ok {
		return dhDomainParameters{}, fmt.Errorf("invalid PKINIT DH group %d parameters", group)
	}
	q := new(big.Int).Rsh(new(big.Int).Sub(p, big.NewInt(1)), 1)
	return dhDomainParameters{P: p, G: big.NewInt(2), Q: q}, nil
}
