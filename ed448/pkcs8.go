package ed448

import (
	"crypto"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/ed448"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

// oid is id-Ed448, 1.3.101.113 (RFC 8410 section 3).
var oid = asn1.ObjectIdentifier{1, 3, 101, 113}

// privateKeyInfo is the PKCS#8 PrivateKeyInfo (RFC 5208) shape RFC 8410
// section 7 uses for Ed448: version 0, the algorithm identifier with no
// parameters, and a privateKey OCTET STRING whose content is the DER of
// CurvePrivateKey, itself an OCTET STRING holding the 57-byte seed. This
// is what OpenSSL writes and reads.
type privateKeyInfo struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type pkcs8Codec struct{}

func (pkcs8Codec) MarshalPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	sk, ok := priv.(ed448.PrivateKey)
	if !ok {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	if len(sk) != ed448.PrivateKeySize {
		return nil, fmt.Errorf("Ed448 private key: %d bytes, want %d", len(sk), ed448.PrivateKeySize)
	}
	curvePrivateKey, err := asn1.Marshal(sk.Seed())
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(privateKeyInfo{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: oid},
		PrivateKey: curvePrivateKey,
	})
}

func (pkcs8Codec) ParsePKCS8(der []byte) (crypto.PrivateKey, error) {
	var p privateKeyInfo
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		// Not parseable as this PrivateKeyInfo shape — let other codecs try.
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	if !p.Algo.Algorithm.Equal(oid) {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	if len(p.Algo.Parameters.FullBytes) != 0 {
		return nil, fmt.Errorf("Ed448 private key: algorithm parameters must be absent (RFC 8410)")
	}
	var seed []byte
	rest, err := asn1.Unmarshal(p.PrivateKey, &seed)
	if err != nil {
		return nil, fmt.Errorf("Ed448 private key: CurvePrivateKey: %w", err)
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("Ed448 private key: trailing data after CurvePrivateKey")
	}
	if len(seed) != ed448.SeedSize {
		return nil, fmt.Errorf("Ed448 private key: seed is %d bytes, want %d", len(seed), ed448.SeedSize)
	}
	return ed448.NewKeyFromSeed(seed), nil
}

func init() {
	dnsalgpkcs8.Register(pkcs8Codec{})
}
