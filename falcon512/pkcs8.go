package falcon512

import (
	"crypto"
	"encoding/asn1"
	"fmt"

	"github.com/johanix/dnssec-algorithms/liboqs"
	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

// oid is a placeholder PKCS#8 algorithm OID for Falcon-512. The
// eventual FIPS 206 (FN-DSA) and the LAMPS Falcon certificate
// profile have not assigned a final OID; using a clearly-private tail
// under NIST CSOR's id-alg arc avoids colliding with anything real.
//
// All Falcon/MAYO/SNOVA subpackages in this repo follow the same
// convention: 2.16.840.1.101.3.4.3.99 + N, where N starts at 1.
//
//	1 = Falcon-512
//	2 = MAYO-1
//	3 = SNOVA-24_5_4
//
// Revise once IETF LAMPS publishes a finalized profile.
var oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 99, 1}

type privateKeyInfo struct {
	Version    int
	Algo       algorithmIdentifier
	PrivateKey []byte
}

type algorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.RawValue `asn1:"optional"`
}

type pkcs8Codec struct{}

func (pkcs8Codec) MarshalPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	s, ok := priv.(*liboqs.Signer)
	if !ok {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	if s.AlgName != AlgName {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	buf, err := s.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(privateKeyInfo{
		Version:    0,
		Algo:       algorithmIdentifier{Algorithm: oid},
		PrivateKey: buf,
	})
}

func (pkcs8Codec) ParsePKCS8(der []byte) (crypto.PrivateKey, error) {
	var p privateKeyInfo
	if _, err := asn1.Unmarshal(der, &p); err != nil {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	if !p.Algo.Algorithm.Equal(oid) {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	s, err := liboqs.UnmarshalBinary(AlgName, p.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("falcon-512 private key decode: %w", err)
	}
	return s, nil
}

func init() {
	dnsalgpkcs8.Register(pkcs8Codec{})
}
