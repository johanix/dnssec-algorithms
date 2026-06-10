package qruov_q31_l3

import (
	"crypto"
	"encoding/asn1"
	"fmt"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
	"github.com/johanix/dnssec-algorithms/qruovc"
)

// oid is a placeholder PKCS#8 algorithm OID for QR-UOV-I. NIST onramp
// algorithms have no assigned PKIX OID; using the same private tail
// convention as the other algorithm subpackages in this repo
// (2.16.840.1.101.3.4.3.99.N). N=5 is the first free tail past the
// other PQ subpackages (Falcon=1, MAYO=2, SNOVA=3, SQIsign=4).
//
// This OID identifies the private-key serialization only; it is
// independent of whatever DNSSEC algorithm codepoint a consumer binds
// the scheme to via dns.RegisterAlgorithm.
var oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 99, 5}

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
	s, ok := priv.(*qruovc.Signer)
	if !ok {
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
	s, err := qruovc.UnmarshalBinary(p.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("qruov_q31_l3 private key decode: %w", err)
	}
	return s, nil
}

func init() {
	dnsalgpkcs8.Register(pkcs8Codec{})
}
