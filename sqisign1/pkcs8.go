package sqisign1

import (
	"crypto"
	"encoding/asn1"
	"fmt"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
	"github.com/johanix/dnssec-algorithms/sqisignc"
)

// oid is a placeholder PKCS#8 algorithm OID for SQIsign-I. NIST
// onramp algorithms have no assigned PKIX OID; using the same private
// tail convention as the other algorithm subpackages in this repo
// (2.16.840.1.101.3.4.3.99.N). N=4 is the first free tail past the
// liboqs-backed algorithms (Falcon=1, MAYO=2, SNOVA=3).
var oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 99, 4}

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
	s, ok := priv.(*sqisignc.Signer)
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
	s, err := sqisignc.UnmarshalBinary(p.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("sqisign-1 private key decode: %w", err)
	}
	return s, nil
}

func init() {
	dnsalgpkcs8.Register(pkcs8Codec{})
}
