package falcon1024

import (
	"crypto"
	"encoding/asn1"
	"fmt"

	"github.com/johanix/dnssec-algorithms/liboqs"
	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

// oid is a placeholder PKCS#8 algorithm OID for Falcon-1024. The
// eventual FIPS 206 (FN-DSA) / LAMPS Falcon certificate profile has
// not assigned a final OID; using the same private tail convention as
// the other algorithm subpackages in this repo
// (2.16.840.1.101.3.4.3.99.N). Falcon-512 uses tail 1, Falcon-1024
// uses 9.
var oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 99, 9}

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
		return nil, fmt.Errorf("falcon-1024 private key decode: %w", err)
	}
	return s, nil
}

func init() {
	dnsalgpkcs8.Register(pkcs8Codec{})
}
