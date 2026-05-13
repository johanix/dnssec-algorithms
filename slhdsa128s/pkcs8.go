package slhdsa128s

import (
	"crypto"
	"encoding/asn1"
	"fmt"

	"github.com/cloudflare/circl/sign/slhdsa"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

// oid is the NIST OID for SLH-DSA-SHA2-128s (FIPS 205), per CSOR
// allocation under id-slh-dsa (2.16.840.1.101.3.4.3.20).
//
// The 12 SLH-DSA parameter sets occupy 2.16.840.1.101.3.4.3.{20..31};
// other variants would each get their own subpackage with their own
// OID.
var oid = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 20}

// privateKeyInfo is a minimal PKCS#8 PrivateKeyInfo (RFC 5958) for an
// SLH-DSA-SHA2-128s key. The privateKey OCTET STRING holds CIRCL's
// packed key bytes (skSeed || skPrf || pkSeed || pkRoot, 64 bytes
// total for the 128s parameter set).
//
// This is a demo-profile choice. draft-ietf-lamps-cms-sphincs-plus
// and follow-ups define the canonical CMS / certificate profile for
// SLH-DSA; that is a more elaborate envelope. The shape here is
// chosen for round-trip fidelity inside tdns and is not interop-
// compatible with PKIX-conformant SLH-DSA encoders.
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
	sk, ok := priv.(*slhdsa.PrivateKey)
	if !ok {
		return nil, dnsalgpkcs8.ErrUnsupported
	}
	skBytes, err := sk.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return asn1.Marshal(privateKeyInfo{
		Version:    0,
		Algo:       algorithmIdentifier{Algorithm: oid},
		PrivateKey: skBytes,
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
	sk := &slhdsa.PrivateKey{ID: ParamSet}
	if err := sk.UnmarshalBinary(p.PrivateKey); err != nil {
		return nil, fmt.Errorf("SLH-DSA-SHA2-128s private key decode: %w", err)
	}
	return sk, nil
}

func init() {
	dnsalgpkcs8.Register(pkcs8Codec{})
}
