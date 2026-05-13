// Package mldsa44 provides a [dns.Algorithm] implementation of
// NIST FIPS 204 ML-DSA-44 for DNSSEC SIG(0) transaction signing and
// RRSIG zone signing.
//
// Algorithm number 199 is used. IANA has not yet assigned a codepoint
// for ML-DSA in the DNS Security Algorithm Numbers registry; 199 is
// chosen from the Unassigned range. Collision risk is on the user;
// pin the codepoint in deployment configuration.
//
// Importing this package for its side effects registers the algorithm
// with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/mldsa44"
//
// All twelve [dns.Algorithm] interface methods are implemented. The
// crypto backend is github.com/cloudflare/circl/sign/mldsa/mldsa44.
package mldsa44

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"
	"fmt"

	"github.com/cloudflare/circl/sign/mldsa/mldsa44"
	"github.com/miekg/dns"
)

// Number is the algorithm codepoint claimed by this implementation.
// Pinned at IANA-Unassigned 199 until an IANA-assigned number exists
// for ML-DSA-44 in the DNS Security Algorithm Numbers registry.
const Number uint8 = 199

// Compile-time assertion that CIRCL's ML-DSA-44 private key satisfies
// crypto.Signer, so the shared sign() path in miekg/dns can use it.
var _ crypto.Signer = (*mldsa44.PrivateKey)(nil)

type impl struct{}

func init() {
	if err := dns.RegisterAlgorithm(&impl{}); err != nil {
		panic(fmt.Sprintf("dnssec-algorithms/mldsa44: registration failed: %v", err))
	}
}

func (impl) Number() uint8     { return Number }
func (impl) Name() string      { return "MLDSA44" }
func (impl) Hash() crypto.Hash { return 0 }

func (impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	_, priv, err := mldsa44.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	if len(buf) != mldsa44.PublicKeySize {
		return nil, dns.ErrKey
	}
	pk := new(mldsa44.PublicKey)
	if err := pk.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return pk, nil
}

func (impl) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	p, ok := pub.(*mldsa44.PublicKey)
	if !ok {
		return nil, dns.ErrKey
	}
	return p.MarshalBinary()
}

func (impl) ReadPrivateKey(m map[string]string) (crypto.PrivateKey, error) {
	v, ok := m["privatekey"]
	if !ok {
		return nil, dns.ErrPrivKey
	}
	buf, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(buf) != mldsa44.PrivateKeySize {
		return nil, dns.ErrPrivKey
	}
	p := new(mldsa44.PrivateKey)
	if err := p.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return p, nil
}

func (impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	p, ok := priv.(*mldsa44.PrivateKey)
	if !ok {
		return "", dns.ErrPrivKey
	}
	buf, err := p.MarshalBinary()
	if err != nil {
		return "", err
	}
	return "PrivateKey: " + base64.StdEncoding.EncodeToString(buf) + "\n", nil
}

func (impl) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	p, ok := pub.(*mldsa44.PublicKey)
	if !ok {
		return dns.ErrKey
	}
	if mldsa44.Verify(p, hashed, nil, sig) {
		return nil
	}
	return dns.ErrSig
}

func (impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
