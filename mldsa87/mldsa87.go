// Package mldsa87 provides a [dns.Algorithm] implementation of
// NIST FIPS 204 ML-DSA-87 for DNSSEC SIG(0) transaction signing and
// RRSIG zone signing.
//
// The codepoint is chosen by the application at registration time:
//
//	import (
//	    "github.com/miekg/dns"
//	    "github.com/johanix/dnssec-algorithms/mldsa87"
//	)
//
//	func init() {
//	    dns.RegisterAlgorithm(213, mldsa87.New())
//	}
//
// IANA has not assigned a codepoint for ML-DSA in the DNS Security
// Algorithm Numbers registry; the application picks a value from the
// Unassigned range.
//
// All [dns.Algorithm] interface methods are implemented on top of
// github.com/cloudflare/circl/sign/mldsa/mldsa87.
package mldsa87

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"
	"github.com/miekg/dns"
)

// Compile-time assertion that CIRCL's ML-DSA-87 private key satisfies
// crypto.Signer, so the shared sign() path in miekg/dns can use it.
var _ crypto.Signer = (*mldsa87.PrivateKey)(nil)

// Impl is the ML-DSA-87 [dns.Algorithm] implementation. Construct
// with [New]; pass the returned value to [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for ML-DSA-87.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "MLDSA87" }
func (*Impl) Hash() crypto.Hash { return 0 }

func (*Impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	_, priv, err := mldsa87.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (*Impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	if len(buf) != mldsa87.PublicKeySize {
		return nil, dns.ErrKey
	}
	pk := new(mldsa87.PublicKey)
	if err := pk.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return pk, nil
}

func (*Impl) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	p, ok := pub.(*mldsa87.PublicKey)
	if !ok {
		return nil, dns.ErrKey
	}
	return p.MarshalBinary()
}

func (*Impl) ReadPrivateKey(m map[string]string) (crypto.PrivateKey, error) {
	v, ok := m["privatekey"]
	if !ok {
		return nil, dns.ErrPrivKey
	}
	buf, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(buf) != mldsa87.PrivateKeySize {
		return nil, dns.ErrPrivKey
	}
	p := new(mldsa87.PrivateKey)
	if err := p.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return p, nil
}

func (*Impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	p, ok := priv.(*mldsa87.PrivateKey)
	if !ok {
		return "", dns.ErrPrivKey
	}
	buf, err := p.MarshalBinary()
	if err != nil {
		return "", err
	}
	return "PrivateKey: " + base64.StdEncoding.EncodeToString(buf) + "\n", nil
}

func (*Impl) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	p, ok := pub.(*mldsa87.PublicKey)
	if !ok {
		return dns.ErrKey
	}
	if mldsa87.Verify(p, hashed, nil, sig) {
		return nil
	}
	return dns.ErrSig
}

func (*Impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
