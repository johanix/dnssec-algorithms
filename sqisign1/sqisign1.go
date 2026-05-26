// Package sqisign1 provides a [dns.Algorithm] implementation of
// SQIsign-I (the level-1 parameter set of the SQIsign post-quantum
// signature scheme, NIST onramp candidate, isogeny-based) for DNSSEC
// SIG(0) transaction signing and RRSIG zone signing.
//
// The package does not own a DNSSEC algorithm codepoint. The caller
// chooses one and binds it at registration time:
//
//	dns.RegisterAlgorithm(N, sqisign1.New())
//
// This repo's tests and demo use number 204 by convention; downstream
// applications may pick any value from the private-use or
// experimental range. IANA has not yet assigned a codepoint for
// SQIsign in the DNS Security Algorithm Numbers registry.
//
// SQIsign-I sizes (NIST security level 1):
//   - public key: 65 bytes
//   - secret key: 353 bytes
//   - signature:  148 bytes
//
// The signature size is the operationally interesting property: it is
// smaller than every other DNSSEC signature algorithm currently in
// use (Ed25519: 64 B, ECDSA P-256: 64 B, RSA-2048: 256 B, ML-DSA-44:
// 2420 B, Falcon-512: ~666 B). Round 2 reference signing on Apple
// Silicon is ~50 ms per signature; performance on other platforms
// should be benchmarked before committing to online-signing
// workflows.
//
// # Build requirement
//
// This subpackage transitively imports CGO bindings to the SQIsign
// reference C library. See dnssec-algorithms/sqisignc/ for the build
// glue and dnssec-algorithms/README.md for setup instructions.
//
// # Standardization status
//
// SQIsign is a NIST onramp candidate, not yet standardized. Wire
// formats and parameters may change before any future final spec.
// Experimental use only.
//
// Importing this package for its side effects registers the algorithm
// with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/sqisign1"
package sqisign1

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/sqisignc"
)

// Impl is the SQIsign-I [dns.Algorithm] implementation. Construct
// with [New]; pass the returned value to [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for SQIsign-I.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "SQISIGN1" }
func (*Impl) Hash() crypto.Hash { return 0 }

func (*Impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	return sqisignc.Generate()
}

func (*Impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	if len(buf) != sqisignc.PublicKeySize {
		return nil, fmt.Errorf("sqisign-1 public key length %d, want %d", len(buf), sqisignc.PublicKeySize)
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}

func (*Impl) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	p, ok := pub.([]byte)
	if !ok {
		return nil, dns.ErrKey
	}
	return p, nil
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
	return sqisignc.UnmarshalBinary(buf)
}

func (*Impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	s, ok := priv.(*sqisignc.Signer)
	if !ok {
		return "", dns.ErrPrivKey
	}
	buf, err := s.MarshalBinary()
	if err != nil {
		return "", err
	}
	return "PrivateKey: " + base64.StdEncoding.EncodeToString(buf) + "\n", nil
}

func (*Impl) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	pkBytes, ok := pub.([]byte)
	if !ok {
		return dns.ErrKey
	}
	if err := sqisignc.VerifySignature(pkBytes, hashed, sig); err != nil {
		if err == sqisignc.ErrSig {
			return dns.ErrSig
		}
		return err
	}
	return nil
}

func (*Impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
