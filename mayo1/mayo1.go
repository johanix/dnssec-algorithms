// Package mayo1 provides a [dns.Algorithm] implementation of MAYO-1
// (NIST onramp post-quantum signature candidate, oil-and-vinegar
// based) for DNSSEC SIG(0) transaction signing and RRSIG zone
// signing.
//
// Algorithm number 202 is used. IANA has not yet assigned a codepoint
// for MAYO in the DNS Security Algorithm Numbers registry.
//
// MAYO-1 is the level-1 parameter set (NIST security level 1).
// Signatures are 454 bytes; public keys 1420 bytes; secret keys are a
// tiny 24-byte seed.
//
// # Build requirement
//
// This subpackage transitively imports CGO bindings to liboqs. See
// dnssec-algorithms/liboqs/pkgconfig/.
//
// # Standardization status
//
// MAYO is a NIST onramp candidate, not yet standardized. Wire formats
// and parameters may change before any future final spec.
// Experimental use only.
//
// Importing this package for its side effects registers the algorithm
// with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/mayo1"
package mayo1

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/liboqs"
)

const Number uint8 = 202
const AlgName = "MAYO-1"

type impl struct{}

func init() {
	if err := dns.RegisterAlgorithm(&impl{}); err != nil {
		panic(fmt.Sprintf("dnssec-algorithms/mayo1: registration failed: %v", err))
	}
}

func (impl) Number() uint8     { return Number }
func (impl) Name() string      { return "MAYO1" }
func (impl) Hash() crypto.Hash { return 0 }

func (impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	return liboqs.Generate(AlgName)
}

func (impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	want, err := liboqs.PublicKeySize(AlgName)
	if err != nil {
		return nil, err
	}
	if len(buf) != want {
		return nil, fmt.Errorf("mayo-1 public key length %d, want %d", len(buf), want)
	}
	out := make([]byte, len(buf))
	copy(out, buf)
	return out, nil
}

func (impl) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	p, ok := pub.([]byte)
	if !ok {
		return nil, dns.ErrKey
	}
	return p, nil
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
	return liboqs.UnmarshalBinary(AlgName, buf)
}

func (impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	s, ok := priv.(*liboqs.Signer)
	if !ok {
		return "", dns.ErrPrivKey
	}
	if s.AlgName != AlgName {
		return "", fmt.Errorf("mayo-1 PrivateKeyToString: signer is for %q", s.AlgName)
	}
	buf, err := s.MarshalBinary()
	if err != nil {
		return "", err
	}
	return "PrivateKey: " + base64.StdEncoding.EncodeToString(buf) + "\n", nil
}

func (impl) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	pkBytes, ok := pub.([]byte)
	if !ok {
		return dns.ErrKey
	}
	if err := liboqs.VerifySignature(AlgName, pkBytes, hashed, sig); err != nil {
		if err == liboqs.ErrSig {
			return dns.ErrSig
		}
		return err
	}
	return nil
}

func (impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
