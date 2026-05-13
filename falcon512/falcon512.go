// Package falcon512 provides a [dns.Algorithm] implementation of
// Falcon-512 (NIST PQC, basis of the draft FIPS 206 FN-DSA) for
// DNSSEC SIG(0) transaction signing and RRSIG zone signing.
//
// Algorithm number 201 is used. IANA has not yet assigned a
// codepoint for Falcon / FN-DSA in the DNS Security Algorithm
// Numbers registry; 201 is chosen from the Unassigned range.
//
// Falcon-512 produces ~666-byte signatures (variable length, max
// 752). At NIST security level 1. The signing primitive uses FFT
// over the NTRU lattice; the underlying C implementation lives in
// the Open Quantum Safe liboqs library and is reached via liboqs-go.
//
// # Build requirement
//
// This subpackage transitively imports CGO bindings to liboqs. The
// build host must have liboqs installed and a liboqs-go.pc file on
// PKG_CONFIG_PATH. See dnssec-algorithms/liboqs/pkgconfig/.
//
// # Standardization status
//
// Falcon-512 is the basis of FIPS 206 (FN-DSA), still in draft as
// of 2026. The on-the-wire signature format produced by liboqs
// follows the original Falcon submission, which may differ in
// details from the eventual FIPS 206 finalization. Operators should
// treat this as experimental.
//
// Importing this package for its side effects registers the
// algorithm with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/falcon512"
package falcon512

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/liboqs"
)

// Number is the algorithm codepoint claimed by this implementation.
const Number uint8 = 201

// AlgName is the liboqs identifier for Falcon-512.
const AlgName = "Falcon-512"

type impl struct{}

func init() {
	if err := dns.RegisterAlgorithm(&impl{}); err != nil {
		panic(fmt.Sprintf("dnssec-algorithms/falcon512: registration failed: %v", err))
	}
}

func (impl) Number() uint8     { return Number }
func (impl) Name() string      { return "FALCON512" }
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
		return nil, fmt.Errorf("falcon-512 public key length %d, want %d", len(buf), want)
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
		return "", fmt.Errorf("falcon-512 PrivateKeyToString: signer is for %q", s.AlgName)
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
