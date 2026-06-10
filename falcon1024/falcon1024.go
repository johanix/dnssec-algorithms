// Package falcon1024 provides a [dns.Algorithm] implementation of
// Falcon-1024 (NIST PQC, basis of the draft FIPS 206 FN-DSA) for
// DNSSEC SIG(0) transaction signing and RRSIG zone signing.
//
// Algorithm number 209 is used. IANA has not yet assigned a codepoint
// for Falcon / FN-DSA in the DNS Security Algorithm Numbers registry;
// 209 is chosen from the Unassigned range.
//
// Falcon-1024 is the NIST security level 5 parameter set (vs Falcon-512
// at level 1). It produces variable-length signatures up to 1462 bytes
// (~1280 typical); public keys are 1793 bytes. The signing primitive
// uses FFT over the NTRU lattice; the underlying C implementation lives
// in the Open Quantum Safe liboqs library and is reached via liboqs-go.
//
// # Floating-point caveat
//
// Falcon signing and key generation use IEEE-754 double-precision
// floating-point arithmetic. This complicates constant-time
// (side-channel-resistant) implementation and cross-platform
// reproducibility, and is a known reason FN-DSA standardization trails
// ML-DSA. Verification is integer-only, so for DNSSEC the floating-point
// exposure is confined to the signer. Operators should treat this as
// experimental and sign only on trusted hardware.
//
// # Build requirement
//
// This subpackage transitively imports CGO bindings to liboqs. The
// build host must have liboqs installed and a liboqs-go.pc file on
// PKG_CONFIG_PATH. See dnssec-algorithms/liboqs/pkgconfig/.
//
// # Standardization status
//
// Falcon-1024 is the basis of FIPS 206 (FN-DSA), still in draft as of
// 2026. The on-the-wire signature format produced by liboqs follows
// the original Falcon submission, which may differ from the eventual
// FIPS 206 finalization. Experimental use only.
//
// Importing this package for its side effects registers the algorithm
// with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/falcon1024"
package falcon1024

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/liboqs"
)

// AlgName is the liboqs identifier for Falcon-1024.
const AlgName = "Falcon-1024"

// Impl is the Falcon-1024 [dns.Algorithm] implementation. Construct
// with [New]; pass the returned value to [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for Falcon-1024.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "FALCON1024" }
func (*Impl) Hash() crypto.Hash { return 0 }

func (*Impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	return liboqs.Generate(AlgName)
}

func (*Impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	want, err := liboqs.PublicKeySize(AlgName)
	if err != nil {
		return nil, err
	}
	if len(buf) != want {
		return nil, fmt.Errorf("falcon-1024 public key length %d, want %d", len(buf), want)
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
	return liboqs.UnmarshalBinary(AlgName, buf)
}

func (*Impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	s, ok := priv.(*liboqs.Signer)
	if !ok {
		return "", dns.ErrPrivKey
	}
	if s.AlgName != AlgName {
		return "", fmt.Errorf("falcon-1024 PrivateKeyToString: signer is for %q", s.AlgName)
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
	if err := liboqs.VerifySignature(AlgName, pkBytes, hashed, sig); err != nil {
		if err == liboqs.ErrSig {
			return dns.ErrSig
		}
		return err
	}
	return nil
}

func (*Impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
