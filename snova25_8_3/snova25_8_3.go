// Package snova25_8_3 provides a [dns.Algorithm] implementation of
// SNOVA-25_8_3 (NIST onramp post-quantum signature candidate,
// oil-and-vinegar based) for DNSSEC SIG(0) transaction signing and
// RRSIG zone signing.
//
// Algorithm number 211 is used. IANA has not yet assigned a codepoint
// for SNOVA in the DNS Security Algorithm Numbers registry.
//
// SNOVA-25_8_3 is a NIST level-1 parameter set whose (v,o,l) =
// (25,8,3) choice strikes a balance between signature and key size:
// signatures are 165 bytes and public keys 2320 bytes (a smaller
// public key than SNOVA-37_17_2, with a slightly larger signature).
// Secret keys are a 48-byte seed.
//
// # Build requirement
//
// This subpackage transitively imports CGO bindings to liboqs. See
// dnssec-algorithms/liboqs/pkgconfig/.
//
// # Standardization status
//
// SNOVA is a NIST onramp candidate, not yet standardized. Wire
// formats and parameters may change before any future final spec.
// Experimental use only.
//
// Importing this package for its side effects registers the algorithm
// with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/snova25_8_3"
package snova25_8_3

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/liboqs"
)

// AlgName is the liboqs identifier for SNOVA-25_8_3.
const AlgName = "SNOVA_25_8_3"

// Impl is the SNOVA-25_8_3 [dns.Algorithm] implementation. Construct
// with [New]; pass the returned value to [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for SNOVA-25_8_3.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "SNOVA25_8_3" }
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
		return nil, fmt.Errorf("snova-25_8_3 public key length %d, want %d", len(buf), want)
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
		return "", fmt.Errorf("snova-25_8_3 PrivateKeyToString: signer is for %q", s.AlgName)
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
