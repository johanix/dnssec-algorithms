// Package qruov1 provides a [dns.Algorithm] implementation of QR-UOV-I
// (the level-1, q=31 L=3 parameter set of the QR-UOV post-quantum
// signature scheme, NIST onramp candidate, multivariate) for DNSSEC
// SIG(0) transaction signing and RRSIG zone signing.
//
// QR-UOV ("Quotient Ring UOV") is a variant of Unbalanced Oil and
// Vinegar that represents the public key as polynomials over a
// quotient ring, roughly halving the public-key size versus plain
// UOV. It advanced to the third round of NIST's additional-signatures
// process.
//
// The package does not own a DNSSEC algorithm codepoint. The caller
// chooses one and binds it at registration time:
//
//	dns.RegisterAlgorithm(N, qruov1.New())
//
// This repo's tests and demo use number 205 by convention; downstream
// applications may pick any value from the private-use or experimental
// range. IANA has not assigned a codepoint for QR-UOV in the DNS
// Security Algorithm Numbers registry.
//
// QR-UOV-I (q=31, L=3, v=165, m=60) sizes:
//   - public key: 23641 bytes
//   - secret key: 32 bytes (a pair of 16-byte seeds)
//   - signature:  157 bytes
//
// The trade-off is the operationally interesting property: the
// signature is tiny (157 B — between Ed25519's 64 B and RSA-2048's
// 256 B, and far below ML-DSA-44's 2420 B or Falcon-512's ~666 B),
// while the public key is large (~23 KB), comparable to the other
// multivariate PQ schemes in this repo. Small signatures suit RRSIG-
// heavy responses; the large DNSKEY is a one-time cost per key.
//
// # Build requirement
//
// This subpackage transitively imports CGO bindings to the QR-UOV
// round2 reference C library, pinned to the q=31 L=3 parameter set.
// See dnssec-algorithms/qruovc/ for the build glue and
// dnssec-algorithms/README.md for setup instructions.
//
// # Standardization status
//
// QR-UOV is a NIST onramp candidate, not yet standardized. Wire
// formats and parameters may change before any future final spec. The
// reference implementation's own TODO additionally flags that
// constant-time (secret-independent) rejection sampling and linear
// solving are not yet complete. Experimental use only.
//
// Importing this package for its side effects registers the algorithm
// with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/qruov1"
package qruov1

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/qruovc"
)

// Impl is the QR-UOV-I [dns.Algorithm] implementation. Construct with
// [New]; pass the returned value to [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for QR-UOV-I.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "QRUOV1" }
func (*Impl) Hash() crypto.Hash { return 0 }

func (*Impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	return qruovc.Generate()
}

func (*Impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	if len(buf) != qruovc.PublicKeySize {
		return nil, fmt.Errorf("qruov-1 public key length %d, want %d", len(buf), qruovc.PublicKeySize)
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
	return qruovc.UnmarshalBinary(buf)
}

func (*Impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	s, ok := priv.(*qruovc.Signer)
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
	if err := qruovc.VerifySignature(pkBytes, hashed, sig); err != nil {
		if err == qruovc.ErrSig {
			return dns.ErrSig
		}
		return err
	}
	return nil
}

func (*Impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
