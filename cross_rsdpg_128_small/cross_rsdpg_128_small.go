// Package cross_rsdpg_128_small provides a [dns.Algorithm]
// implementation of CROSS RSDP-G-128-small (NIST additional-signatures
// round-2 candidate, code-based) for DNSSEC SIG(0) transaction signing
// and RRSIG zone signing.
//
// Algorithm number 214 is used. IANA has not yet assigned a codepoint
// for CROSS in the DNS Security Algorithm Numbers registry.
//
// # Why CROSS for DNSSEC
//
// CROSS is code-based (Restricted Syndrome Decoding Problem, the
// RSDP-G / Gallager-code variant here) — a hardness family with no
// other representation in this repo, whose other algorithms are
// lattice (ML-DSA, Falcon), multivariate/UOV-derived (MAYO, SNOVA,
// QR-UOV), or isogeny (SQIsign). Family diversity is the point: an
// algorithm-split KSK backed by a distinct assumption hedges against a
// break in any one family.
//
// CROSS RSDP-G-128-small has a 54-byte public key and an 8960-byte
// signature — the mirror image of QR-UOV (large key, tiny signature).
// The large signature makes it UNSUITABLE as a ZSK (the RRSIG would
// bloat every signed response), but well suited as a KSK: a KSK signs
// only the DNSKEY RRset, whose response is fetched occasionally and is
// already TCP/DoT-bound in the algorithm-split model. Even during a
// KSK algorithm rollover — two KSK signatures over the DNSKEY RRset —
// two ~9 KB CROSS signatures plus the small public keys and the ZSK
// material stay comfortably under the 64 KB DNSKEY-response ceiling
// (~20-21 KB total). See docs/pqc-algorithm-families.md.
//
// # Build requirement
//
// This subpackage transitively imports CGO bindings to liboqs. See
// dnssec-algorithms/liboqs/pkgconfig/. CROSS is included in a full
// liboqs build; note that the minimal-build filter in
// liboqs/build-liboqs-static.sh does not currently select it.
//
// # Standardization status
//
// CROSS is a NIST additional-signatures round-2 candidate, not yet
// standardized. Wire formats and parameters may change before any
// future final spec. Experimental use only.
//
// Importing this package for its side effects registers the algorithm
// with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/cross_rsdpg_128_small"
package cross_rsdpg_128_small

import (
	"crypto"
	"encoding/base64"
	"fmt"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/liboqs"
)

// AlgName is the liboqs identifier for CROSS RSDP-G-128-small. It must
// match the canonical OQS_SIG_alg string exactly (OQS_SIG_new is
// called with it verbatim): "cross-rsdpg-128-small".
const AlgName = "cross-rsdpg-128-small"

// Impl is the CROSS RSDP-G-128-small [dns.Algorithm] implementation.
// Construct with [New]; pass the returned value to
// [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for CROSS RSDP-G-128-small.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "CROSSRSDPG128SMALL" }
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
		return nil, fmt.Errorf("cross-rsdpg-128-small public key length %d, want %d", len(buf), want)
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
		return "", fmt.Errorf("cross-rsdpg-128-small PrivateKeyToString: signer is for %q", s.AlgName)
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
