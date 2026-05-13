// Package liboqs provides a thin adapter layer that lets out-of-tree
// DNSSEC algorithm subpackages built on top of the Open Quantum Safe
// liboqs C library (via liboqs-go) plug into the
// github.com/miekg/dns algorithm registration API.
//
// It is internal-style infrastructure: not meant for direct use by
// applications. Each concrete algorithm subpackage (falcon512,
// mayo1, snova24_5_4, ...) imports this helper and routes through
// [SignerFromSecretKey], [Generate], and [VerifySignature] rather
// than touching liboqs-go directly. The benefit is one place to
// own the CGO build glue, the [crypto.Signer] adapter shape, and
// the fresh-per-call sig-object lifecycle.
//
// # Lifecycle pattern
//
// liboqs-go's oqs.Signature wraps a C OQS_SIG handle that owns the
// secret key and must be released with Clean(). Rather than thread
// that lifecycle through Go's crypto.Signer interface (which has no
// Close), we treat the secret key as immutable bytes and create a
// fresh oqs.Signature per Sign or Verify call. Per-call CGO setup
// is microseconds against millisecond-scale signing — negligible.
//
// # Build setup
//
// Importing this package transitively imports liboqs-go, which uses
// CGO to call into the system liboqs. Every host that compiles a
// program using this package needs a working liboqs-go.pc on
// PKG_CONFIG_PATH. See dnssec-algorithms/liboqs/pkgconfig/ and the
// repo's README for setup details.
package liboqs

import (
	"crypto"
	"fmt"
	"io"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// Signer adapts a secret key + algorithm name into a [crypto.Signer]
// usable by the shared miekg/dns sign() path. Public is the raw
// public-key bytes (as defined by the liboqs algorithm); the
// public-key-from-wire decoding lives in each algorithm subpackage.
type Signer struct {
	AlgName   string
	SecretKey []byte
	Pub       []byte
}

// Public returns the raw public-key bytes as a crypto.PublicKey. The
// concrete value is a copy of Pub; algorithm subpackages may wrap it
// further (e.g. tag with a typed marker) in their PublicKeyToWire.
func (s *Signer) Public() crypto.PublicKey { return s.Pub }

// Sign satisfies [crypto.Signer]. Each call creates a fresh
// oqs.Signature configured for s.AlgName, signs, and frees the
// underlying C state on return.
//
// IMPORTANT: liboqs-go's Signature.Clean calls OQS_MEM_cleanse on the
// secret-key slice it was initialized with, zeroing the bytes
// in-place. We pass a defensive copy of s.SecretKey so the master
// copy on the Signer survives across many Sign calls.
func (s *Signer) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	skCopy := make([]byte, len(s.SecretKey))
	copy(skCopy, s.SecretKey)
	var sig oqs.Signature
	if err := sig.Init(s.AlgName, skCopy); err != nil {
		return nil, fmt.Errorf("liboqs init %q: %w", s.AlgName, err)
	}
	defer sig.Clean()
	out, err := sig.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("liboqs sign %q: %w", s.AlgName, err)
	}
	return out, nil
}

// Generate creates a fresh keypair for algName and returns a
// *Signer holding both halves. Public-key bytes are exposed for the
// caller to feed back into a DNSKEY/KEY rdata field.
//
// Same caveat as Sign: the deferred Clean cleanses the in-place
// secret-key slice, so we take a defensive copy before returning.
func Generate(algName string) (*Signer, error) {
	var sig oqs.Signature
	if err := sig.Init(algName, nil); err != nil {
		return nil, fmt.Errorf("liboqs init %q: %w", algName, err)
	}
	defer sig.Clean()
	pub, err := sig.GenerateKeyPair()
	if err != nil {
		return nil, fmt.Errorf("liboqs GenerateKeyPair %q: %w", algName, err)
	}
	sk := sig.ExportSecretKey()
	skCopy := make([]byte, len(sk))
	copy(skCopy, sk)
	return &Signer{
		AlgName:   algName,
		SecretKey: skCopy,
		Pub:       pub,
	}, nil
}

// VerifySignature checks signature against message using the public
// key under algName. Returns nil on success.
func VerifySignature(algName string, pub, message, signature []byte) error {
	var sig oqs.Signature
	if err := sig.Init(algName, nil); err != nil {
		return fmt.Errorf("liboqs init %q: %w", algName, err)
	}
	defer sig.Clean()
	ok, err := sig.Verify(message, signature, pub)
	if err != nil {
		return fmt.Errorf("liboqs verify %q: %w", algName, err)
	}
	if !ok {
		return ErrSig
	}
	return nil
}

// PublicKeySize returns the configured public-key length for the
// algorithm. Useful for sanity checks in algorithm subpackages.
func PublicKeySize(algName string) (int, error) {
	var sig oqs.Signature
	if err := sig.Init(algName, nil); err != nil {
		return 0, fmt.Errorf("liboqs init %q: %w", algName, err)
	}
	defer sig.Clean()
	return sig.Details().LengthPublicKey, nil
}

// MarshalBinary packs a Signer's secret + public bytes into a single
// byte slice. Layout: secret_bytes || public_bytes. Both lengths are
// fixed per algorithm, so UnmarshalBinary can split on the
// algorithm's secret-key-length boundary.
//
// liboqs-go does not expose a public-key-from-secret-key derivation,
// and several PQ algorithms in liboqs store the secret as a tiny seed
// (e.g. MAYO-1: 24 bytes; SNOVA: 48 bytes) without an in-band public
// key. Persisting both halves is the simplest reliable round-trip.
func (s *Signer) MarshalBinary() ([]byte, error) {
	out := make([]byte, 0, len(s.SecretKey)+len(s.Pub))
	out = append(out, s.SecretKey...)
	out = append(out, s.Pub...)
	return out, nil
}

// UnmarshalBinary is the inverse of MarshalBinary for a given
// algorithm. The algorithm name is supplied separately because the
// blob alone does not carry it.
func UnmarshalBinary(algName string, buf []byte) (*Signer, error) {
	var sig oqs.Signature
	if err := sig.Init(algName, nil); err != nil {
		return nil, fmt.Errorf("liboqs init %q: %w", algName, err)
	}
	defer sig.Clean()
	skLen := sig.Details().LengthSecretKey
	pkLen := sig.Details().LengthPublicKey
	if len(buf) != skLen+pkLen {
		return nil, fmt.Errorf("liboqs %q: marshaled key length %d, want %d (sk %d + pk %d)",
			algName, len(buf), skLen+pkLen, skLen, pkLen)
	}
	out := &Signer{
		AlgName:   algName,
		SecretKey: make([]byte, skLen),
		Pub:       make([]byte, pkLen),
	}
	copy(out.SecretKey, buf[:skLen])
	copy(out.Pub, buf[skLen:])
	return out, nil
}
