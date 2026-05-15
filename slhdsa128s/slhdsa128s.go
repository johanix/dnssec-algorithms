// Package slhdsa128s provides a [dns.Algorithm] implementation of
// SLH-DSA-SHA2-128s (FIPS 205) for DNSSEC SIG(0) transaction signing.
//
// The codepoint is chosen by the application at registration time:
//
//	dns.RegisterAlgorithm(200, slhdsa128s.New())
//
// IANA has not assigned a codepoint for SLH-DSA in the DNS Security
// Algorithm Numbers registry; 200 is commonly chosen from the
// Unassigned range, but the application is free to pick another.
//
// SLH-DSA-SHA2-128s is the small-signature, slow-signing variant at
// NIST security level 1. Signatures are 7856 bytes. RRSIG zone
// signing with these is impractical for routine DNS use; the primary
// use case for SLH-DSA in DNSSEC is SIG(0) transaction signing where
// TCP is mandatory and the conservative hash-based security model is
// attractive.
//
// The CIRCL backend ([github.com/cloudflare/circl/sign/slhdsa]) is
// pure Go — no cgo, no external C library required.
//
// Signing path: [crypto.Signer.Sign] on a CIRCL SLH-DSA private key
// wraps the input bytes per FIPS 205 §10.2 (pure mode with empty
// context): the signer actually signs 0x00 || 0x00 || input. The
// shared miekg/dns sign path passes the wire-format bytes through
// unchanged (Hash returns 0 — identity), so this wrap is applied
// consistently on both sign and verify ends.
package slhdsa128s

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/miekg/dns"
)

// ParamSet is the CIRCL SLH-DSA parameter set used by this package.
// SHA2_128s = SLH-DSA-SHA2-128s per FIPS 205.
const ParamSet = slhdsa.SHA2_128s

// Compile-time assertion that CIRCL's SLH-DSA private key satisfies
// crypto.Signer, so the shared sign() path in miekg/dns can use it.
var _ crypto.Signer = (*slhdsa.PrivateKey)(nil)

// Impl is the SLH-DSA-SHA2-128s [dns.Algorithm] implementation.
// Construct with [New]; pass the returned value to
// [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for SLH-DSA-SHA2-128s.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "SLHDSA128S" }
func (*Impl) Hash() crypto.Hash { return 0 }

func (*Impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	_, priv, err := slhdsa.GenerateKey(rand.Reader, ParamSet)
	if err != nil {
		return nil, err
	}
	return &priv, nil
}

func (*Impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	pk := &slhdsa.PublicKey{ID: ParamSet}
	if err := pk.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return pk, nil
}

func (*Impl) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	// CIRCL's slhdsa.PrivateKey.Public() returns a slhdsa.PublicKey
	// by value, but other call paths produce a pointer. Accept both.
	switch p := pub.(type) {
	case *slhdsa.PublicKey:
		return p.MarshalBinary()
	case slhdsa.PublicKey:
		return p.MarshalBinary()
	default:
		return nil, dns.ErrKey
	}
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
	p := &slhdsa.PrivateKey{ID: ParamSet}
	if err := p.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return p, nil
}

func (*Impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	p, ok := priv.(*slhdsa.PrivateKey)
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
	var p *slhdsa.PublicKey
	switch v := pub.(type) {
	case *slhdsa.PublicKey:
		p = v
	case slhdsa.PublicKey:
		p = &v
	default:
		return dns.ErrKey
	}
	if slhdsa.Verify(p, slhdsa.NewMessage(hashed), sig, nil) {
		return nil
	}
	return dns.ErrSig
}

func (*Impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
