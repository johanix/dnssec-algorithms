// Package slhdsa128s provides a [dns.Algorithm] implementation of
// SLH-DSA-SHA2-128s (FIPS 205) for DNSSEC SIG(0) transaction signing.
//
// Algorithm number 200 is used. IANA has not assigned a codepoint for
// SLH-DSA in the DNS Security Algorithm Numbers registry; 200 is
// chosen from the Unassigned range as the codepoint right next to
// MLDSA44 at 199. Collision risk is on the user; pin the codepoint
// in deployment configuration.
//
// SLH-DSA-SHA2-128s is the small-signature, slow-signing variant at
// NIST security level 1. Signatures are 7856 bytes. RRSIG zone
// signing with these is impractical for routine DNS use; the primary
// use case for SLH-DSA in DNSSEC is SIG(0) transaction signing where
// TCP is mandatory and the conservative hash-based security model is
// attractive.
//
// Importing this package for its side effects registers the algorithm
// with [github.com/miekg/dns]:
//
//	import _ "github.com/johanix/dnssec-algorithms/slhdsa128s"
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
	"fmt"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/miekg/dns"
)

// Number is the algorithm codepoint claimed by this implementation.
// Pinned at IANA-Unassigned 200 until an IANA-assigned number exists
// for SLH-DSA in the DNS Security Algorithm Numbers registry.
const Number uint8 = 200

// ParamSet is the CIRCL SLH-DSA parameter set used by this package.
// SHA2_128s = SLH-DSA-SHA2-128s per FIPS 205.
const ParamSet = slhdsa.SHA2_128s

// Compile-time assertion that CIRCL's SLH-DSA private key satisfies
// crypto.Signer, so the shared sign() path in miekg/dns can use it.
var _ crypto.Signer = (*slhdsa.PrivateKey)(nil)

type impl struct{}

func init() {
	if err := dns.RegisterAlgorithm(&impl{}); err != nil {
		panic(fmt.Sprintf("dnssec-algorithms/slhdsa128s: registration failed: %v", err))
	}
}

func (impl) Number() uint8     { return Number }
func (impl) Name() string      { return "SLHDSA128S" }
func (impl) Hash() crypto.Hash { return 0 }

func (impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	_, priv, err := slhdsa.GenerateKey(rand.Reader, ParamSet)
	if err != nil {
		return nil, err
	}
	return &priv, nil
}

func (impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	pk := &slhdsa.PublicKey{ID: ParamSet}
	if err := pk.UnmarshalBinary(buf); err != nil {
		return nil, err
	}
	return pk, nil
}

func (impl) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
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

func (impl) ReadPrivateKey(m map[string]string) (crypto.PrivateKey, error) {
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

func (impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
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

func (impl) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
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

func (impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
