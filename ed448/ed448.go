// Package ed448 provides a [dns.Algorithm] implementation of Ed448
// (RFC 8032) for DNSSEC, as RFC 8080 specifies it: pure Ed448 with an
// empty context string, not Ed448ph.
//
// IANA assigned codepoint 16 to ED448 in the DNS Security Algorithm
// Numbers registry. miekg/dns defines the constant and the name but has
// no implementation, so the number is free to register:
//
//	import (
//	    "github.com/miekg/dns"
//	    "github.com/johanix/dnssec-algorithms/ed448"
//	)
//
//	func init() {
//	    dns.RegisterAlgorithm(dns.ED448, ed448.New())
//	}
//
// Unlike the post-quantum algorithms in this module, Ed448 is a standard
// algorithm that every validator is expected to implement. It is
// therefore not a row of registry.Algorithms: tdns registers it in every
// binary rather than through a per-app algorithm list, and a generator
// reading the table must not register it a second time.
//
// All [dns.Algorithm] interface methods are implemented on top of
// github.com/cloudflare/circl/sign/ed448.
package ed448

import (
	"crypto"
	"crypto/rand"
	"encoding/base64"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/miekg/dns"
)

// Compile-time assertion that CIRCL's Ed448 private key satisfies
// crypto.Signer, so the shared sign() path in miekg/dns can use it. With
// a zero crypto.Hash as the options, CIRCL signs pure Ed448 with an
// empty context, which is what RFC 8080 requires.
var _ crypto.Signer = ed448.PrivateKey(nil)

// Impl is the Ed448 [dns.Algorithm] implementation. Construct with
// [New]; pass the returned value to [dns.RegisterAlgorithm].
type Impl struct{}

// New returns a [dns.Algorithm] implementation for Ed448.
func New() *Impl { return &Impl{} }

func (*Impl) Name() string      { return "ED448" }
func (*Impl) Hash() crypto.Hash { return 0 }

func (*Impl) Generate(bits int) (crypto.PrivateKey, error) {
	if bits != 0 {
		return nil, dns.ErrKeySize
	}
	_, priv, err := ed448.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return priv, nil
}

func (*Impl) PublicKeyFromWire(buf []byte) (crypto.PublicKey, error) {
	if len(buf) != ed448.PublicKeySize {
		return nil, dns.ErrKey
	}
	return ed448.PublicKey(append([]byte(nil), buf...)), nil
}

func (*Impl) PublicKeyToWire(pub crypto.PublicKey) ([]byte, error) {
	var p ed448.PublicKey
	switch k := pub.(type) {
	case ed448.PublicKey:
		p = k
	case *ed448.PublicKey:
		if k == nil {
			return nil, dns.ErrKey
		}
		p = *k
	default:
		return nil, dns.ErrKey
	}
	if len(p) != ed448.PublicKeySize {
		return nil, dns.ErrKey
	}
	return append([]byte(nil), p...), nil
}

// ReadPrivateKey reads the "PrivateKey:" field of a BIND-style key file:
// the base64 of the 57-byte seed, as BIND, OpenSSL-based signers and
// NLnet Labs' domain library all write it.
func (*Impl) ReadPrivateKey(m map[string]string) (crypto.PrivateKey, error) {
	v, ok := m["privatekey"]
	if !ok {
		return nil, dns.ErrPrivKey
	}
	seed, err := base64.StdEncoding.DecodeString(v)
	if err != nil {
		return nil, err
	}
	if len(seed) != ed448.SeedSize {
		return nil, dns.ErrPrivKey
	}
	return ed448.NewKeyFromSeed(seed), nil
}

func (*Impl) PrivateKeyToString(priv crypto.PrivateKey) (string, error) {
	p, ok := priv.(ed448.PrivateKey)
	if !ok || len(p) != ed448.PrivateKeySize {
		return "", dns.ErrPrivKey
	}
	return "PrivateKey: " + base64.StdEncoding.EncodeToString(p.Seed()) + "\n", nil
}

func (*Impl) Verify(pub crypto.PublicKey, hashed, sig []byte) error {
	p, ok := pub.(ed448.PublicKey)
	if !ok || len(p) != ed448.PublicKeySize {
		return dns.ErrKey
	}
	if len(sig) != ed448.SignatureSize {
		return dns.ErrSig
	}
	if ed448.Verify(p, hashed, sig, "") {
		return nil
	}
	return dns.ErrSig
}

func (*Impl) SignaturePostProcess(sig []byte) ([]byte, error) {
	return sig, nil
}
