// Package mldsakey encodes and decodes ML-DSA private keys as PKCS#8
// (RFC 5958 OneAsymmetricKey), in the format RFC 9881 section 6
// specifies.
//
// RFC 9881 makes the privateKey OCTET STRING hold one arm of a CHOICE:
//
//	ML-DSA-44-PrivateKey ::= CHOICE {
//	  seed [0] OCTET STRING (SIZE (32)),
//	  expandedKey OCTET STRING (SIZE (2560)),
//	  both SEQUENCE {
//	      seed OCTET STRING (SIZE (32)),
//	      expandedKey OCTET STRING (SIZE (2560))
//	      }
//	  }
//
// (and the same for ML-DSA-65 and ML-DSA-87, with their own expanded
// sizes). The module uses IMPLICIT TAGS, so the seed arm is encoded
// as 0x80 0x20 followed by the 32 seed bytes.
//
// The seed is the only form other formats can carry: a JWK for ML-DSA
// holds the seed as "priv", and the seed cannot be recovered from the
// expanded key. Writers should therefore use [MarshalSeed] whenever
// they still have the seed.
//
// Earlier tdns and dnssec-algorithms releases wrote a pre-RFC layout:
// the raw expanded key directly in the privateKey OCTET STRING, with
// no CHOICE wrapping. [Parse] still reads it and reports it as
// [FormLegacy]. Such an OCTET STRING is exactly the expanded-key size
// long, which no RFC 9881 encoding can be (the seed arm is 34 bytes,
// the expandedKey arm adds a 4-byte header, the both arm more), so the
// length tells it apart without guessing. RFC 9881 asks parsers to
// pick the CHOICE arm by tag, not length; [Parse] does that for every
// blob that is not legacy-sized.
//
// The package is stdlib only. It does not expand seeds: that needs the
// ML-DSA implementation, which the algorithm packages own. They also
// own the consistency check of the both arm.
package mldsakey

import (
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

// SeedSize is the size of an ML-DSA key-generation seed (FIPS 204 ξ),
// the same for every parameter set.
const SeedSize = 32

// Params names one ML-DSA parameter set: its PKCS#8 algorithm OID and
// the size of its expanded private key.
type Params struct {
	Name         string
	OID          asn1.ObjectIdentifier
	ExpandedSize int
}

// The three FIPS 204 parameter sets. The OIDs are the NIST ones
// (RFC 9881 section 2); the sizes are FIPS 204 table 2.
var (
	MLDSA44 = Params{Name: "ML-DSA-44", OID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 17}, ExpandedSize: 2560}
	MLDSA65 = Params{Name: "ML-DSA-65", OID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 18}, ExpandedSize: 4032}
	MLDSA87 = Params{Name: "ML-DSA-87", OID: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, 19}, ExpandedSize: 4896}
)

var all = []Params{MLDSA44, MLDSA65, MLDSA87}

// Form says how a PKCS#8 blob stores the private key.
type Form int

const (
	// FormSeed is RFC 9881's seed arm: the 32-byte seed only.
	FormSeed Form = iota + 1
	// FormExpanded is RFC 9881's expandedKey arm: no seed.
	FormExpanded
	// FormBoth is RFC 9881's both arm: seed and expanded key.
	FormBoth
	// FormLegacy is the pre-RFC tdns layout: the raw expanded key,
	// no CHOICE wrapping, no seed.
	FormLegacy
)

func (f Form) String() string {
	switch f {
	case FormSeed:
		return "seed"
	case FormExpanded:
		return "expandedKey"
	case FormBoth:
		return "both"
	case FormLegacy:
		return "legacy (pre-RFC 9881 raw expanded key)"
	}
	return fmt.Sprintf("Form(%d)", int(f))
}

// Key is a decoded ML-DSA private key, before any seed expansion.
// Seed is nil for FormExpanded and FormLegacy; Expanded is nil for
// FormSeed.
type Key struct {
	Params   Params
	Form     Form
	Seed     []byte
	Expanded []byte
}

// oneAsymmetricKey is RFC 5958 OneAsymmetricKey. The optional
// attributes and v2 publicKey are not read, as crypto/x509 does not
// read them for the algorithms it handles.
type oneAsymmetricKey struct {
	Version    int
	Algo       pkix.AlgorithmIdentifier
	PrivateKey []byte
}

type bothArm struct {
	Seed     []byte
	Expanded []byte
}

// MarshalSeed returns the PKCS#8 DER of an ML-DSA private key in the
// seed form RFC 9881 recommends.
func MarshalSeed(p Params, seed []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("%s: seed is %d bytes, want %d", p.Name, len(seed), SeedSize)
	}
	inner, err := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: seed})
	if err != nil {
		return nil, err
	}
	return marshalOuter(p, inner)
}

// MarshalExpanded returns the PKCS#8 DER of an ML-DSA private key in
// RFC 9881's expandedKey form. Use it only for a key whose seed is
// gone; the result cannot be exported as JWK.
func MarshalExpanded(p Params, expanded []byte) ([]byte, error) {
	if len(expanded) != p.ExpandedSize {
		return nil, fmt.Errorf("%s: expanded key is %d bytes, want %d", p.Name, len(expanded), p.ExpandedSize)
	}
	inner, err := asn1.Marshal(expanded)
	if err != nil {
		return nil, err
	}
	return marshalOuter(p, inner)
}

// MarshalBoth returns the PKCS#8 DER of an ML-DSA private key in
// RFC 9881's both form. The caller vouches that expanded is the
// expansion of seed.
func MarshalBoth(p Params, seed, expanded []byte) ([]byte, error) {
	if len(seed) != SeedSize {
		return nil, fmt.Errorf("%s: seed is %d bytes, want %d", p.Name, len(seed), SeedSize)
	}
	if len(expanded) != p.ExpandedSize {
		return nil, fmt.Errorf("%s: expanded key is %d bytes, want %d", p.Name, len(expanded), p.ExpandedSize)
	}
	inner, err := asn1.Marshal(bothArm{Seed: seed, Expanded: expanded})
	if err != nil {
		return nil, err
	}
	return marshalOuter(p, inner)
}

func marshalOuter(p Params, inner []byte) ([]byte, error) {
	return asn1.Marshal(oneAsymmetricKey{
		Version:    0,
		Algo:       pkix.AlgorithmIdentifier{Algorithm: p.OID},
		PrivateKey: inner,
	})
}

// Parse decodes the PKCS#8 DER of a private key for any of the three
// ML-DSA parameter sets. It returns [dnsalgpkcs8.ErrUnsupported] when
// der is not PKCS#8 or its algorithm is not ML-DSA.
func Parse(der []byte) (Key, error) {
	outer, err := parseOuter(der)
	if err != nil {
		return Key{}, err
	}
	for _, p := range all {
		if outer.Algo.Algorithm.Equal(p.OID) {
			return parseInner(p, outer)
		}
	}
	return Key{}, dnsalgpkcs8.ErrUnsupported
}

// ParseAs is [Parse] for one parameter set: it returns
// [dnsalgpkcs8.ErrUnsupported] when der's algorithm is not p. An
// algorithm package's PKCS#8 codec uses it, so that a malformed key of
// another ML-DSA level is left to that level's codec.
func ParseAs(p Params, der []byte) (Key, error) {
	outer, err := parseOuter(der)
	if err != nil {
		return Key{}, err
	}
	if !outer.Algo.Algorithm.Equal(p.OID) {
		return Key{}, dnsalgpkcs8.ErrUnsupported
	}
	return parseInner(p, outer)
}

// Seed returns the seed stored in the PKCS#8 DER of an ML-DSA private
// key. ok is false, with a nil error, when the key is stored without
// its seed (expandedKey or legacy form): such a key can sign, but it
// cannot be exported in a format that carries only the seed, such as
// JWK. Call [Parse] to learn which form it is.
func Seed(der []byte) (seed []byte, ok bool, err error) {
	k, err := Parse(der)
	if err != nil {
		return nil, false, err
	}
	if k.Seed == nil {
		return nil, false, nil
	}
	return k.Seed, true, nil
}

func parseOuter(der []byte) (oneAsymmetricKey, error) {
	var outer oneAsymmetricKey
	rest, err := asn1.Unmarshal(der, &outer)
	if err != nil || len(rest) != 0 {
		// Not our shape: let other codecs try.
		return oneAsymmetricKey{}, dnsalgpkcs8.ErrUnsupported
	}
	return outer, nil
}

func parseInner(p Params, outer oneAsymmetricKey) (Key, error) {
	// RFC 5958: v1 (0), or v2 (1) when a publicKey is present.
	if outer.Version != 0 && outer.Version != 1 {
		return Key{}, fmt.Errorf("%s private key: PKCS#8 version %d, want 0 or 1", p.Name, outer.Version)
	}
	priv := outer.PrivateKey

	// Legacy: the raw expanded key, unwrapped. No RFC 9881 encoding
	// has this length (see the package comment).
	if len(priv) == p.ExpandedSize {
		return Key{Params: p, Form: FormLegacy, Expanded: priv}, nil
	}

	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(priv, &raw)
	if err != nil {
		return Key{}, fmt.Errorf("%s private key: %w", p.Name, err)
	}
	if len(rest) != 0 {
		return Key{}, fmt.Errorf("%s private key: %d trailing bytes after the key", p.Name, len(rest))
	}

	switch {
	case raw.Class == asn1.ClassContextSpecific && raw.Tag == 0 && !raw.IsCompound:
		if len(raw.Bytes) != SeedSize {
			return Key{}, fmt.Errorf("%s private key: seed is %d bytes, want %d", p.Name, len(raw.Bytes), SeedSize)
		}
		return Key{Params: p, Form: FormSeed, Seed: raw.Bytes}, nil

	case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagOctetString && !raw.IsCompound:
		if len(raw.Bytes) != p.ExpandedSize {
			return Key{}, fmt.Errorf("%s private key: expandedKey is %d bytes, want %d", p.Name, len(raw.Bytes), p.ExpandedSize)
		}
		return Key{Params: p, Form: FormExpanded, Expanded: raw.Bytes}, nil

	case raw.Class == asn1.ClassUniversal && raw.Tag == asn1.TagSequence && raw.IsCompound:
		var b bothArm
		rest, err := asn1.Unmarshal(raw.FullBytes, &b)
		if err != nil {
			return Key{}, fmt.Errorf("%s private key, both form: %w", p.Name, err)
		}
		if len(rest) != 0 {
			return Key{}, fmt.Errorf("%s private key, both form: %d trailing bytes", p.Name, len(rest))
		}
		if len(b.Seed) != SeedSize {
			return Key{}, fmt.Errorf("%s private key, both form: seed is %d bytes, want %d", p.Name, len(b.Seed), SeedSize)
		}
		if len(b.Expanded) != p.ExpandedSize {
			return Key{}, fmt.Errorf("%s private key, both form: expandedKey is %d bytes, want %d", p.Name, len(b.Expanded), p.ExpandedSize)
		}
		return Key{Params: p, Form: FormBoth, Seed: b.Seed, Expanded: b.Expanded}, nil
	}
	return Key{}, fmt.Errorf("%s private key: unknown encoding (class %d, tag %d)", p.Name, raw.Class, raw.Tag)
}
