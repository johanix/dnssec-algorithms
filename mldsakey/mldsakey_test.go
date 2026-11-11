package mldsakey

import (
	"bytes"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

// The testdata/rfc9881-*.pem files are the example private keys of
// RFC 9881 Appendix C.1, all derived from the seed 000102...1e1f.

func rfcSeed() []byte {
	s := make([]byte, SeedSize)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

// readRFCKey returns the DER of testdata/rfc9881-<name>.pem.
func readRFCKey(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", "rfc9881-"+name+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("%s: no PRIVATE KEY block", name)
	}
	return block.Bytes
}

var levels = []struct {
	file string
	p    Params
}{
	{"mldsa44", MLDSA44},
	{"mldsa65", MLDSA65},
	{"mldsa87", MLDSA87},
}

// TestRFC9881Examples parses every RFC 9881 example and re-marshals
// it, byte for byte.
func TestRFC9881Examples(t *testing.T) {
	for _, l := range levels {
		t.Run(l.p.Name, func(t *testing.T) {
			seedDER := readRFCKey(t, l.file+"-seed")
			expDER := readRFCKey(t, l.file+"-expanded")
			bothDER := readRFCKey(t, l.file+"-both")

			seedKey, err := Parse(seedDER)
			if err != nil {
				t.Fatalf("Parse(seed): %v", err)
			}
			if seedKey.Form != FormSeed || seedKey.Params.Name != l.p.Name {
				t.Fatalf("seed example parsed as %s %s", seedKey.Params.Name, seedKey.Form)
			}
			if !bytes.Equal(seedKey.Seed, rfcSeed()) || seedKey.Expanded != nil {
				t.Fatalf("seed example: seed %x, expanded %d bytes", seedKey.Seed, len(seedKey.Expanded))
			}

			expKey, err := Parse(expDER)
			if err != nil {
				t.Fatalf("Parse(expanded): %v", err)
			}
			if expKey.Form != FormExpanded || expKey.Seed != nil || len(expKey.Expanded) != l.p.ExpandedSize {
				t.Fatalf("expanded example parsed as %s, seed %x, expanded %d bytes", expKey.Form, expKey.Seed, len(expKey.Expanded))
			}

			bothKey, err := Parse(bothDER)
			if err != nil {
				t.Fatalf("Parse(both): %v", err)
			}
			if bothKey.Form != FormBoth || !bytes.Equal(bothKey.Seed, rfcSeed()) || !bytes.Equal(bothKey.Expanded, expKey.Expanded) {
				t.Fatalf("both example parsed as %s, or its halves differ from the seed and expanded examples", bothKey.Form)
			}

			got, err := MarshalSeed(l.p, rfcSeed())
			if err != nil || !bytes.Equal(got, seedDER) {
				t.Errorf("MarshalSeed differs from the RFC example (err %v)", err)
			}
			got, err = MarshalExpanded(l.p, expKey.Expanded)
			if err != nil || !bytes.Equal(got, expDER) {
				t.Errorf("MarshalExpanded differs from the RFC example (err %v)", err)
			}
			got, err = MarshalBoth(l.p, rfcSeed(), expKey.Expanded)
			if err != nil || !bytes.Equal(got, bothDER) {
				t.Errorf("MarshalBoth differs from the RFC example (err %v)", err)
			}
		})
	}
}

// legacyDER builds the pre-RFC layout: the raw expanded key straight
// in the privateKey OCTET STRING.
func legacyDER(t *testing.T, p Params, expanded []byte) []byte {
	t.Helper()
	der, err := asn1.Marshal(oneAsymmetricKey{
		Algo:       pkix.AlgorithmIdentifier{Algorithm: p.OID},
		PrivateKey: expanded,
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func TestParseLegacy(t *testing.T) {
	for _, l := range levels {
		t.Run(l.p.Name, func(t *testing.T) {
			expKey, err := Parse(readRFCKey(t, l.file+"-expanded"))
			if err != nil {
				t.Fatal(err)
			}
			k, err := Parse(legacyDER(t, l.p, expKey.Expanded))
			if err != nil {
				t.Fatalf("Parse(legacy): %v", err)
			}
			if k.Form != FormLegacy || k.Seed != nil || !bytes.Equal(k.Expanded, expKey.Expanded) {
				t.Fatalf("legacy parsed as %s, seed %x", k.Form, k.Seed)
			}
		})
	}
}

// TestParseLegacyLeadingTagByte: a legacy key whose first byte looks
// like a CHOICE tag is still legacy. The length decides, not the tag.
func TestParseLegacyLeadingTagByte(t *testing.T) {
	for _, first := range []byte{0x04, 0x30, 0x80} {
		raw := make([]byte, MLDSA44.ExpandedSize)
		raw[0] = first
		k, err := ParseAs(MLDSA44, legacyDER(t, MLDSA44, raw))
		if err != nil || k.Form != FormLegacy {
			t.Errorf("first byte %#x: form %v, err %v; want legacy", first, k.Form, err)
		}
	}
}

func TestSeed(t *testing.T) {
	for _, tc := range []struct {
		name   string
		wantOK bool
	}{
		{"mldsa65-seed", true},
		{"mldsa65-both", true},
		{"mldsa65-expanded", false},
	} {
		seed, ok, err := Seed(readRFCKey(t, tc.name))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if ok != tc.wantOK {
			t.Errorf("%s: ok %v, want %v", tc.name, ok, tc.wantOK)
		}
		if ok && !bytes.Equal(seed, rfcSeed()) {
			t.Errorf("%s: seed %x", tc.name, seed)
		}
		if !ok && seed != nil {
			t.Errorf("%s: no seed reported, but got %x", tc.name, seed)
		}
	}

	expKey, err := Parse(readRFCKey(t, "mldsa44-expanded"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := Seed(legacyDER(t, MLDSA44, expKey.Expanded)); ok || err != nil {
		t.Errorf("legacy key: ok %v, err %v; want no seed, no error", ok, err)
	}
}

func TestParseAsWrongLevel(t *testing.T) {
	_, err := ParseAs(MLDSA44, readRFCKey(t, "mldsa65-seed"))
	if !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("ML-DSA-65 key as ML-DSA-44: got %v, want ErrUnsupported", err)
	}
}

func TestParseNotMLDSA(t *testing.T) {
	ed25519OID := asn1.ObjectIdentifier{1, 3, 101, 112}
	der, err := asn1.Marshal(oneAsymmetricKey{
		Algo:       pkix.AlgorithmIdentifier{Algorithm: ed25519OID},
		PrivateKey: make([]byte, 34),
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, in := range map[string][]byte{
		"ed25519": der,
		"garbage": []byte("not DER at all"),
		"empty":   nil,
	} {
		if _, err := Parse(in); !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
			t.Errorf("%s: got %v, want ErrUnsupported", name, err)
		}
	}
}

// TestParseMalformed: an ML-DSA OID with a broken private key is an
// error, not ErrUnsupported, so no other codec claims it.
func TestParseMalformed(t *testing.T) {
	short := make([]byte, SeedSize-1)
	shortSeed, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: short})
	wrongExp, _ := asn1.Marshal(make([]byte, MLDSA44.ExpandedSize-1))
	bothShort, _ := asn1.Marshal(bothArm{Seed: short, Expanded: make([]byte, MLDSA44.ExpandedSize)})
	otherTag, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 1, Bytes: rfcSeed()})
	seedArm, _ := asn1.Marshal(asn1.RawValue{Class: asn1.ClassContextSpecific, Tag: 0, Bytes: rfcSeed()})
	trailing := append(append([]byte{}, seedArm...), 0x00)

	for name, inner := range map[string][]byte{
		"short seed":      shortSeed,
		"short expanded":  wrongExp,
		"both short seed": bothShort,
		"unknown tag":     otherTag,
		"trailing bytes":  trailing,
	} {
		der, err := asn1.Marshal(oneAsymmetricKey{
			Algo:       pkix.AlgorithmIdentifier{Algorithm: MLDSA44.OID},
			PrivateKey: inner,
		})
		if err != nil {
			t.Fatal(err)
		}
		_, err = Parse(der)
		if err == nil || errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
			t.Errorf("%s: got %v, want a decode error", name, err)
		}
	}

	v2, _ := asn1.Marshal(oneAsymmetricKey{Version: 2, Algo: pkix.AlgorithmIdentifier{Algorithm: MLDSA44.OID}, PrivateKey: seedArm})
	if _, err := Parse(v2); err == nil || errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("version 2: got %v, want a decode error", err)
	}
}

func TestMarshalRejectsWrongSizes(t *testing.T) {
	if _, err := MarshalSeed(MLDSA44, make([]byte, 31)); err == nil {
		t.Error("MarshalSeed accepted a 31-byte seed")
	}
	if _, err := MarshalExpanded(MLDSA44, make([]byte, MLDSA65.ExpandedSize)); err == nil {
		t.Error("MarshalExpanded accepted an ML-DSA-65-sized key for ML-DSA-44")
	}
	if _, err := MarshalBoth(MLDSA87, rfcSeed(), make([]byte, MLDSA44.ExpandedSize)); err == nil {
		t.Error("MarshalBoth accepted a wrong-sized expanded key")
	}
}
