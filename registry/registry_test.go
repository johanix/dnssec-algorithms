package registry

import "testing"

// TestTableIntegrity guards the invariants the generator and the
// runtime registration depend on: unique codepoints, unique names, no
// empty fields, a known group, and role flags that make sense.
func TestTableIntegrity(t *testing.T) {
	seenNum := map[uint8]string{}
	seenName := map[string]bool{}
	groups := map[Group]bool{PureGo: true, Liboqs: true, SQIsign: true, QRUOV: true}

	for _, a := range Algorithms {
		if a.Name == "" {
			t.Errorf("codepoint %d: empty Name", a.Codepoint)
		}
		if prev, ok := seenNum[a.Codepoint]; ok {
			t.Errorf("duplicate codepoint %d: %q and %q", a.Codepoint, prev, a.Name)
		}
		seenNum[a.Codepoint] = a.Name

		if seenName[a.Name] {
			t.Errorf("duplicate name %q", a.Name)
		}
		seenName[a.Name] = true

		if a.Package == "" {
			t.Errorf("%s: empty Package", a.Name)
		}
		if !groups[a.Group] {
			t.Errorf("%s: unknown Group %q", a.Name, a.Group)
		}

		// Role flags must be a subset of ForDNSSEC: you cannot be a
		// KSK/ZSK if you are not a DNSSEC algorithm at all.
		if (a.Caps.ForKSK || a.Caps.ForZSK) && !a.Caps.ForDNSSEC {
			t.Errorf("%s: ForKSK/ForZSK set without ForDNSSEC", a.Name)
		}
		// A DNSSEC algorithm should be usable in at least one role.
		if a.Caps.ForDNSSEC && !a.Caps.ForKSK && !a.Caps.ForZSK {
			t.Errorf("%s: ForDNSSEC but neither ForKSK nor ForZSK", a.Name)
		}
	}
}

// noRow are the algorithms with facts but no row in Algorithms: the
// miekg/dns built-ins; ED448, which this module implements (ed448/) and
// consumers register in every binary; and ML-DSA-44, which tdns implements
// and registers itself (johanix/tdns#760).
var noRow = map[string]bool{
	"ED25519": true, "ED448": true, "ECDSAP256SHA256": true, "ECDSAP384SHA384": true,
	"RSASHA256": true, "RSASHA512": true, "MLDSA44": true,
}

// TestFactsCoverage guards that AlgorithmFacts (external, name-keyed
// static facts) stays in step with the Algorithms decisions table: every
// registry algorithm has a facts entry, and every facts entry is either a
// registry algorithm or one of noRow (not a typo'd orphan).
func TestFactsCoverage(t *testing.T) {
	inRegistry := map[string]bool{}
	for _, a := range Algorithms {
		inRegistry[a.Name] = true
		if _, ok := AlgorithmFacts[a.Name]; !ok {
			t.Errorf("%s: no AlgorithmFacts entry (every registry algorithm needs one)", a.Name)
		}
	}

	for name, f := range AlgorithmFacts {
		if !inRegistry[name] && !noRow[name] {
			t.Errorf("AlgorithmFacts[%q]: not a registry algorithm and not one of the algorithms kept out of it (typo?)", name)
		}
		// Sizes are spec-fixed and non-zero for every real algorithm.
		if f.PubKeyBytes <= 0 || f.SigBytes <= 0 {
			t.Errorf("AlgorithmFacts[%q]: PubKeyBytes/SigBytes must be > 0 (got %d/%d)", name, f.PubKeyBytes, f.SigBytes)
		}
	}
}

// An algorithm that its consumers register in every binary must not come
// back as a row: a generator would then register it a second time.
func TestAlwaysRegisteredAlgorithmsHaveNoRow(t *testing.T) {
	for _, a := range Algorithms {
		if a.Name == "ED448" || a.Name == "MLDSA44" || a.Codepoint == 16 || a.Codepoint == 18 {
			t.Errorf("%s (codepoint %d) is registered in every binary and must not be a row", a.Name, a.Codepoint)
		}
	}
}
