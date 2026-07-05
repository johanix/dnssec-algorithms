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
