package mldsa65

import (
	"bytes"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"

	"github.com/johanix/dnssec-algorithms/mldsakey"
	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

// readRFCKey returns the DER of one of RFC 9881's Appendix C.1
// example keys, all derived from the seed 000102...1e1f. The files are
// kept with the mldsakey package.
func readRFCKey(t *testing.T, form string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "mldsakey", "testdata", "rfc9881-mldsa65-"+form+".pem"))
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("%s: no PRIVATE KEY block", form)
	}
	return block.Bytes
}

func rfcSeed() []byte {
	s := make([]byte, mldsa65.SeedSize)
	for i := range s {
		s[i] = byte(i)
	}
	return s
}

func parse(t *testing.T, der []byte) *mldsa65.PrivateKey {
	t.Helper()
	priv, err := dnsalgpkcs8.Parse(der)
	if err != nil {
		t.Fatalf("pkcs8.Parse: %v", err)
	}
	sk, ok := priv.(*mldsa65.PrivateKey)
	if !ok {
		t.Fatalf("pkcs8.Parse returned %T, want *mldsa65.PrivateKey", priv)
	}
	return sk
}

// legacyDER is the pre-RFC 9881 layout earlier releases wrote: the raw
// expanded key in the privateKey OCTET STRING.
func legacyDER(t *testing.T, sk *mldsa65.PrivateKey) []byte {
	t.Helper()
	type algorithmIdentifier struct {
		Algorithm asn1.ObjectIdentifier
	}
	type privateKeyInfo struct {
		Version    int
		Algo       algorithmIdentifier
		PrivateKey []byte
	}
	der, err := asn1.Marshal(privateKeyInfo{
		Algo:       algorithmIdentifier{Algorithm: params.OID},
		PrivateKey: sk.Bytes(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// signs checks that sk makes a signature its public key verifies.
func signs(t *testing.T, sk *mldsa65.PrivateKey) {
	t.Helper()
	msg := []byte("example.com. RRSIG input")
	sig, err := sk.Sign(nil, msg, nil)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := New().Verify(sk.Public(), msg, sig); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestPKCS8RoundTrip(t *testing.T) {
	priv, err := New().Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sk := priv.(*mldsa65.PrivateKey)

	der, err := dnsalgpkcs8.Marshal(sk)
	if err != nil {
		t.Fatalf("pkcs8.Marshal: %v", err)
	}
	sk2 := parse(t, der)
	if !sk.Equal(sk2) {
		t.Errorf("round-tripped key does not equal original")
	}

	// Re-marshal the parsed key and confirm byte-for-byte equality
	// with the first marshal — exercises the codec's determinism.
	der2, err := dnsalgpkcs8.Marshal(sk2)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(der, der2) {
		t.Error("re-marshaled DER differs from original")
	}
}

// TestGenerateKeepsSeed: a generated key keeps its seed, and is
// stored in RFC 9881's seed form.
func TestGenerateKeepsSeed(t *testing.T) {
	priv, err := New().Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sk := priv.(*mldsa65.PrivateKey)
	if len(sk.Seed()) != mldsa65.SeedSize {
		t.Fatalf("generated key has no seed")
	}
	der, err := dnsalgpkcs8.Marshal(sk)
	if err != nil {
		t.Fatalf("pkcs8.Marshal: %v", err)
	}
	k, err := mldsakey.Parse(der)
	if err != nil {
		t.Fatalf("mldsakey.Parse: %v", err)
	}
	if k.Form != mldsakey.FormSeed {
		t.Errorf("stored in %s form, want seed", k.Form)
	}
	seed, ok, err := mldsakey.Seed(der)
	if err != nil || !ok || !bytes.Equal(seed, sk.Seed()) {
		t.Errorf("mldsakey.Seed: %x, %v, %v; want the generated seed", seed, ok, err)
	}
	signs(t, parse(t, der))
}

// TestMarshalForms: what each kind of loaded key is written as. RFC
// 9881's example keys are re-marshaled byte for byte.
func TestMarshalForms(t *testing.T) {
	for _, tc := range []struct {
		in, out string
	}{
		{"seed", "seed"},
		{"both", "seed"},
		{"expanded", "expanded"},
	} {
		der, err := dnsalgpkcs8.Marshal(parse(t, readRFCKey(t, tc.in)))
		if err != nil {
			t.Fatalf("%s: pkcs8.Marshal: %v", tc.in, err)
		}
		if !bytes.Equal(der, readRFCKey(t, tc.out)) {
			t.Errorf("a key read from the %s form is not written as the RFC's %s form", tc.in, tc.out)
		}
	}

	// A legacy key has no seed: it is written in the standard
	// expandedKey form, not in the legacy layout.
	legacy := parse(t, legacyDER(t, parse(t, readRFCKey(t, "expanded"))))
	der, err := dnsalgpkcs8.Marshal(legacy)
	if err != nil {
		t.Fatalf("legacy: pkcs8.Marshal: %v", err)
	}
	if !bytes.Equal(der, readRFCKey(t, "expanded")) {
		t.Error("a legacy key is not written in the RFC's expandedKey form")
	}
}

// TestPKCS8RFC9881 reads the three RFC 9881 example forms. All must
// give the same key, the seed forms with the seed kept.
func TestPKCS8RFC9881(t *testing.T) {
	fromSeed := parse(t, readRFCKey(t, "seed"))
	fromExpanded := parse(t, readRFCKey(t, "expanded"))
	fromBoth := parse(t, readRFCKey(t, "both"))

	if !fromSeed.Equal(fromExpanded) || !fromSeed.Equal(fromBoth) {
		t.Fatal("the three RFC 9881 forms give different keys")
	}
	if !bytes.Equal(fromSeed.Seed(), rfcSeed()) || !bytes.Equal(fromBoth.Seed(), rfcSeed()) {
		t.Errorf("seed not kept: seed form %x, both form %x", fromSeed.Seed(), fromBoth.Seed())
	}
	if fromExpanded.Seed() != nil {
		t.Errorf("expandedKey form reports a seed: %x", fromExpanded.Seed())
	}
	signs(t, fromSeed)
	signs(t, fromExpanded)
}

// TestPKCS8Legacy: keys written by earlier releases still load and
// sign.
func TestPKCS8Legacy(t *testing.T) {
	want := parse(t, readRFCKey(t, "expanded"))
	sk := parse(t, legacyDER(t, want))
	if !sk.Equal(want) {
		t.Fatal("legacy key differs from the key it was made from")
	}
	if sk.Seed() != nil {
		t.Errorf("legacy key reports a seed: %x", sk.Seed())
	}
	signs(t, sk)
}

// TestPKCS8BothMismatch: a both-form key whose halves disagree is
// refused, not loaded from either half.
func TestPKCS8BothMismatch(t *testing.T) {
	k, err := mldsakey.Parse(readRFCKey(t, "both"))
	if err != nil {
		t.Fatal(err)
	}

	otherSeed := rfcSeed()
	otherSeed[0] ^= 0xff
	flippedExp := bytes.Clone(k.Expanded)
	flippedExp[len(flippedExp)-1] ^= 0x01

	for name, halves := range map[string][2][]byte{
		"other seed":            {otherSeed, k.Expanded},
		"expanded key modified": {k.Seed, flippedExp},
	} {
		der, err := mldsakey.MarshalBoth(params, halves[0], halves[1])
		if err != nil {
			t.Fatal(err)
		}
		_, err = dnsalgpkcs8.Parse(der)
		if err == nil || errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
			t.Errorf("%s: got %v, want the key refused", name, err)
		}
	}
}

func TestPKCS8MarshalRejectsWrongType(t *testing.T) {
	c := pkcs8Codec{}
	_, err := c.MarshalPKCS8("not a key")
	if !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("got %v, want ErrUnsupported", err)
	}
}

func TestPKCS8ParseRejectsWrongOID(t *testing.T) {
	c := pkcs8Codec{}
	// Valid ASN.1 PrivateKeyInfo shape with a different OID. The
	// inner OID 2.16.840.1.101.3.4.3.99 is not assigned to ML-DSA-65.
	// We synthesize it by editing a real marshaled ML-DSA-65 key.
	_, sk, err := mldsa65.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := c.MarshalPKCS8(sk)
	if err != nil {
		t.Fatalf("MarshalPKCS8 setup: %v", err)
	}
	// The OID's last component is 18 in the encoding. Find its
	// position by scanning for the OID prefix bytes and flip the
	// trailing 18 to 99 (both single-byte values).
	prefix := []byte{0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x03}
	i := bytes.Index(der, prefix)
	if i < 0 || i+len(prefix) >= len(der) {
		t.Fatalf("could not locate ML-DSA OID prefix in DER")
	}
	if der[i+len(prefix)] != 18 {
		t.Fatalf("expected OID last component 18, got %d", der[i+len(prefix)])
	}
	der[i+len(prefix)] = 99
	_, err = c.ParsePKCS8(der)
	if !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("got %v, want ErrUnsupported", err)
	}
}
