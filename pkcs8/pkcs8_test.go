package pkcs8

import (
	"bytes"
	"crypto"
	"errors"
	"testing"
)

type fakeKeyA struct{ tag string }

func (fakeKeyA) Public() crypto.PublicKey { return nil }

type fakeKeyB struct{ tag string }

func (fakeKeyB) Public() crypto.PublicKey { return nil }

// codecA handles fakeKeyA and OID 0xA1.
type codecA struct{}

func (codecA) MarshalPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	k, ok := priv.(fakeKeyA)
	if !ok {
		return nil, ErrUnsupported
	}
	return append([]byte{0xA1}, []byte(k.tag)...), nil
}

func (codecA) ParsePKCS8(der []byte) (crypto.PrivateKey, error) {
	if len(der) == 0 || der[0] != 0xA1 {
		return nil, ErrUnsupported
	}
	return fakeKeyA{tag: string(der[1:])}, nil
}

// codecB handles fakeKeyB and OID 0xB2.
type codecB struct{}

func (codecB) MarshalPKCS8(priv crypto.PrivateKey) ([]byte, error) {
	k, ok := priv.(fakeKeyB)
	if !ok {
		return nil, ErrUnsupported
	}
	return append([]byte{0xB2}, []byte(k.tag)...), nil
}

func (codecB) ParsePKCS8(der []byte) (crypto.PrivateKey, error) {
	if len(der) == 0 || der[0] != 0xB2 {
		return nil, ErrUnsupported
	}
	return fakeKeyB{tag: string(der[1:])}, nil
}

// Register at init so the tests share one registry state. Note:
// Register has no Unregister and no test isolation; using fake codecs
// avoids touching the real algorithm registry of any consumer test.
func init() {
	Register(codecA{})
	Register(codecB{})
}

func TestMarshal_DispatchesToMatchingCodec(t *testing.T) {
	got, err := Marshal(fakeKeyA{tag: "alpha"})
	if err != nil {
		t.Fatalf("Marshal A: %v", err)
	}
	want := append([]byte{0xA1}, []byte("alpha")...)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal A: got %x, want %x", got, want)
	}

	got, err = Marshal(fakeKeyB{tag: "beta"})
	if err != nil {
		t.Fatalf("Marshal B: %v", err)
	}
	want = append([]byte{0xB2}, []byte("beta")...)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal B: got %x, want %x", got, want)
	}
}

func TestMarshal_ReturnsUnsupportedForUnknownType(t *testing.T) {
	_, err := Marshal("not a known key type")
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("got %v, want ErrUnsupported", err)
	}
}

func TestParse_DispatchesByOID(t *testing.T) {
	keyA, err := Parse(append([]byte{0xA1}, []byte("alpha")...))
	if err != nil {
		t.Fatalf("Parse A: %v", err)
	}
	if keyA.(fakeKeyA).tag != "alpha" {
		t.Errorf("Parse A: tag = %q, want alpha", keyA.(fakeKeyA).tag)
	}

	keyB, err := Parse(append([]byte{0xB2}, []byte("beta")...))
	if err != nil {
		t.Fatalf("Parse B: %v", err)
	}
	if keyB.(fakeKeyB).tag != "beta" {
		t.Errorf("Parse B: tag = %q, want beta", keyB.(fakeKeyB).tag)
	}
}

func TestParse_ReturnsUnsupportedForUnknownOID(t *testing.T) {
	_, err := Parse([]byte{0x99, 'x'})
	if !errors.Is(err, ErrUnsupported) {
		t.Errorf("got %v, want ErrUnsupported", err)
	}
}

func TestRoundTrip(t *testing.T) {
	orig := fakeKeyA{tag: "roundtrip"}
	der, err := Marshal(orig)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := Parse(der)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if got.(fakeKeyA).tag != orig.tag {
		t.Errorf("roundtrip: got %q, want %q", got.(fakeKeyA).tag, orig.tag)
	}
}
