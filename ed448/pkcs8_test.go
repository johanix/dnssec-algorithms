package ed448

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/cloudflare/circl/sign/ed448"

	dnsalgpkcs8 "github.com/johanix/dnssec-algorithms/pkcs8"
)

func TestPKCS8RoundTrip(t *testing.T) {
	_, sk, err := ed448.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := dnsalgpkcs8.Marshal(sk)
	if err != nil {
		t.Fatalf("pkcs8.Marshal: %v", err)
	}
	parsed, err := dnsalgpkcs8.Parse(der)
	if err != nil {
		t.Fatalf("pkcs8.Parse: %v", err)
	}
	sk2, ok := parsed.(ed448.PrivateKey)
	if !ok {
		t.Fatalf("pkcs8.Parse returned %T, want ed448.PrivateKey", parsed)
	}
	if !sk.Equal(sk2) {
		t.Error("round-tripped key does not equal the original")
	}
	der2, err := dnsalgpkcs8.Marshal(sk2)
	if err != nil {
		t.Fatalf("re-Marshal: %v", err)
	}
	if !bytes.Equal(der, der2) {
		t.Error("re-marshaled DER differs from the original")
	}
}

// TestPKCS8OpenSSL checks the codec against OpenSSL: a PEM from
// `openssl genpkey -algorithm ED448` parses (the standard library does
// not know the OID, so the registry path is the one taken), its public
// key is OpenSSL's, marshaling it again gives OpenSSL's exact DER, and a
// signature OpenSSL made verifies.
func TestPKCS8OpenSSL(t *testing.T) {
	pemBytes, err := os.ReadFile("testdata/openssl/ed448.pem")
	if err != nil {
		t.Fatal(err)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil || block.Type != "PRIVATE KEY" {
		t.Fatalf("testdata/openssl/ed448.pem: no PRIVATE KEY block")
	}
	if _, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		t.Log("note: the standard library now parses Ed448 PKCS#8 itself")
	}

	parsed, err := dnsalgpkcs8.Parse(block.Bytes)
	if err != nil {
		t.Fatalf("pkcs8.Parse: %v", err)
	}
	sk, ok := parsed.(ed448.PrivateKey)
	if !ok {
		t.Fatalf("pkcs8.Parse returned %T, want ed448.PrivateKey", parsed)
	}

	wantPub := readB64File(t, "testdata/openssl/ed448.pub.b64")
	if got := []byte(sk.Public().(ed448.PublicKey)); !bytes.Equal(got, wantPub) {
		t.Errorf("public key differs from OpenSSL's\n ours:    %x\n openssl: %x", got, wantPub)
	}

	der, err := dnsalgpkcs8.Marshal(sk)
	if err != nil {
		t.Fatalf("pkcs8.Marshal: %v", err)
	}
	if !bytes.Equal(der, block.Bytes) {
		t.Errorf("marshaled DER differs from OpenSSL's\n ours:    %x\n openssl: %x", der, block.Bytes)
	}

	msg, err := os.ReadFile("testdata/openssl/msg.txt")
	if err != nil {
		t.Fatal(err)
	}
	sig := readB64File(t, "testdata/openssl/sig.b64")
	if err := New().Verify(ed448.PublicKey(wantPub), msg, sig); err != nil {
		t.Errorf("OpenSSL's signature does not verify: %v", err)
	}
	if ours, err := sk.Sign(nil, msg, crypto.Hash(0)); err != nil {
		t.Errorf("Sign: %v", err)
	} else if !bytes.Equal(ours, sig) {
		t.Errorf("our signature of msg.txt differs from OpenSSL's")
	}
}

func TestPKCS8MarshalRejectsWrongType(t *testing.T) {
	c := pkcs8Codec{}
	if _, err := c.MarshalPKCS8("not a key"); !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("MarshalPKCS8(string): err = %v, want ErrUnsupported", err)
	}
}

func TestPKCS8ParseRejectsOtherOID(t *testing.T) {
	// Our own DER with the OID changed to id-Ed25519: same shape, other OID.
	_, sk, err := ed448.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	der, err := dnsalgpkcs8.Marshal(sk)
	if err != nil {
		t.Fatal(err)
	}
	// id-Ed448 is 06 03 2b 65 71; id-Ed25519 is 06 03 2b 65 70.
	other := bytes.Replace(der, []byte{0x06, 0x03, 0x2b, 0x65, 0x71}, []byte{0x06, 0x03, 0x2b, 0x65, 0x70}, 1)
	if _, err := (pkcs8Codec{}).ParsePKCS8(other); !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("ParsePKCS8(Ed25519 OID): err = %v, want ErrUnsupported", err)
	}
	if _, err := (pkcs8Codec{}).ParsePKCS8([]byte("garbage")); !errors.Is(err, dnsalgpkcs8.ErrUnsupported) {
		t.Errorf("ParsePKCS8(garbage): err = %v, want ErrUnsupported", err)
	}
}

func readB64File(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	b, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return b
}
