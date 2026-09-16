package ed448

import (
	"crypto"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/ed448"
	"github.com/miekg/dns"
)

// Register the algorithm at test-binary init time under its IANA
// codepoint, so the tests exercise the full miekg/dns dispatch path.
func init() {
	if err := dns.RegisterAlgorithm(dns.ED448, New()); err != nil {
		panic("ed448 test init: RegisterAlgorithm: " + err.Error())
	}
}

func TestRegistered(t *testing.T) {
	if name := dns.AlgorithmToString[dns.ED448]; name != "ED448" {
		t.Errorf("AlgorithmToString[%d] = %q, want ED448", dns.ED448, name)
	}
	if h := dns.AlgorithmToHash[dns.ED448]; h != 0 {
		t.Errorf("AlgorithmToHash[%d] = %v, want 0 (identity)", dns.ED448, h)
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: dns.ED448,
	}
	priv, err := dnskey.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sk, ok := priv.(ed448.PrivateKey)
	if !ok {
		t.Fatalf("Generate returned %T, want ed448.PrivateKey", priv)
	}
	if n := len(mustB64(t, dnskey.PublicKey)); n != ed448.PublicKeySize {
		t.Fatalf("DNSKEY public key is %d bytes, want %d", n, ed448.PublicKeySize)
	}

	s := dnskey.PrivateKeyString(sk)
	if !strings.Contains(s, "Algorithm: 16 (ED448)") {
		t.Errorf("PrivateKeyString missing algorithm line:\n%s", s)
	}
	parsed, err := dnskey.NewPrivateKey(s)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	if !sk.Equal(parsed) {
		t.Error("round-tripped private key differs from the original")
	}
}

func TestGenerateRejectsBits(t *testing.T) {
	if _, err := New().Generate(456); err != dns.ErrKeySize {
		t.Errorf("Generate(456) err = %v, want ErrKeySize", err)
	}
}

func TestSignVerifyRRset(t *testing.T) {
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     256,
		Protocol:  3,
		Algorithm: dns.ED448,
	}
	priv, err := dnskey.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	rrset := []dns.RR{mustRR(t, "example. 3600 IN MX 10 mail.example.")}
	sig := newRRSIG(dnskey)
	if err := sig.Sign(priv.(crypto.Signer), rrset); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if n := len(mustB64(t, sig.Signature)); n != ed448.SignatureSize {
		t.Errorf("signature is %d bytes, want %d", n, ed448.SignatureSize)
	}
	if err := sig.Verify(dnskey, rrset); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	tampered := []dns.RR{mustRR(t, "example. 3600 IN MX 20 mail.example.")}
	if err := sig.Verify(dnskey, tampered); err == nil {
		t.Error("Verify accepted a signature over a different RRset")
	}
}

// TestBINDSignedZone checks the package against BIND 9: every RRSIG in a
// zone BIND signed with Ed448 verifies, and signing the same RRset with
// BIND's private key and the same RRSIG fields reproduces BIND's
// signature byte for byte (Ed448 is deterministic). A mismatch in the
// seed interpretation, the context string or Ed448 vs Ed448ph shows up
// here.
func TestBINDSignedZone(t *testing.T) {
	dnskey, priv := readKeyPair(t, "testdata/bind/Kexample.+016+04850")

	f, err := os.Open("testdata/bind/example.zone.signed")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	rrsets := map[string][]dns.RR{}
	var sigs []*dns.RRSIG
	zp := dns.NewZoneParser(f, "example.", "example.zone.signed")
	for rr, ok := zp.Next(); ok; rr, ok = zp.Next() {
		if s, isSig := rr.(*dns.RRSIG); isSig {
			sigs = append(sigs, s)
			continue
		}
		key := dns.CanonicalName(rr.Header().Name) + "/" + dns.TypeToString[rr.Header().Rrtype]
		rrsets[key] = append(rrsets[key], rr)
	}
	if err := zp.Err(); err != nil {
		t.Fatalf("parsing the signed zone: %v", err)
	}
	if len(sigs) == 0 {
		t.Fatal("no RRSIGs in the BIND fixture")
	}

	for _, s := range sigs {
		key := dns.CanonicalName(s.Hdr.Name) + "/" + dns.TypeToString[s.TypeCovered]
		rrset := rrsets[key]
		if len(rrset) == 0 {
			t.Errorf("%s: RRSIG without its RRset", key)
			continue
		}
		if s.KeyTag != dnskey.KeyTag() {
			t.Errorf("%s: key tag %d, want %d", key, s.KeyTag, dnskey.KeyTag())
			continue
		}
		if err := s.Verify(dnskey, rrset); err != nil {
			t.Errorf("%s: BIND's RRSIG does not verify: %v", key, err)
			continue
		}

		ours := &dns.RRSIG{
			Hdr:         s.Hdr,
			TypeCovered: s.TypeCovered,
			Algorithm:   s.Algorithm,
			Labels:      s.Labels,
			OrigTtl:     s.OrigTtl,
			Expiration:  s.Expiration,
			Inception:   s.Inception,
			KeyTag:      s.KeyTag,
			SignerName:  s.SignerName,
		}
		if err := ours.Sign(priv, rrset); err != nil {
			t.Errorf("%s: Sign: %v", key, err)
			continue
		}
		if ours.Signature != s.Signature {
			t.Errorf("%s: signature differs from BIND's\n ours: %s\n bind: %s", key, ours.Signature, s.Signature)
		}
	}
}

// TestDomainKeyFile reads a key pair written by NLnet Labs' domain
// library (Private-key-format v1.2, as Cascade and dnst write it): the
// private seed must produce the public key in the .key file.
func TestDomainKeyFile(t *testing.T) {
	dnskey, priv := readKeyPair(t, "testdata/domain/Ktest.+016+07379")
	if tag := dnskey.KeyTag(); tag != 7379 {
		t.Errorf("key tag %d, want 7379", tag)
	}
	wire, err := New().PublicKeyToWire(priv.Public())
	if err != nil {
		t.Fatalf("PublicKeyToWire: %v", err)
	}
	if got := base64.StdEncoding.EncodeToString(wire); got != dnskey.PublicKey {
		t.Errorf("public key from the private seed differs from the .key file\n seed: %s\n file: %s", got, dnskey.PublicKey)
	}

	rrset := []dns.RR{mustRR(t, "test. 3600 IN TXT \"domain interop\"")}
	sig := newRRSIG(dnskey)
	if err := sig.Sign(priv, rrset); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := sig.Verify(dnskey, rrset); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

func TestReadPrivateKeyRejectsWrongSize(t *testing.T) {
	short := base64.StdEncoding.EncodeToString(make([]byte, ed448.SeedSize-1))
	if _, err := New().ReadPrivateKey(map[string]string{"privatekey": short}); err != dns.ErrPrivKey {
		t.Errorf("56-byte seed: err = %v, want ErrPrivKey", err)
	}
	if _, err := New().ReadPrivateKey(map[string]string{}); err != dns.ErrPrivKey {
		t.Errorf("missing field: err = %v, want ErrPrivKey", err)
	}
}

func TestPublicKeyFromWireRejectsWrongSize(t *testing.T) {
	if _, err := New().PublicKeyFromWire(make([]byte, 32)); err != dns.ErrKey {
		t.Errorf("32-byte key: err = %v, want ErrKey", err)
	}
}

func readKeyPair(t *testing.T, base string) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	pub, err := os.ReadFile(base + ".key")
	if err != nil {
		t.Fatal(err)
	}
	rr, err := dns.NewRR(firstRecordLine(string(pub)))
	if err != nil {
		t.Fatalf("%s.key: %v", base, err)
	}
	dnskey, ok := rr.(*dns.DNSKEY)
	if !ok {
		t.Fatalf("%s.key holds %T, want *dns.DNSKEY", base, rr)
	}
	f, err := os.Open(base + ".private")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	priv, err := dnskey.ReadPrivateKey(f, filepath.Base(base)+".private")
	if err != nil {
		t.Fatalf("%s.private: %v", base, err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("%s.private: %T is not a crypto.Signer", base, priv)
	}
	return dnskey, signer
}

// firstRecordLine skips the ';' comment lines BIND puts at the top of a
// .key file.
func firstRecordLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if l := strings.TrimSpace(line); l != "" && !strings.HasPrefix(l, ";") {
			return line
		}
	}
	return ""
}

func newRRSIG(k *dns.DNSKEY) *dns.RRSIG {
	now := time.Now()
	return &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: k.Hdr.Name, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  dns.ED448,
		Inception:  uint32(now.Add(-time.Hour).Unix()),
		Expiration: uint32(now.Add(time.Hour).Unix()),
		KeyTag:     k.KeyTag(),
		SignerName: k.Hdr.Name,
	}
}

func mustRR(t *testing.T, s string) dns.RR {
	t.Helper()
	rr, err := dns.NewRR(s)
	if err != nil {
		t.Fatalf("NewRR(%q): %v", s, err)
	}
	return rr
}

func mustB64(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("base64: %v", err)
	}
	return b
}
