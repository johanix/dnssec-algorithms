package mayo3

import (
	"crypto"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/liboqs"
)

// Number is the codepoint the tests use. Out-of-tree consumers pick
// their own; we just need a consistent value across the test file.
const Number uint8 = 207

// Register the algorithm at test-binary init time.
func init() {
	if err := dns.RegisterAlgorithm(Number, New()); err != nil {
		panic("mayo3 test init: RegisterAlgorithm: " + err.Error())
	}
}

func TestRegistered(t *testing.T) {
	if name := dns.AlgorithmToString[Number]; name != "MAYO3" {
		t.Errorf("AlgorithmToString[%d] = %q, want MAYO3", Number, name)
	}
	if h := dns.AlgorithmToHash[Number]; h != 0 {
		t.Errorf("AlgorithmToHash[%d] = %v, want 0 (identity)", Number, h)
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	keyrr := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeKEY, Class: dns.ClassINET},
		Algorithm: Number,
	}}
	priv, err := keyrr.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	sk, ok := priv.(*liboqs.Signer)
	if !ok {
		t.Fatalf("Generate returned %T, want *liboqs.Signer", priv)
	}

	s := keyrr.PrivateKeyString(sk)
	if !strings.Contains(s, "Algorithm: 207 (MAYO3)") {
		t.Errorf("PrivateKeyString missing algorithm line:\n%s", s)
	}

	parsed, err := keyrr.NewPrivateKey(s)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	sk2, ok := parsed.(*liboqs.Signer)
	if !ok {
		t.Fatalf("NewPrivateKey returned %T, want *liboqs.Signer", parsed)
	}
	if sk2.AlgName != AlgName {
		t.Errorf("round-tripped signer is for %q, want %q", sk2.AlgName, AlgName)
	}
	if string(sk.SecretKey) != string(sk2.SecretKey) {
		t.Error("round-tripped secret key differs")
	}
	if string(sk.Pub) != string(sk2.Pub) {
		t.Error("round-tripped public key differs")
	}
}

func TestRRSIG(t *testing.T) {
	keyrr := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: Number,
	}
	priv, err := keyrr.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("Generate did not return a crypto.Signer")
	}

	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"hello"},
	}
	now := uint32(time.Now().Unix())
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  Number,
		KeyTag:     keyrr.KeyTag(),
		SignerName: "example.",
		Inception:  now - 300,
		Expiration: now + 300,
	}
	if err := rrsig.Sign(signer, []dns.RR{txt}); err != nil {
		t.Fatalf("RRSIG.Sign: %v", err)
	}
	if err := rrsig.Verify(keyrr, []dns.RR{txt}); err != nil {
		t.Fatalf("RRSIG.Verify: %v", err)
	}
}

func TestSIG0(t *testing.T) {
	keyrr := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: Number,
	}}
	priv, err := keyrr.Generate(0)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	signer := priv.(crypto.Signer)

	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeSOA)
	now := uint32(time.Now().Unix())
	sig := &dns.SIG{RRSIG: dns.RRSIG{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY, Ttl: 0},
		Algorithm:  Number,
		KeyTag:     keyrr.KeyTag(),
		SignerName: keyrr.Hdr.Name,
		Inception:  now - 300,
		Expiration: now + 300,
	}}
	buf, err := sig.Sign(signer, m)
	if err != nil {
		t.Fatalf("SIG.Sign: %v", err)
	}
	if err := sig.Verify(keyrr, buf); err != nil {
		t.Fatalf("SIG.Verify: %v", err)
	}
}

func TestPKCS8RoundTrip(t *testing.T) {
	s1, err := liboqs.Generate(AlgName)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	c := pkcs8Codec{}
	der, err := c.MarshalPKCS8(s1)
	if err != nil {
		t.Fatalf("MarshalPKCS8: %v", err)
	}
	parsed, err := c.ParsePKCS8(der)
	if err != nil {
		t.Fatalf("ParsePKCS8: %v", err)
	}
	s2 := parsed.(*liboqs.Signer)
	if string(s1.SecretKey) != string(s2.SecretKey) {
		t.Error("PKCS#8 round-trip secret-key mismatch")
	}
	_ = base64.StdEncoding.EncodeToString(der)
}
