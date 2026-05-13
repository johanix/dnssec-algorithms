package slhdsa128s

import (
	"crypto"
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/sign/slhdsa"
	"github.com/miekg/dns"
)

func TestRegistered(t *testing.T) {
	if name := dns.AlgorithmToString[Number]; name != "SLHDSA128S" {
		t.Errorf("AlgorithmToString[%d] = %q, want SLHDSA128S", Number, name)
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
	sk, ok := priv.(*slhdsa.PrivateKey)
	if !ok {
		t.Fatalf("Generate returned %T, want *slhdsa.PrivateKey", priv)
	}

	s := keyrr.PrivateKeyString(sk)
	if !strings.Contains(s, "Algorithm: 200 (SLHDSA128S)") {
		t.Errorf("PrivateKeyString missing algorithm line:\n%s", s)
	}
	if !strings.Contains(s, "PrivateKey:") {
		t.Errorf("PrivateKeyString missing PrivateKey line:\n%s", s)
	}

	parsed, err := keyrr.NewPrivateKey(s)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	sk2, ok := parsed.(*slhdsa.PrivateKey)
	if !ok {
		t.Fatalf("NewPrivateKey returned %T, want *slhdsa.PrivateKey", parsed)
	}
	// CIRCL's PrivateKey.Equal does a value-type assertion
	// (x.(PrivateKey)) and rejects pointer-typed arguments, so deref
	// before comparing.
	if !sk.Equal(*sk2) {
		t.Error("round-tripped private key does not equal original")
	}
}

func TestPublicKeyLength(t *testing.T) {
	keyrr := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeKEY, Class: dns.ClassINET},
		Algorithm: Number,
	}}
	if _, err := keyrr.Generate(0); err != nil {
		t.Fatalf("Generate: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(keyrr.PublicKey)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	// SLH-DSA-SHA2-128s public key is 2*n = 32 bytes (pkSeed || pkRoot).
	if len(raw) != 32 {
		t.Fatalf("generated public key is %d bytes, want 32", len(raw))
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
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("Generate did not return a crypto.Signer")
	}

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
