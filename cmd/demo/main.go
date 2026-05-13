// Demo program for the dnssec-algorithms registration plumbing.
//
// Imports an out-of-tree algorithm package (mldsa44) for its side
// effects, then exercises the registered algorithm through the
// miekg/dns library's public API: Generate, RRSIG sign+verify, and
// SIG(0) sign+verify. Prints PASS / FAIL for each step.
//
// Build and run:
//
//	go run ./cmd/demo
//
// Useful as an end-to-end smoke test when wiring a new algorithm into
// the registry — confirms the per-algorithm switches in miekg/dns all
// reach the registered implementation.
package main

import (
	"crypto"
	"fmt"
	"os"
	"time"

	"github.com/miekg/dns"

	_ "github.com/johanix/dnssec-algorithms/mldsa44"
)

const algNum uint8 = 199

func main() {
	checks := []struct {
		name string
		fn   func() error
	}{
		{"registered-maps view", checkRegistered},
		{"generate + private-key file roundtrip", checkGenerateAndKeyRoundTrip},
		{"RRSIG sign + verify", checkRRSIG},
		{"SIG(0) sign + verify", checkSIG0},
	}

	failed := 0
	for _, c := range checks {
		if err := c.fn(); err != nil {
			fmt.Printf("FAIL  %s: %v\n", c.name, err)
			failed++
		} else {
			fmt.Printf("PASS  %s\n", c.name)
		}
	}

	if failed != 0 {
		fmt.Printf("\n%d check(s) failed\n", failed)
		os.Exit(1)
	}
	fmt.Println("\nAll checks passed.")
}

func checkRegistered() error {
	name := dns.AlgorithmToString[algNum]
	if name != "MLDSA44" {
		return fmt.Errorf("AlgorithmToString[%d] = %q, want MLDSA44", algNum, name)
	}
	h := dns.AlgorithmToHash[algNum]
	if h != 0 {
		return fmt.Errorf("AlgorithmToHash[%d] = %v, want 0 (identity hash)", algNum, h)
	}
	return nil
}

func checkGenerateAndKeyRoundTrip() error {
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: algNum,
	}
	priv, err := k.Generate(0)
	if err != nil {
		return fmt.Errorf("Generate: %w", err)
	}
	if k.PublicKey == "" {
		return fmt.Errorf("Generate left DNSKEY.PublicKey empty")
	}
	pkstr := k.PrivateKeyString(priv)
	if pkstr == "" {
		return fmt.Errorf("PrivateKeyString returned empty")
	}
	k2 := &dns.DNSKEY{Algorithm: algNum, PublicKey: k.PublicKey}
	if _, err := k2.NewPrivateKey(pkstr); err != nil {
		return fmt.Errorf("NewPrivateKey roundtrip: %w", err)
	}
	return nil
}

func checkRRSIG() error {
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: algNum,
	}
	priv, err := k.Generate(0)
	if err != nil {
		return fmt.Errorf("Generate: %w", err)
	}
	signer := priv.(crypto.Signer)

	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"hello"},
	}

	now := uint32(time.Now().Unix())
	rrsig := &dns.RRSIG{
		Hdr:        dns.RR_Header{Name: "example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		Algorithm:  algNum,
		KeyTag:     k.KeyTag(),
		SignerName: "example.",
		Inception:  now - 300,
		Expiration: now + 300,
	}
	if err := rrsig.Sign(signer, []dns.RR{txt}); err != nil {
		return fmt.Errorf("RRSIG.Sign: %w", err)
	}
	if err := rrsig.Verify(k, []dns.RR{txt}); err != nil {
		return fmt.Errorf("RRSIG.Verify: %w", err)
	}
	return nil
}

func checkSIG0() error {
	k := &dns.KEY{DNSKEY: dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: algNum,
	}}
	priv, err := k.Generate(0)
	if err != nil {
		return fmt.Errorf("Generate: %w", err)
	}
	signer := priv.(crypto.Signer)

	m := new(dns.Msg)
	m.SetQuestion("example.", dns.TypeSOA)

	now := uint32(time.Now().Unix())
	sig := &dns.SIG{RRSIG: dns.RRSIG{
		Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY, Ttl: 0},
		Algorithm:  algNum,
		KeyTag:     k.KeyTag(),
		SignerName: k.Hdr.Name,
		Inception:  now - 300,
		Expiration: now + 300,
	}}
	buf, err := sig.Sign(signer, m)
	if err != nil {
		return fmt.Errorf("SIG.Sign: %w", err)
	}
	if err := sig.Verify(k, buf); err != nil {
		return fmt.Errorf("SIG.Verify: %w", err)
	}
	return nil
}

