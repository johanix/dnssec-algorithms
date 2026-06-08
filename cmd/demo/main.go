// Demo program for the dnssec-algorithms registration plumbing.
//
// Imports each out-of-tree algorithm package for its side effects,
// then exercises every registered algorithm through the miekg/dns
// public API: Generate, RRSIG sign+verify, and SIG(0) sign+verify.
// Prints PASS / FAIL per step per algorithm.
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

	"github.com/johanix/dnssec-algorithms/falcon512"
	"github.com/johanix/dnssec-algorithms/mayo1"
	"github.com/johanix/dnssec-algorithms/mldsa44"
	"github.com/johanix/dnssec-algorithms/qruov1"
	"github.com/johanix/dnssec-algorithms/slhdsa128s"
	"github.com/johanix/dnssec-algorithms/snova24_5_4"
	"github.com/johanix/dnssec-algorithms/sqisign1"
)

// algorithms enumerates every algorithm subpackage demoed here. The
// codepoints are chosen by this demo, not by the subpackages — adapt
// to a different number scheme by editing this table.
var algorithms = []struct {
	num  uint8
	name string
	impl dns.Algorithm
}{
	{199, "MLDSA44", mldsa44.New()},
	{200, "SLHDSA128S", slhdsa128s.New()},
	{201, "FALCON512", falcon512.New()},
	{202, "MAYO1", mayo1.New()},
	{203, "SNOVA24_5_4", snova24_5_4.New()},
	{204, "SQISIGN1", sqisign1.New()},
	{205, "QRUOV1", qruov1.New()},
}

func init() {
	for _, alg := range algorithms {
		if err := dns.RegisterAlgorithm(alg.num, alg.impl); err != nil {
			panic(fmt.Sprintf("dns.RegisterAlgorithm(%d, %s): %v",
				alg.num, alg.name, err))
		}
	}
}

func main() {
	failed := 0
	for _, alg := range algorithms {
		fmt.Printf("=== %s (algorithm %d) ===\n", alg.name, alg.num)
		checks := []struct {
			name string
			fn   func(uint8, string) error
		}{
			{"registered-maps view", checkRegistered},
			{"generate + private-key file roundtrip", checkGenerateAndKeyRoundTrip},
			{"RRSIG sign + verify", checkRRSIG},
			{"SIG(0) sign + verify", checkSIG0},
		}
		for _, c := range checks {
			if err := c.fn(alg.num, alg.name); err != nil {
				fmt.Printf("FAIL  %s: %v\n", c.name, err)
				failed++
			} else {
				fmt.Printf("PASS  %s\n", c.name)
			}
		}
		fmt.Println()
	}

	if failed != 0 {
		fmt.Printf("%d check(s) failed\n", failed)
		os.Exit(1)
	}
	fmt.Println("All checks passed.")
}

func checkRegistered(algNum uint8, algName string) error {
	if name := dns.AlgorithmToString[algNum]; name != algName {
		return fmt.Errorf("AlgorithmToString[%d] = %q, want %s", algNum, name, algName)
	}
	if h := dns.AlgorithmToHash[algNum]; h != 0 {
		return fmt.Errorf("AlgorithmToHash[%d] = %v, want 0 (identity hash)", algNum, h)
	}
	return nil
}

func checkGenerateAndKeyRoundTrip(algNum uint8, _ string) error {
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

func checkRRSIG(algNum uint8, _ string) error {
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

func checkSIG0(algNum uint8, _ string) error {
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
