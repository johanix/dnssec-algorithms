// Command algbench measures DNSSEC sign and verify cost for every
// algorithm — classical built-ins plus the out-of-tree algorithms in
// this repo — and reports the cost RELATIVE TO ED25519 (= 1), the same
// reference the tdns algorithms.yaml enrichment uses.
//
// It drives everything through the miekg/dns RRSIG Sign/Verify path
// (the same path tdns servers use), so built-ins (ED25519, ECDSA, RSA)
// and registered algorithms are timed identically and comparably.
//
// Output is a paste-ready block of `signingcost:` / `validationcost:`
// values per algorithm, plus a table with the raw timings.
//
// Build and run:
//
//	go run ./cmd/algbench                 # default iterations
//	go run ./cmd/algbench -n 200          # more iterations (steadier)
//	go run ./cmd/algbench -rsabits 3072   # RSA key size (default 2048)
//
// The C-backed algorithms need their libraries built and on
// PKG_CONFIG_PATH (see BUILDING.md); algorithms whose Generate fails
// (library missing) are skipped with a note rather than aborting.
//
// IMPORTANT: results are hardware-specific. Run this on the reference
// hardware you actually deploy on; the numbers are only meaningful
// relative to ED25519 measured in the same run.
package main

import (
	"crypto"
	"flag"
	"fmt"
	"os"
	"sort"
	"time"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/falcon1024"
	"github.com/johanix/dnssec-algorithms/falcon512"
	"github.com/johanix/dnssec-algorithms/mayo1"
	"github.com/johanix/dnssec-algorithms/mayo2"
	"github.com/johanix/dnssec-algorithms/mayo3"
	"github.com/johanix/dnssec-algorithms/mayo5"
	"github.com/johanix/dnssec-algorithms/mldsa44"
	"github.com/johanix/dnssec-algorithms/qruov_q31_l3"
	"github.com/johanix/dnssec-algorithms/slhdsa128s"
	"github.com/johanix/dnssec-algorithms/snova24_5_4"
	"github.com/johanix/dnssec-algorithms/snova25_8_3"
	"github.com/johanix/dnssec-algorithms/snova37_17_2"
	"github.com/johanix/dnssec-algorithms/sqisign1"
)

// registered are the out-of-tree algorithms wired into miekg/dns.
// Codepoints match cmd/demo and the tdns app registration.
var registered = []struct {
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
	{205, "QRUOV_Q31_L3", qruov_q31_l3.New()},
	{206, "MAYO2", mayo2.New()},
	{207, "MAYO3", mayo3.New()},
	{208, "MAYO5", mayo5.New()},
	{209, "FALCON1024", falcon1024.New()},
	{210, "SNOVA37_17_2", snova37_17_2.New()},
	{211, "SNOVA25_8_3", snova25_8_3.New()},
}

// classical are the miekg/dns built-ins we also time. RSA entries are
// generated at -rsabits.
var classical = []struct {
	num  uint8
	name string
}{
	{dns.RSASHA256, "RSASHA256"},
	{dns.RSASHA512, "RSASHA512"},
	{dns.ECDSAP256SHA256, "ECDSAP256SHA256"},
	{dns.ECDSAP384SHA384, "ECDSAP384SHA384"},
	{dns.ED25519, "ED25519"},
}

const referenceName = "ED25519"

type result struct {
	name     string
	num      uint8
	signNs   float64 // median ns per RRSIG.Sign
	verifyNs float64 // median ns per RRSIG.Verify
	skipped  string  // non-empty -> why it was skipped
}

func main() {
	n := flag.Int("n", 100, "iterations per measured operation")
	rsabits := flag.Int("rsabits", 2048, "RSA key size in bits (for RSASHA*)")
	flag.Parse()

	for _, a := range registered {
		if err := dns.RegisterAlgorithm(a.num, a.impl); err != nil {
			fmt.Fprintf(os.Stderr, "RegisterAlgorithm(%d, %s): %v\n", a.num, a.name, err)
			os.Exit(1)
		}
	}

	var all []struct {
		num  uint8
		name string
		bits int
	}
	for _, a := range classical {
		// miekg/dns built-ins require a specific key size in Generate:
		// RSA takes -rsabits; ECDSA P-256/ED25519 take 256, P-384 takes
		// 384. (Registered PQ algorithms take 0.)
		var bits int
		switch a.num {
		case dns.RSASHA256, dns.RSASHA512:
			bits = *rsabits
		case dns.ECDSAP256SHA256, dns.ED25519:
			bits = 256
		case dns.ECDSAP384SHA384:
			bits = 384
		}
		all = append(all, struct {
			num  uint8
			name string
			bits int
		}{a.num, a.name, bits})
	}
	for _, a := range registered {
		all = append(all, struct {
			num  uint8
			name string
			bits int
		}{a.num, a.name, 0})
	}

	results := make([]result, 0, len(all))
	var refSign, refVerify float64
	for _, a := range all {
		r := benchmark(a.num, a.name, a.bits, *n)
		if r.skipped != "" {
			fmt.Fprintf(os.Stderr, "skip %s: %s\n", r.name, r.skipped)
		}
		if r.name == referenceName && r.skipped == "" {
			refSign, refVerify = r.signNs, r.verifyNs
		}
		results = append(results, r)
	}

	if refSign == 0 || refVerify == 0 {
		fmt.Fprintf(os.Stderr, "reference %s did not produce timings; cannot compute relative costs\n", referenceName)
		os.Exit(1)
	}

	printTable(results, refSign, refVerify)
	printYAML(results, refSign, refVerify)
}

// benchmark generates one key for (num, bits), then times n RRSIG
// Sign and Verify operations over a fixed TXT RRset, returning median
// ns/op. A Generate failure (e.g. missing C library) yields a skipped
// result instead of aborting.
func benchmark(num uint8, name string, bits, n int) result {
	k := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: num,
	}
	priv, err := k.Generate(bits)
	if err != nil {
		return result{name: name, num: num, skipped: fmt.Sprintf("Generate failed: %v", err)}
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		return result{name: name, num: num, skipped: "private key is not a crypto.Signer"}
	}

	txt := &dns.TXT{
		Hdr: dns.RR_Header{Name: "example.", Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 3600},
		Txt: []string{"the quick brown fox jumps over the lazy dog"},
	}
	rrset := []dns.RR{txt}
	now := uint32(time.Now().Unix())

	mkSig := func() *dns.RRSIG {
		return &dns.RRSIG{
			Hdr:        dns.RR_Header{Name: "example.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
			Algorithm:  num,
			KeyTag:     k.KeyTag(),
			SignerName: "example.",
			Inception:  now - 300,
			Expiration: now + 300,
		}
	}

	// Warm up once and confirm a full round-trip works.
	warm := mkSig()
	if err := warm.Sign(signer, rrset); err != nil {
		return result{name: name, num: num, skipped: fmt.Sprintf("Sign failed: %v", err)}
	}
	if err := warm.Verify(k, rrset); err != nil {
		return result{name: name, num: num, skipped: fmt.Sprintf("Verify failed: %v", err)}
	}

	signTimes := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		rrsig := mkSig()
		start := time.Now()
		if err := rrsig.Sign(signer, rrset); err != nil {
			return result{name: name, num: num, skipped: fmt.Sprintf("Sign failed mid-bench: %v", err)}
		}
		signTimes = append(signTimes, float64(time.Since(start).Nanoseconds()))
	}

	// Pre-sign one RRSIG to time verification repeatedly.
	vsig := mkSig()
	if err := vsig.Sign(signer, rrset); err != nil {
		return result{name: name, num: num, skipped: fmt.Sprintf("Sign (for verify) failed: %v", err)}
	}
	verifyTimes := make([]float64, 0, n)
	for i := 0; i < n; i++ {
		start := time.Now()
		if err := vsig.Verify(k, rrset); err != nil {
			return result{name: name, num: num, skipped: fmt.Sprintf("Verify failed mid-bench: %v", err)}
		}
		verifyTimes = append(verifyTimes, float64(time.Since(start).Nanoseconds()))
	}

	return result{
		name:     name,
		num:      num,
		signNs:   median(signTimes),
		verifyNs: median(verifyTimes),
	}
}

func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := append([]float64(nil), xs...)
	sort.Float64s(s)
	mid := len(s) / 2
	if len(s)%2 == 1 {
		return s[mid]
	}
	return (s[mid-1] + s[mid]) / 2
}

// relCost rounds a relative cost to a readable value: integers for >= 10,
// one decimal otherwise, and a minimum reported value of 1 for anything
// at or below the reference.
func relCost(ns, ref float64) float64 {
	r := ns / ref
	switch {
	case r >= 10:
		return float64(int(r + 0.5))
	default:
		return float64(int(r*10+0.5)) / 10
	}
}

func printTable(results []result, refSign, refVerify float64) {
	fmt.Printf("# DNSSEC sign/verify benchmark (RRSIG over a 1-RR TXT set)\n")
	fmt.Printf("# Reference: %s (signingcost = validationcost = 1)\n", referenceName)
	fmt.Printf("# Median ns/op; relative columns are ns/op divided by the %s median.\n\n", referenceName)
	fmt.Printf("%-16s %12s %12s %10s %10s\n", "ALGORITHM", "SIGN ns", "VERIFY ns", "SIGN x", "VERIFY x")
	for _, r := range results {
		if r.skipped != "" {
			fmt.Printf("%-16s %12s %12s %10s %10s   (skipped: %s)\n", r.name, "-", "-", "-", "-", r.skipped)
			continue
		}
		fmt.Printf("%-16s %12.0f %12.0f %10.1f %10.1f\n",
			r.name, r.signNs, r.verifyNs, r.signNs/refSign, r.verifyNs/refVerify)
	}
	fmt.Println()
}

func printYAML(results []result, refSign, refVerify float64) {
	fmt.Printf("# Paste-ready: signingcost / validationcost relative to %s.\n", referenceName)
	fmt.Printf("# Drop these two lines into each profile in algorithms.yaml.\n\n")
	for _, r := range results {
		if r.skipped != "" {
			fmt.Printf("      %s:\n         # skipped: %s\n", r.name, r.skipped)
			continue
		}
		fmt.Printf("      %s:\n         signingcost:     %g\n         validationcost:  %g\n",
			r.name, relCost(r.signNs, refSign), relCost(r.verifyNs, refVerify))
	}
}
