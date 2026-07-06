// Command algbench measures DNSSEC sign and verify cost for every
// algorithm — classical built-ins plus the out-of-tree algorithms in
// this repo — and reports the cost RELATIVE TO ED25519 (= 1).
//
// The set of algorithms and their codepoints come from the registry
// package (the single source of truth); algbench only supplies each one's
// implementation to benchmark. A registry algorithm with no wired
// implementation is a hard error, so the benchmark can never silently
// drift from the registry.
//
// It drives everything through the miekg/dns RRSIG Sign/Verify path
// (the same path tdns servers use), so built-ins (ED25519, ECDSA, RSA)
// and registered algorithms are timed identically and comparably.
//
// Output is a table of raw timings, plus the per-architecture cost YAML
// (algorithm-costs.yaml). Costs are machine-dependent, so the YAML is
// keyed by CPU architecture:
//
//	go run ./cmd/algbench                       # print costs for this arch
//	go run ./cmd/algbench -write algorithm-costs.yaml
//	                                            # merge into the file, under
//	                                            # this host's arch block,
//	                                            # preserving other arches
//	go run ./cmd/algbench -arch amd64 -write algorithm-costs.yaml
//	                                            # label the block explicitly
//	go run ./cmd/algbench -n 200                # more iterations (steadier)
//	go run ./cmd/algbench -rsabits 3072         # RSA key size (default 2048)
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
	"runtime"
	"sort"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/yaml.v3"

	"github.com/johanix/dnssec-algorithms/cross_rsdpg_128_small"
	"github.com/johanix/dnssec-algorithms/falcon1024"
	"github.com/johanix/dnssec-algorithms/falcon512"
	"github.com/johanix/dnssec-algorithms/mayo1"
	"github.com/johanix/dnssec-algorithms/mayo2"
	"github.com/johanix/dnssec-algorithms/mayo3"
	"github.com/johanix/dnssec-algorithms/mayo5"
	"github.com/johanix/dnssec-algorithms/mldsa44"
	"github.com/johanix/dnssec-algorithms/mldsa65"
	"github.com/johanix/dnssec-algorithms/mldsa87"
	"github.com/johanix/dnssec-algorithms/qruov_q31_l3"
	"github.com/johanix/dnssec-algorithms/registry"
	"github.com/johanix/dnssec-algorithms/slhdsa128s"
	"github.com/johanix/dnssec-algorithms/snova24_5_4"
	"github.com/johanix/dnssec-algorithms/snova25_8_3"
	"github.com/johanix/dnssec-algorithms/snova37_17_2"
	"github.com/johanix/dnssec-algorithms/sqisign1"
)

// impls maps a registry algorithm Name to its constructor. The set of
// algorithms and their codepoints come from the registry (the single
// source of truth); this map only supplies the concrete implementation to
// benchmark. Every registry algorithm must have an entry here — a missing
// one is a hard error at startup, so this can never silently drift from
// the registry the way the old hardcoded list did.
var impls = map[string]func() dns.Algorithm{
	"MLDSA44":            func() dns.Algorithm { return mldsa44.New() },
	"MLDSA65":            func() dns.Algorithm { return mldsa65.New() },
	"MLDSA87":            func() dns.Algorithm { return mldsa87.New() },
	"SLHDSA128S":         func() dns.Algorithm { return slhdsa128s.New() },
	"FALCON512":          func() dns.Algorithm { return falcon512.New() },
	"FALCON1024":         func() dns.Algorithm { return falcon1024.New() },
	"MAYO1":              func() dns.Algorithm { return mayo1.New() },
	"MAYO2":              func() dns.Algorithm { return mayo2.New() },
	"MAYO3":              func() dns.Algorithm { return mayo3.New() },
	"MAYO5":              func() dns.Algorithm { return mayo5.New() },
	"SNOVA24_5_4":        func() dns.Algorithm { return snova24_5_4.New() },
	"SNOVA37_17_2":       func() dns.Algorithm { return snova37_17_2.New() },
	"SNOVA25_8_3":        func() dns.Algorithm { return snova25_8_3.New() },
	"SQISIGN1":           func() dns.Algorithm { return sqisign1.New() },
	"QRUOV_Q31_L3":       func() dns.Algorithm { return qruov_q31_l3.New() },
	"CROSSRSDPG128SMALL": func() dns.Algorithm { return cross_rsdpg_128_small.New() },
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
	arch := flag.String("arch", runtime.GOARCH, "architecture label for the cost block (defaults to this host's GOARCH)")
	write := flag.String("write", "", "merge the measured costs into this algorithm-costs.yaml file, under the -arch block")
	flag.Parse()

	// The registry is the single source of truth for which PQ algorithms
	// exist and their codepoints. Register each one's implementation from
	// the impls map; a registry algorithm with no impl entry is a hard
	// error (the map has drifted from the registry and must be fixed).
	for _, a := range registry.Algorithms {
		newImpl, ok := impls[a.Name]
		if !ok {
			fmt.Fprintf(os.Stderr, "no implementation wired for registry algorithm %s (%d); add it to impls in cmd/algbench\n", a.Name, a.Codepoint)
			os.Exit(1)
		}
		if err := dns.RegisterAlgorithm(a.Codepoint, newImpl()); err != nil {
			fmt.Fprintf(os.Stderr, "RegisterAlgorithm(%d, %s): %v\n", a.Codepoint, a.Name, err)
			os.Exit(1)
		}
	}

	type algRow struct {
		num  uint8
		name string
		bits int
	}
	var all []algRow
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
		all = append(all, algRow{a.num, a.name, bits})
	}
	for _, a := range registry.Algorithms {
		all = append(all, algRow{a.Codepoint, a.Name, 0})
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
	if *write != "" {
		if err := writeCostsFile(*write, *arch, results, refSign, refVerify); err != nil {
			fmt.Fprintf(os.Stderr, "writing %s: %v\n", *write, err)
			os.Exit(1)
		}
		fmt.Printf("# merged %s costs into %s\n", *arch, *write)
	} else {
		printCostsYAML(*arch, results, refSign, refVerify)
	}
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

// cost is one algorithm's relative signing/validation cost.
type cost struct {
	Signing    float64 `yaml:"signing"`
	Validation float64 `yaml:"validation"`
}

// costsFile is the on-disk multi-arch cost table:
//
//	costs:
//	   arm64:
//	      MLDSA44: { signing: 3.1, validation: 1.9 }
//	   amd64:
//	      MLDSA44: { signing: 2.8, validation: 1.7 }
type costsFile struct {
	Costs map[string]map[string]cost `yaml:"costs"`
}

// measuredCosts builds the per-algorithm cost map for one benchmark run,
// skipping algorithms that could not be measured.
func measuredCosts(results []result, refSign, refVerify float64) map[string]cost {
	out := map[string]cost{}
	for _, r := range results {
		if r.skipped != "" {
			continue
		}
		out[r.name] = cost{
			Signing:    relCost(r.signNs, refSign),
			Validation: relCost(r.verifyNs, refVerify),
		}
	}
	return out
}

// printCostsYAML prints the multi-arch cost YAML for this run to stdout,
// with just the one arch block. Useful for inspection; -write merges into
// a file instead.
func printCostsYAML(arch string, results []result, refSign, refVerify float64) {
	cf := costsFile{Costs: map[string]map[string]cost{arch: measuredCosts(results, refSign, refVerify)}}
	out, err := yaml.Marshal(cf)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshaling costs: %v\n", err)
		return
	}
	fmt.Printf("# Signing/validation cost relative to %s (= 1), measured on this host.\n", referenceName)
	fmt.Printf("# -write <file> merges this under costs.%s, preserving other architectures.\n\n%s", arch, out)
}

// writeCostsFile merges this run's costs into path under the arch block,
// preserving cost blocks for other architectures already in the file. The
// file is created if absent.
func writeCostsFile(path, arch string, results []result, refSign, refVerify float64) error {
	var cf costsFile
	if data, err := os.ReadFile(path); err == nil {
		if err := yaml.Unmarshal(data, &cf); err != nil {
			return fmt.Errorf("parsing existing %s: %w", path, err)
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if cf.Costs == nil {
		cf.Costs = map[string]map[string]cost{}
	}
	cf.Costs[arch] = measuredCosts(results, refSign, refVerify)

	out, err := yaml.Marshal(cf)
	if err != nil {
		return err
	}
	header := fmt.Sprintf("# Signing/validation cost per algorithm, relative to %s (= 1), by CPU\n"+
		"# architecture. Produced by cmd/algbench; the shape is stable, the exact\n"+
		"# factors are hardware-specific. Regenerate an arch block with:\n"+
		"#   go run ./cmd/algbench -write %s\n\n", referenceName, path)
	return os.WriteFile(path, append([]byte(header), out...), 0o644)
}
