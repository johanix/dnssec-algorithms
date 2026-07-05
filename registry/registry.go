// Package registry is the single source of truth for the DNSSEC
// signature algorithms this module provides: their codepoint, canonical
// name, usage capabilities (including KSK/ZSK role), implementing
// package, and which build-tag group (if any) their implementation
// belongs to.
//
// It is PURE DATA. It imports none of the adapter subpackages, so a
// consumer can link the whole table with zero cgo cost — e.g. to map a
// codepoint to a name for display even in a build that cannot verify
// with that algorithm. Code generation and tdns's compile-time
// registration turn these rows into RegisterMetadata (all algs, always)
// and Register (per-app, build-tag-gated) calls; the Package/Group
// columns are consumed by the generator, not at runtime.
//
// Codepoints here are project-internal, in the IANA-unassigned range,
// and experimental — they will change when/if the IETF assigns real
// codepoints.
package registry

// Group is the build-tag group an algorithm's implementation belongs
// to. PureGo implementations have no build tag; the others require the
// named C library (and its cgo build tag) to be linked.
type Group string

const (
	PureGo  Group = "purego"
	Liboqs  Group = "liboqs"
	SQIsign Group = "sqisign"
	QRUOV   Group = "qruov"
)

// Caps mirrors tdns's algorithms.Capabilities. ForKSK/ForZSK refine
// ForDNSSEC by role: an algorithm whose signature is small enough for
// every RRSIG is ForZSK; one whose signature is only tolerable in the
// occasional DNSKEY response (a large PQ signature) is ForKSK but not
// ForZSK. A CLI types algorithm names case-insensitively (input is
// upper-cased before matching), so Name doubles as the typed name — no
// separate cli_name is needed.
type Caps struct {
	ForSIG0   bool
	ForDNSSEC bool
	ForKSK    bool
	ForZSK    bool
}

// Alg is one row of the registry.
type Alg struct {
	Codepoint uint8
	Name      string // canonical BIND/registry name, e.g. "MLDSA44"
	Caps      Caps
	Package   string // implementing import path (generator turns into an import)
	Group     Group
}

// dnssec is the shorthand for a small-signature algorithm usable in any
// DNSSEC role (both KSK and ZSK) plus SIG(0).
var dnssec = Caps{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: true}

// kskOnly is for large-signature algorithms: fine as a KSK (signs only
// the occasional DNSKEY RRset) but not as a ZSK (would bloat every
// RRSIG). See docs/pqc-algorithm-families.md.
var kskOnly = Caps{ForSIG0: true, ForDNSSEC: true, ForKSK: true, ForZSK: false}

const base = "github.com/johanix/dnssec-algorithms/"

// Algorithms is the authoritative table. Add a row here (with a unique
// codepoint and name) to introduce an algorithm; the generator and every
// app's metadata pick it up.
var Algorithms = []Alg{
	{199, "MLDSA44", dnssec, base + "mldsa44", PureGo},
	{200, "SLHDSA128S", kskOnly, base + "slhdsa128s", PureGo}, // ~7.8 KB signature
	{201, "FALCON512", dnssec, base + "falcon512", Liboqs},
	{202, "MAYO1", dnssec, base + "mayo1", Liboqs},
	{203, "SNOVA24_5_4", dnssec, base + "snova24_5_4", Liboqs},
	{204, "SQISIGN1", dnssec, base + "sqisign1", SQIsign},
	{205, "QRUOV_Q31_L3", dnssec, base + "qruov_q31_l3", QRUOV},
	{206, "MAYO2", dnssec, base + "mayo2", Liboqs},
	{207, "MAYO3", dnssec, base + "mayo3", Liboqs},
	{208, "MAYO5", dnssec, base + "mayo5", Liboqs},
	{209, "FALCON1024", dnssec, base + "falcon1024", Liboqs},
	{210, "SNOVA37_17_2", dnssec, base + "snova37_17_2", Liboqs},
	{211, "SNOVA25_8_3", dnssec, base + "snova25_8_3", Liboqs},
	{212, "MLDSA65", dnssec, base + "mldsa65", PureGo},
	{213, "MLDSA87", dnssec, base + "mldsa87", PureGo},
	{214, "CROSSRSDPG128SMALL", kskOnly, base + "cross_rsdpg_128_small", Liboqs}, // ~9 KB signature
}
