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
	{199, "MLDSA44", kskOnly, base + "mldsa44", PureGo},
	{200, "MLDSA65", kskOnly, base + "mldsa65", PureGo},
	{201, "MLDSA87", kskOnly, base + "mldsa87", PureGo},
	{202, "SLHDSA128S", kskOnly, base + "slhdsa128s", PureGo}, // ~7.8 KB signature
	{203, "FALCON512", dnssec, base + "falcon512", Liboqs},
	{204, "FALCON1024", kskOnly, base + "falcon1024", Liboqs},
	{205, "MAYO1", dnssec, base + "mayo1", Liboqs},
	{206, "MAYO2", dnssec, base + "mayo2", Liboqs},
	{207, "MAYO3", dnssec, base + "mayo3", Liboqs},
	{208, "MAYO5", kskOnly, base + "mayo5", Liboqs},
	{209, "SNOVA24_5_4", dnssec, base + "snova24_5_4", Liboqs},
	{210, "SNOVA37_17_2", dnssec, base + "snova37_17_2", Liboqs},
	{211, "SNOVA25_8_3", dnssec, base + "snova25_8_3", Liboqs},
	{212, "SQISIGN1", dnssec, base + "sqisign1", SQIsign},
	{213, "QRUOV_Q31_L3", dnssec, base + "qruov_q31_l3", QRUOV},
	{214, "CROSSRSDPG128SMALL", kskOnly, base + "cross_rsdpg_128_small", Liboqs}, // ~9 KB signature
}

// Facts is external, machine-independent information about an algorithm,
// fixed by its specification — NOT a project decision. It is kept in a
// separate structure from Alg (see AlgorithmFacts) so the Algorithms table
// stays a clean one-line-per-alg list of the decisions we make (codepoint,
// role, wiring). Sizes are the raw key/signature bytes, excluding the
// surrounding DNSKEY/RRSIG record framing.
//
// Costs (signing/validation speed) are deliberately NOT here: they are
// machine-dependent (they shift across CPU architectures) and belong in
// the measured, per-arch algorithm-costs data, not in this universal table.
type Facts struct {
	PubKeyBytes   int    // DNSKEY/KEY public key size, bytes
	SigBytes      int    // RRSIG/SIG signature size, bytes (typical; some schemes are variable-length)
	SecKeyBytes   int    // stored private key size, bytes
	SecurityLevel int    // NIST PQ security level 1/3/5; 0 = classical/unspecified
	Maturity      string // final | draft | candidate | builtin
	Description   string // free-form note
}

// AlgorithmFacts holds the static facts for each algorithm, keyed by
// algorithm Name. Name — not codepoint — is the join key: a name is stable
// (ML-DSA-44 is ML-DSA-44 regardless of codepoint), whereas the codepoint
// is a project decision that will change when the IETF assigns real
// numbers. An algorithm in Algorithms may have no Facts entry yet (a
// decision made before the facts were filled in); consumers render the
// missing fields as "-".
//
// PQ sizes/levels are from the algorithm specifications; classical entries
// are included so listings can annotate the built-in algorithms too.
var AlgorithmFacts = map[string]Facts{
	// --- Classical (miekg/dns built-ins; RSA sizes shown for 2048-bit) ---
	"ED25519":         {PubKeyBytes: 32, SigBytes: 64, SecKeyBytes: 32, Maturity: "builtin", Description: "Edwards-curve DSA (RFC 8080); classical"},
	"ECDSAP256SHA256": {PubKeyBytes: 64, SigBytes: 64, SecKeyBytes: 32, Maturity: "builtin", Description: "ECDSA P-256 with SHA-256 (RFC 6605); classical, widely deployed"},
	"ECDSAP384SHA384": {PubKeyBytes: 96, SigBytes: 96, SecKeyBytes: 48, Maturity: "builtin", Description: "ECDSA P-384 with SHA-384 (RFC 6605); classical"},
	"RSASHA256":       {PubKeyBytes: 260, SigBytes: 256, SecKeyBytes: 1192, Maturity: "builtin", Description: "RSA with SHA-256 (RFC 5702); classical. Sizes for a 2048-bit key (variable)"},
	"RSASHA512":       {PubKeyBytes: 260, SigBytes: 256, SecKeyBytes: 1192, Maturity: "builtin", Description: "RSA with SHA-512 (RFC 5702); classical. Sizes for a 2048-bit key (variable)"},

	// --- Lattice ---
	"MLDSA44":    {PubKeyBytes: 1312, SigBytes: 2420, SecKeyBytes: 2560, SecurityLevel: 2, Maturity: "final", Description: "ML-DSA-44 (FIPS 204), lattice"},
	"MLDSA65":    {PubKeyBytes: 1952, SigBytes: 3309, SecKeyBytes: 4032, SecurityLevel: 3, Maturity: "final", Description: "ML-DSA-65 (FIPS 204), lattice; level-3 parameter set"},
	"MLDSA87":    {PubKeyBytes: 2592, SigBytes: 4627, SecKeyBytes: 4896, SecurityLevel: 5, Maturity: "final", Description: "ML-DSA-87 (FIPS 204), lattice; level-5 parameter set"},
	"FALCON512":  {PubKeyBytes: 897, SigBytes: 752, SecKeyBytes: 1281, SecurityLevel: 1, Maturity: "draft", Description: "Falcon-512 (FIPS 206 draft), lattice; signature is variable-length, <= 752"},
	"FALCON1024": {PubKeyBytes: 1793, SigBytes: 1462, SecKeyBytes: 2305, SecurityLevel: 5, Maturity: "draft", Description: "Falcon-1024 (FIPS 206 draft), lattice; level-5, variable-length sig <= 1462"},

	// --- Hash-based ---
	"SLHDSA128S": {PubKeyBytes: 32, SigBytes: 7856, SecKeyBytes: 64, SecurityLevel: 1, Maturity: "final", Description: "SLH-DSA-SHA2-128s (FIPS 205), hash-based; tiny keys, large slow signatures"},

	// --- Multivariate / UOV-derived ---
	"MAYO1":        {PubKeyBytes: 1420, SigBytes: 454, SecKeyBytes: 24, SecurityLevel: 1, Maturity: "candidate", Description: "MAYO-1 (NIST onramp), oil-and-vinegar; seed-sized secret key"},
	"MAYO2":        {PubKeyBytes: 4912, SigBytes: 186, SecKeyBytes: 24, SecurityLevel: 1, Maturity: "candidate", Description: "MAYO-2 (NIST onramp), oil-and-vinegar; larger pubkey / smaller sig than MAYO-1"},
	"MAYO3":        {PubKeyBytes: 2986, SigBytes: 681, SecKeyBytes: 32, SecurityLevel: 3, Maturity: "candidate", Description: "MAYO-3 (NIST onramp), oil-and-vinegar; level-3 parameter set"},
	"MAYO5":        {PubKeyBytes: 5554, SigBytes: 964, SecKeyBytes: 40, SecurityLevel: 5, Maturity: "candidate", Description: "MAYO-5 (NIST onramp), oil-and-vinegar; level-5 parameter set"},
	"SNOVA24_5_4":  {PubKeyBytes: 1016, SigBytes: 248, SecKeyBytes: 48, SecurityLevel: 1, Maturity: "candidate", Description: "SNOVA-24_5_4 (NIST onramp), oil-and-vinegar"},
	"SNOVA37_17_2": {PubKeyBytes: 9842, SigBytes: 124, SecKeyBytes: 48, SecurityLevel: 1, Maturity: "candidate", Description: "SNOVA-37_17_2 (NIST onramp), oil-and-vinegar; smallest signature (124 B), larger public key"},
	"SNOVA25_8_3":  {PubKeyBytes: 2320, SigBytes: 165, SecKeyBytes: 48, SecurityLevel: 1, Maturity: "candidate", Description: "SNOVA-25_8_3 (NIST onramp), oil-and-vinegar; small signature, modest public key"},
	"QRUOV_Q31_L3": {PubKeyBytes: 23641, SigBytes: 157, SecKeyBytes: 32, SecurityLevel: 1, Maturity: "candidate", Description: "QR-UOV-I q=31 L=3 (NIST onramp), oil-and-vinegar; large public key"},

	// --- Isogeny ---
	"SQISIGN1": {PubKeyBytes: 65, SigBytes: 148, SecKeyBytes: 353, SecurityLevel: 1, Maturity: "candidate", Description: "SQIsign-I (NIST onramp), isogeny; very small keys and signatures, slow"},

	// --- Code-based ---
	"CROSSRSDPG128SMALL": {PubKeyBytes: 54, SigBytes: 8960, SecKeyBytes: 32, SecurityLevel: 1, Maturity: "candidate", Description: "CROSS RSDP-G-128-small (NIST additional-signatures round 2), code-based; tiny public key, large signature - KSK-role candidate"},
}
