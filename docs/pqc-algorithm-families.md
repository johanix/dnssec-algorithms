# PQC Signature Families for DNSSEC — Selection Notes

**Status:** working notes, 2026-07-05. Records which post-quantum signature
families we have considered for DNSSEC (specifically the algorithm-split
KSK/ZSK model behind `draft-johani-dnsop-dnssec-alg-split`), which are
implemented here, which are excluded and why, and what to investigate next.

## The DNSSEC sizing constraints (what "relevant" means)

A PQC signature is judged for DNSSEC against constraints that differ from
generic PKI:

1. **RRSIG signature size is the dominant cost.** An RRSIG accompanies
   *every* signed response. A large signature bloats ordinary answers and
   pushes them past the EDNS(0) UDP budget into TCP/fragmentation. This is
   the binding constraint for a **ZSK** (which signs all zone data).

2. **The DNSKEY RRset response must fit under 64 KB** — the whole set: all
   DNSKEYs + the RRSIG(s) over the DNSKEY RRset + message overhead. During a
   **KSK algorithm rollover** the DNSKEY RRset carries **two** KSK signatures
   (old + new), so the rollover response is the worst case to budget for.

3. **Public-key size is a secondary cost**, borne only in the (occasional,
   TCP/DoT-tolerant) DNSKEY response — *not* on every answer.

**The algorithm-split insight:** a KSK and a ZSK need not share an algorithm.
This lets a KSK spend its budget on the axis that is cheap for a KSK:
- A **ZSK** must have a **small signature** (it is on every response); its
  public key is only in DNSKEY, so a larger key is tolerable.
- A **KSK** signs only the DNSKEY RRset. Its signature appears only in the
  DNSKEY response, so a **large signature is acceptable** — provided two of
  them still fit under 64 KB during rollover. Its public key is likewise only
  in DNSKEY.

So the two roles have *opposite* tolerances, and different families win each.

## Families considered

| Family | Basis | Examples (liboqs) | Sig size | PK size | Verdict |
|---|---|---|---|---|---|
| **Lattice** | Module-LWE/NTRU | ML-DSA-44/65/87, Falcon-512/1024 | 0.6–4.6 KB | 0.9–2.6 KB | **In.** ZSK-viable; the workhorses. |
| **Hash-based** | Hash preimage | SLH-DSA-128s, SPHINCS+ | ~7.9 KB | 32 B | **In (reference).** Big sig — KSK-only / conservative baseline. |
| **Multivariate / UOV-derived** | Oil-and-Vinegar | MAYO-1/2/3/5, SNOVA-\*, QR-UOV-I | 0.15–0.6 KB | 1–24 KB | **In.** Small-sig KSK candidates (big-key/tiny-sig). |
| **Isogeny** | Supersingular isogeny | SQIsign-I | **148 B** | 65 B | **In.** Smallest of all, both axes — but watched (SIDH-class breaks). |
| **Code-based** | Syndrome decoding | **CROSS (RSDP / RSDP-G)** | 9–75 KB | 54–153 B | **Adding (KSK).** New family; see below. |
| **Plain UOV** | Oil-and-Vinegar | UOV-Is/Ip/III/V | ~96–128 B | **44–66 KB** | **Excluded.** Key too large — see below. |
| **KEMs** | (encryption) | ML-KEM, McEliece, Frodo, BIKE, NTRU | — | — | **N/A.** DNSSEC is signatures only. |
| **Stateful hash** | Hash + state | XMSS, LMS (OQS STFL) | — | — | **Excluded.** State management is a poor fit for DNSSEC ops. |

Sizes above are NIST level-1 unless noted; taken from liboqs 0.15.0 headers.

## Implemented in this repo

- **Lattice:** `mldsa44/65/87` (pure Go), `falcon512/1024` (liboqs).
- **Hash-based:** `slhdsa128s` (pure Go).
- **Multivariate:** `mayo1/2/3/5`, `snova24_5_4/25_8_3/37_17_2` (liboqs), `qruov_q31_l3` (own C lib).
- **Isogeny:** `sqisign1` (own C lib).
- **Code-based:** `cross_rsdpg_128_small` (liboqs) — **new, 2026-07-05.**

(DNSSEC algorithm-number assignments are a late-stage implementation choice
tracked with the adapters, not here — this doc is family/parameter analysis.)

## Why CROSS RSDP-G-128-small was added (KSK candidate)

- **New hardness family.** Everything else here is lattice, multivariate
  (all UOV-correlated), isogeny, or hash. CROSS is **code-based** (Restricted
  Syndrome Decoding Problem; the RSDP-G "Gallager" variant here). Adding a
  distinct assumption is the whole point of algorithm-split diversification —
  a break in one family should not compromise every available algorithm.
- **KSK-shaped sizes.** 54-byte public key, **8,960-byte signature** (the
  `small` optimization corner minimizes the signature; RSDP-G beats plain
  RSDP: 8,960 vs 12,432 B and 54 vs 77 B key). The large signature rules it
  out as a ZSK, but for a KSK it lives only in the DNSKEY response.
- **Survives the rollover budget.** Two CROSS RSDP-G KSKs mid-rollover:
  2 × 8,960 B sig + 2 × 54 B key ≈ 18 KB, plus a small ZSK (e.g. Falcon/MAYO)
  DNSKEY + its RRSIG + overhead ≈ 2–3 KB → **≈ 20–21 KB total**, comfortably
  under 64 KB.
- **Standardization traction.** NIST additional-signatures round-2 candidate.
- **Pedagogically clean.** It is the exact mirror of QR-UOV-I (23 KB key /
  157 B sig): CROSS is 54 B key / 9 KB sig. Two opposite-shaped KSKs from two
  different families make a good lab contrast.

## Why plain UOV was excluded (despite the tiny signature)

UOV has an even smaller signature than CROSS (~96–128 B), but its **public
key is 44–66 KB** at level 1. The disqualifier is the DNSKEY-RRset ceiling,
not the per-response cost:

- A single UOV-Is KSK (~44 KB key) nearly fills the 64 KB response alone.
- During a **KSK rollover**, two UOV keys ≈ 88 KB — **over the 64 KB limit
  before adding any ZSK material.** It cannot roll over within one DNSKEY
  response.

This is the clean contrast that justifies CROSS: for a KSK, spending the
budget on the *signature* (CROSS, ~9 KB, ×2 = fine) works, but spending it on
the *key* (UOV, ~44 KB, ×2 = over) does not. QR-UOV-I (~23.6 KB key) is the
largest key we accept, and it is already right at the tolerable edge.

## To investigate next (NOT in liboqs — need their own reference-C integration)

These are the genuinely additive small-signature / diverse-family schemes
that liboqs does not ship. Each would follow the `sqisignc` / `qruovc`
pattern (clone upstream reference C, build a static lib + `.pc`, add a Go
adapter).

- **HAWK** — lattice (module-LIP), Falcon-class signature sizes with simpler,
  faster signing and no floating-point. NIST additional-round. The most
  DNSSEC-relevant small-sig scheme missing from liboqs. **Top of the list.**
- **Other UOV derivatives** — **VOX, PROV, TUOV, SNOVA variants beyond
  liboqs**. Same small-sig/large-key shape as MAYO/QR-UOV; worth surveying
  for a better key/sig/security point for the KSK role.
- **SQIsign level-3/5** and **SQIsign2D / newer isogeny variants** — we have
  SQIsign-I (level 1) only; higher levels and the 2D constructions may change
  the size/speed trade.
- **MQOM, MIRA, RYDE, FAEST, and other MPC-in-the-head signatures** — mostly
  large signatures (CROSS-like or bigger); low priority for DNSSEC, but track
  in case a parameter set lands in KSK-tolerable range.
- **Threshold / aggregate PQ signatures** — not a near-term DNSSEC fit, but
  relevant to multi-signer / DNSKEY-RRset-size reduction ideas long-term.

### Open questions

- For a lean liboqs build (vs. the full build), the correct minimal flags for
  0.15.0 are `OQS_MINIMAL_BUILD="OQS_ENABLE_SIG_FALCON_512;OQS_ENABLE_SIG_MAYO_1;OQS_ENABLE_SIG_SNOVA_SNOVA_24_5_4"`
  (**uppercase** names). If CROSS is kept, add its enable flag too. The
  current `liboqs/build-liboqs-static.sh` uses lowercase names that silently
  exclude these algs from the archive — build fails to link. **Fix pending.**
- Should the KSK-only algorithms (CROSS, SLH-DSA) carry a flag or naming
  convention marking them as "KSK-role only, not for ZSK use", to prevent an
  operator from selecting a 9 KB-signature algorithm as a zone-signing key?
