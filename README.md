# dnssec-algorithms

Out-of-tree implementations of DNSSEC signature algorithms that are
not part of `github.com/miekg/dns`'s built-in set. Each algorithm
lives in its own subpackage and registers itself with the `dns`
package at init time via `dns.RegisterAlgorithm`.

Depends on a build of `miekg/dns` that carries the algorithm
registration API (currently on the `johanix/dns:algorithm-registry`
branch).

## Available algorithms

| Subpackage | Algorithm | Demo codepoint | Standardization | Backend | Build dep |
|---|---|---|---|---|---|
| `mldsa44/` | ML-DSA-44 (FIPS 204) | 199 (Unassigned) | final | CIRCL, pure Go | none |
| `slhdsa128s/` | SLH-DSA-SHA2-128s (FIPS 205) | 200 (Unassigned) | final | CIRCL, pure Go | none |
| `falcon512/` | Falcon-512 (FIPS 206 draft) | 201 (Unassigned) | draft | liboqs-go | liboqs |
| `mayo1/` | MAYO-1 (NIST onramp) | 202 (Unassigned) | candidate | liboqs-go | liboqs |
| `snova24_5_4/` | SNOVA-24_5_4 (NIST onramp) | 203 (Unassigned) | candidate | liboqs-go | liboqs |
| `sqisign1/` | SQIsign-I (NIST onramp) | 204 (Unassigned) | candidate | the-sqisign reference C | the-sqisign, libgmp |
| `qruov_q31_l3/` | QR-UOV-I, q=31 L=3 (NIST onramp) | 205 (Unassigned) | candidate | QR-UOV round2 reference C | qruov/round2, libcrypto |
| `mayo2/` | MAYO-2 (NIST onramp) | 206 (Unassigned) | candidate | liboqs-go | liboqs |
| `mayo3/` | MAYO-3 (NIST onramp) | 207 (Unassigned) | candidate | liboqs-go | liboqs |
| `mayo5/` | MAYO-5 (NIST onramp) | 208 (Unassigned) | candidate | liboqs-go | liboqs |
| `falcon1024/` | Falcon-1024 (FIPS 206 draft) | 209 (Unassigned) | draft | liboqs-go | liboqs |
| `snova37_17_2/` | SNOVA-37_17_2 (NIST onramp) | 210 (Unassigned) | candidate | liboqs-go | liboqs |
| `snova25_8_3/` | SNOVA-25_8_3 (NIST onramp) | 211 (Unassigned) | candidate | liboqs-go | liboqs |

The "Demo codepoint" column shows the number used by this repo's
demo program and tests only. The subpackages themselves do not
own a codepoint — the caller picks one and binds it at registration
time via `dns.RegisterAlgorithm(N, alg.New())` (or, in downstream
applications like tdns, via the equivalent per-app registry call).
Different consumers are free to use different numbers for the same
algorithm; the values listed above are simply this repo's
demo/testing convention.

`mldsa44` and `slhdsa128s` are pure Go (CIRCL) — no system deps. The
rest are CGO wrappers over three C codebases: **liboqs** (Falcon-512,
Falcon-1024, MAYO-1, MAYO-2, MAYO-3, MAYO-5, SNOVA-24_5_4,
SNOVA-37_17_2, SNOVA-25_8_3), **the-sqisign** (SQIsign-I), and
**qruov/round2** (QR-UOV-I). None of the reference C is vendored; see
[BUILDING.md](BUILDING.md) for per-codebase, per-platform setup.

## Quickstart

Pure-Go algorithms need no setup — blank-import and `go build`:

```go
import (
    "github.com/miekg/dns"
    _ "github.com/johanix/dnssec-algorithms/mldsa44"    // codepoint 199
    _ "github.com/johanix/dnssec-algorithms/slhdsa128s" // codepoint 200
)
```

For the CGO algorithms, the pattern is the same blank-import plus a
**one-time** library install and an **env script sourced per shell
session** before `go build`. Pick the codebase(s) you need:

```sh
# liboqs — Falcon-512 (201), MAYO-1 (202), SNOVA-24_5_4 (203)
port install liboqs      # or: pkgin install liboqs
. liboqs/liboqs-env.sh
#   import _ ".../falcon512" / _ ".../mayo1" / _ ".../snova24_5_4"

# the-sqisign — SQIsign-I (204)
sh sqisignc/build-sqisign.sh   # one-time build+install from source
. sqisignc/sqisign-env.sh
#   import _ ".../sqisign1"

# qruov/round2 — QR-UOV-I (205)
sh qruovc/build-qruov.sh       # one-time build+install from source
. qruovc/qruov-env.sh
#   import _ ".../qruov_q31_l3"
```

Then `go build` your program; registration is automatic on import.
Sourcing more than one env script in the same session is fine. Full
details (platforms, requirements, static-link variants, RNG/perf
caveats) are in [BUILDING.md](BUILDING.md).

The `cmd/demo` program imports all six algorithms and exercises each
end-to-end through the miekg/dns public API (it therefore needs all
three C codebases installed). `cmd/qruovtest` is a QR-UOV-only smoke
test.

## Codepoint disclaimer

These algorithms use IANA-Unassigned codepoints. Collision risk is on
the user. Pin the codepoints in your deployment configuration.

## PKCS#8 OID disclaimer

No standardized PKIX OIDs exist yet for Falcon-512, MAYO-1,
SNOVA-24_5_4, SQIsign-I, or QR-UOV-I. This repo uses placeholders
under `2.16.840.1.101.3.4.3.99.N` (`id-alg.99.N`) to avoid collision
with real allocations. Revise once IETF LAMPS publishes finalized
profiles.

## Adding a new algorithm

1. Create a new subdirectory with two Go files implementing the
   `dns.Algorithm` interface and a `dnssec-algorithms/pkcs8.Codec`.
2. Register both from `init()`.
3. For CGO-backed algorithms, route through an in-repo adapter rather
   than calling the C library from the subpackage. For liboqs
   algorithms that means `github.com/johanix/dnssec-algorithms/liboqs`
   and its `Signer`; for an upstream reference library liboqs does not
   ship (as with `sqisignc/` and `qruovc/`), add a sibling adapter +
   `build-*.sh` / `*-env.sh` pair following that pattern.
4. Add a `_test.go` file covering register, Generate → Sign → Verify
   for both RRSIG and SIG(0), a private-key file round-trip, and
   PKCS#8 round-trip.
5. Add to `cmd/demo/main.go`.

Algorithms that exist as research-grade Go libraries (CIRCL, etc.)
should be wrapped here rather than vendored into miekg/dns itself.
