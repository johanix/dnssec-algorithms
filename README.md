# dnssec-algorithms

Out-of-tree implementations of DNSSEC signature algorithms that are
not part of `github.com/miekg/dns`'s built-in set. Each algorithm
lives in its own subpackage and registers itself with the `dns`
package at init time via `dns.RegisterAlgorithm`.

Depends on a build of `miekg/dns` that carries the algorithm
registration API (currently on the `johanix/dns:algorithm-registry`
branch).

## Available algorithms

| Subpackage | Algorithm | Codepoint | Standardization | Backend | Build dep |
|---|---|---|---|---|---|
| `mldsa44/` | ML-DSA-44 (FIPS 204) | 199 (Unassigned) | final | CIRCL, pure Go | none |
| `slhdsa128s/` | SLH-DSA-SHA2-128s (FIPS 205) | 200 (Unassigned) | final | CIRCL, pure Go | none |
| `falcon512/` | Falcon-512 (FIPS 206 draft) | 201 (Unassigned) | draft | liboqs-go | liboqs |
| `mayo1/` | MAYO-1 (NIST onramp) | 202 (Unassigned) | candidate | liboqs-go | liboqs |
| `snova24_5_4/` | SNOVA-24_5_4 (NIST onramp) | 203 (Unassigned) | candidate | liboqs-go | liboqs |

The first two use `github.com/cloudflare/circl` directly — pure Go,
no system dependencies. The latter three use the Open Quantum Safe
`liboqs-go` Go bindings on top of the C `liboqs` library and require
the build host to have liboqs available (see "Build setup" below).

## Usage

Add a blank import for each algorithm you want; everything else is
automatic:

```go
import (
    "github.com/miekg/dns"
    _ "github.com/johanix/dnssec-algorithms/mldsa44"
    _ "github.com/johanix/dnssec-algorithms/slhdsa128s"
    _ "github.com/johanix/dnssec-algorithms/falcon512"
)

func main() {
    k := &dns.DNSKEY{
        Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
        Flags:     257,
        Protocol:  3,
        Algorithm: 201, // Falcon-512
    }
    priv, _ := k.Generate(0)
    _ = priv
}
```

The `cmd/demo` program imports all five algorithms and exercises each
end-to-end through the miekg/dns public API:

```
PKG_CONFIG_PATH=$(pwd)/liboqs/pkgconfig:$PKG_CONFIG_PATH go run ./cmd/demo
```

## Build setup (the CGO algorithms)

`falcon512`, `mayo1`, and `snova24_5_4` use CGO via `liboqs-go`. CGO
requires `pkg-config` to locate a `liboqs-go.pc` file that points at
the liboqs install. The repo's `liboqs/pkgconfig/` directory ships
templates for the two common cases.

### macOS development host (MacPorts)

For a dev workstation that compiles and tests against the
dynamically-linked liboqs from `port install liboqs`:

```
cp liboqs/pkgconfig/liboqs-go.pc.macos-dev liboqs/pkgconfig/liboqs-go.pc
# Edit if MacPorts is not at /opt/local (e.g. Homebrew on Apple
# Silicon uses /opt/homebrew).

export PKG_CONFIG_PATH=$(pwd)/liboqs/pkgconfig:$PKG_CONFIG_PATH
```

Binaries built this way depend on `liboqs.dylib` + `libcrypto.3.dylib`
at runtime. Fine for local testing; not for distribution.

### NetBSD / Linux production build

Builds the binaries that ship. Static-link liboqs into the Go binary
so deployed hosts need only libc — no liboqs install required at the
deploy target.

One-time per build host:

```
sh liboqs/build-liboqs-static.sh
# Default prefix /usr/local/liboqs-static; pass a different one if
# you want it elsewhere.
```

The script:
- Clones liboqs v0.15.0
- Configures with `OQS_USE_OPENSSL=OFF` (use liboqs's internal
  SHA/AES) and `OQS_MINIMAL_BUILD=falcon_512;mayo_1;snova_SNOVA_24_5_4`
  (compile only the three algorithms we use)
- Produces a static `liboqs.a` (no shared library)
- Installs to the prefix
- Drops a matching `liboqs-go.pc` that emits explicit static-link
  flags

Then for the build session:

```
export PKG_CONFIG_PATH=/usr/local/liboqs-static/lib/pkgconfig:$PKG_CONFIG_PATH
cd ../tdns/cmdv2 && make
```

Resulting binaries:
- Contain liboqs (the trimmed-down version) statically linked
- Depend only on libc / libpthread at runtime
- Are ~5 MB larger than pure-Go-algorithm-only binaries

## Codepoint disclaimer

These algorithms use IANA-Unassigned codepoints. Collision risk is on
the user. Pin the codepoints in your deployment configuration.

## PKCS#8 OID disclaimer

No standardized PKIX OIDs exist yet for Falcon-512, MAYO-1, or
SNOVA-24_5_4. This repo uses placeholders under
`2.16.840.1.101.3.4.3.99.N` (`id-alg.99.N`) to avoid collision with
real allocations. Revise once IETF LAMPS publishes finalized
profiles.

## Adding a new algorithm

1. Create a new subdirectory with two Go files implementing the
   `dns.Algorithm` interface and a `dnssec-algorithms/pkcs8.Codec`.
2. Register both from `init()`.
3. For CGO-backed algorithms, import
   `github.com/johanix/dnssec-algorithms/liboqs` and use its `Signer`
   adapter rather than touching liboqs-go directly.
4. Add a `_test.go` file covering register, Generate → Sign → Verify
   for both RRSIG and SIG(0), a private-key file round-trip, and
   PKCS#8 round-trip.
5. Add to `cmd/demo/main.go`.

Algorithms that exist as research-grade Go libraries (CIRCL, etc.)
should be wrapped here rather than vendored into miekg/dns itself.
