# dnssec-algorithms

Out-of-tree implementations of DNSSEC signature algorithms that are not
part of `github.com/miekg/dns`'s built-in set. Each algorithm lives in
its own subpackage and registers itself with the `dns` package at init
time via `dns.RegisterAlgorithm`.

Depends on a build of `miekg/dns` that carries the algorithm
registration API (currently on the `johanix/dns:algorithm-registry`
branch).

## Available algorithms

| Subpackage | Algorithm | Codepoint | Status | Backend |
|---|---|---|---|---|
| `mldsa44/` | ML-DSA-44 (FIPS 204) | 199 (Unassigned) | experimental | CIRCL, pure Go |
| `slhdsa128s/` | SLH-DSA-SHA2-128s (FIPS 205) | 200 (Unassigned) | experimental | CIRCL, pure Go |

## Usage

Add a blank import for the algorithm you want; everything else is
automatic:

```go
import (
    "github.com/miekg/dns"
    _ "github.com/johanix/dnssec-algorithms/mldsa44"
)

func main() {
    k := &dns.DNSKEY{
        Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
        Flags:     257,
        Protocol:  3,
        Algorithm: 199, // ML-DSA-44
    }
    priv, _ := k.Generate(0)
    _ = priv
}
```

## Codepoint disclaimer

These algorithms use IANA-Unassigned codepoints. Collision risk is on
the user. Pin the codepoints in your deployment configuration.

## Adding a new algorithm

1. Create a new subdirectory with a single Go file implementing the
   `dns.Algorithm` interface.
2. Register from `init()`.
3. Add a `_test.go` file covering `Generate -> Sign -> Verify` for
   both RRSIG and SIG(0), plus a private-key-file roundtrip.

Algorithms that exist as research-grade Go libraries (CIRCL, etc.)
should be wrapped here rather than vendored into miekg/dns itself.
