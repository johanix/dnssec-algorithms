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

The "Demo codepoint" column shows the number used by this repo's
demo program and tests only. The subpackages themselves do not
own a codepoint — the caller picks one and binds it at registration
time via `dns.RegisterAlgorithm(N, alg.New())` (or, in downstream
applications like tdns, via the equivalent per-app registry call).
Different consumers are free to use different numbers for the same
algorithm; the values listed above are simply this repo's
demo/testing convention.

The first two algorithms use `github.com/cloudflare/circl` directly
— pure Go, no system dependencies. The next three use the Open
Quantum Safe `liboqs-go` Go bindings on top of the C `liboqs`
library and require the build host to have liboqs available (see
"Build setup" below). The last one (`sqisign1/`) uses the SQIsign
team's own reference C implementation via a thin in-repo CGO
adapter under `sqisignc/`; liboqs does not ship SQIsign. See
"SQIsign build setup" below.

**SQIsign-I sizes** (operationally the most interesting feature):
public key 65 bytes, secret key 353 bytes, **signature 148 bytes** —
smaller than every other DNSSEC signature algorithm currently in
use. Round 2 reference signing on Apple Silicon is ~50 ms per
signature in our tests, fast enough for online dynamic signing.
Verification is comparable. Round 1's "seconds per signature"
reputation no longer applies. Server-side performance on other
platforms (x86, ARM cores without crypto extensions) should be
benchmarked before committing to online-signing workflows.

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
the liboqs install.

**The easy path** — one command per shell session, works on macOS
and NetBSD:

```
. liboqs/liboqs-env.sh
```

The script detects the OS, copies the matching template from
`liboqs/pkgconfig/`, exports `PKG_CONFIG_PATH`, and on NetBSD also
sets `CGO_LDFLAGS=-lcrypto` (a workaround for Go 1.25's cgo
pkg-config integration filtering `-lcrypto` out of `.pc` Libs lines).
After sourcing, `make` in `cmdv2/` Just Works.

If you prefer to `eval` rather than source:

```
eval "$(liboqs/liboqs-env.sh)"
```

### macOS development host (MacPorts)

Install liboqs from MacPorts (`port install liboqs`) — provides
`/opt/local/lib/liboqs.dylib`. The env script picks up
`liboqs-go.pc.macos-dev`, exports `PKG_CONFIG_PATH`, no `CGO_LDFLAGS`
needed.

Binaries built this way depend on `liboqs.dylib` + `libcrypto.3.dylib`
at runtime. Fine for local testing; not for distribution.

### NetBSD with pkgsrc liboqs

Install liboqs from pkgsrc (`pkgin install liboqs`) — provides
`/usr/pkg/lib/liboqs.a`. The env script picks up
`liboqs-go.pc.netbsd-pkgsrc`, exports `PKG_CONFIG_PATH`, and sets
`CGO_LDFLAGS=-lcrypto`.

pkgsrc ships **only** the static archive (no `.so`), so liboqs ends
up statically linked into the resulting Go binaries. The binaries
depend on `libcrypto.so` from the NetBSD base system (always
present); no `pkg_add liboqs` needed on deploy hosts.

### Linux

Template not yet shipped (coming).

## SQIsign build setup

The SQIsign reference C library is not packaged in MacPorts, pkgsrc,
or any Linux distro, so it must be built from source once per build
host. The helper script `sqisignc/build-sqisign.sh` clones the
upstream repo (https://github.com/SQISign/the-sqisign), builds
SQIsign-I (lvl1) with CMake, and installs headers + static archives
+ a matching `sqisign.pc` under a chosen prefix:

```
sh sqisignc/build-sqisign.sh                  # installs to /usr/local/sqisign-lvl1
sh sqisignc/build-sqisign.sh /opt/sqisign     # custom prefix
```

Build-host requirements: `cmake >= 3.13`, a C11 compiler, and GMP
development headers + library (`port install gmp` on MacPorts,
`pkgin install gmp` on pkgsrc, `apt install libgmp-dev` on
Debian/Ubuntu).

After the build is installed, source the matching env script in the
same shell session you build the dnssec-algorithms consumer from:

```
. sqisignc/sqisign-env.sh
```

The script auto-detects the install prefix (defaulting to
`/usr/local/sqisign-lvl1`), exports `PKG_CONFIG_PATH`, and then
`go build` of the `sqisign1` subpackage Just Works. Override with
`SQISIGN_PREFIX=/your/path` if needed.

The resulting Go binaries link the static `libsqisign_lvl1*.a`
archives directly, and depend dynamically on `libgmp` from the
build host's package set (always present on NetBSD if pkgsrc gmp is
installed; common on Linux).

### NetBSD / Linux: full-static, no-OpenSSL alternative

If you need the binaries to be **completely** self-contained
(no libcrypto dep either), run `liboqs/build-liboqs-static.sh` once
per build host. It builds a custom liboqs with `OQS_USE_OPENSSL=OFF`
(uses liboqs's internal SHA/AES) and only the three algorithms we
use, installed under a chosen prefix. Useful when the deploy targets
don't have a libcrypto compatible with the build host's libcrypto.

For the standard NetBSD case (deploying to a NetBSD host with the
same major OS version), the pkgsrc + env-script flow above is
simpler and sufficient.

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
