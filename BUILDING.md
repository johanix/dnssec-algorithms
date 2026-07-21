# Building the CGO-backed algorithms

The pure-Go algorithms (`mldsa44`, `mldsa65`, `mldsa87`, `slhdsa128s`)
need nothing — they compile with a plain `go build`. The remaining
algorithms link C libraries via CGO and need a one-time per-host
setup, plus an env script sourced into the shell session you build
from.

There are three C codebases, each with its own build/env scripts:

| Codebase | Algorithms | Packaged? | Setup |
|---|---|---|---|
| liboqs | Falcon-512/1024, MAYO-1/2/3/5, SNOVA-24_5_4/37_17_2/25_8_3, CROSS RSDP-G-128-small | yes (MacPorts/pkgsrc) | install + `liboqs/liboqs-env.sh` |
| the-sqisign | SQIsign-I | no | `sqisignc/build-sqisign.sh` + `sqisignc/sqisign-env.sh` |
| qruov/round2 | QR-UOV-I | no | `qruovc/build-qruov.sh` + `qruovc/qruov-env.sh` |

None of the reference C is vendored into this repo. liboqs is a system
install; the SQIsign and QR-UOV scripts clone the upstream source at
build time and install a compiled static library outside the repo. The
repo carries only the Go adapters and these scripts.

Each env script is idempotent and safe to source multiple times. You
can source more than one in the same session to build several
algorithms at once.

---

## liboqs (Falcon, MAYO, SNOVA, CROSS)

These use CGO via `liboqs-go`, which needs `pkg-config` to locate a
`liboqs-go.pc` pointing at the liboqs install.

**The easy path** — one command per shell session, works on macOS,
NetBSD, and Linux:

```
. liboqs/liboqs-env.sh
```

The script detects the OS, probes the platform's well-known install
prefixes for liboqs (override with `LIBOQS_PREFIX=/your/path`), writes
a fresh `liboqs-go.pc` into `liboqs/pkgconfig/` from the discovered
paths, and exports `PKG_CONFIG_PATH`. On NetBSD it additionally sets
`CGO_LDFLAGS` to satisfy static liboqs's libcrypto dependency — see
the NetBSD section below. (`CGO_LDFLAGS` rather than the `.pc` Libs
line: Go's cgo pkg-config integration filters `-lcrypto` out of `.pc`
Libs lines.)

If you prefer to `eval` rather than source:

```
eval "$(liboqs/liboqs-env.sh)"
```

### macOS development host (MacPorts)

Install liboqs from MacPorts (`port install liboqs`) — provides
`/opt/local/lib/liboqs.dylib`. The env script detects it (Homebrew
prefixes are probed too), writes the `.pc`, exports
`PKG_CONFIG_PATH`; no `CGO_LDFLAGS` needed.

Binaries built this way depend on `liboqs.dylib` + `libcrypto.3.dylib`
at runtime. Fine for local testing; not for distribution.

### NetBSD with pkgsrc liboqs

Install liboqs from pkgsrc (`pkgin install liboqs`) — provides
`/usr/pkg/lib/liboqs.a`. The env script detects it, writes the `.pc`,
exports `PKG_CONFIG_PATH`, and sets
`CGO_LDFLAGS=/usr/pkg/lib/libcrypto.a` so liboqs's libcrypto
dependency is satisfied by pkgsrc's **static** archive.

pkgsrc ships **only** the static archive (no `.so`), so liboqs — and,
via `CGO_LDFLAGS`, libcrypto — end up statically linked into the
resulting Go binaries. The binaries have **no** runtime libcrypto
dependency at all; nothing needs to be installed on deploy hosts.

Why not `-lcrypto`? That resolves to pkgsrc's `libcrypto.so.3`, but a
cgo link embeds no rpath (pkgsrc's compiler wrapper normally injects
`-Wl,-R/usr/pkg/lib`; go/cgo does not) and the base system's
libcrypto is a different soname (`.so.15`), so the resulting binary
only starts with `LD_LIBRARY_PATH=/usr/pkg/lib` set. The script falls
back to `-lcrypto` only when `/usr/pkg/lib/libcrypto.a` is missing —
if you end up there, expect to need `LD_LIBRARY_PATH` at runtime.

### Linux

The env script probes `/usr`, `/usr/local`, and `/opt/liboqs` (distro
liboqs packages are typically shared libraries, so the resulting
binaries link liboqs dynamically). Not regularly exercised — expect
rough edges.

### No-OpenSSL alternative (NetBSD / Linux)

`liboqs/build-liboqs-static.sh` builds a custom static liboqs with
`OQS_USE_OPENSSL=OFF` (liboqs's internal SHA/AES), removing the
libcrypto dependency at **build** time as well. Since the standard
NetBSD flow above already links libcrypto statically, the runtime
footprint is the same; this script is for hosts without pkgsrc liboqs
or where you don't want OpenSSL involved at all.

**Caveat:** the script currently builds a minimal liboqs with only
three algorithms (Falcon-512, MAYO-1, SNOVA-24_5_4) and its
`OQS_MINIMAL_BUILD` flag names are known-broken (lowercase; see the
open questions in `docs/pqc-algorithm-families.md`). Extend and fix
the list before using it. For the standard NetBSD case, the pkgsrc +
env-script flow above is simpler and sufficient.

---

## the-sqisign (SQIsign-I)

The SQIsign reference C library is not packaged in MacPorts, pkgsrc, or
any Linux distro, so it must be built from source once per build host.
The helper script `sqisignc/build-sqisign.sh` clones the upstream repo
(https://github.com/SQISign/the-sqisign), builds SQIsign-I (lvl1) with
CMake, and installs headers + static archives + a matching
`sqisign.pc` under a chosen prefix:

```
sh sqisignc/build-sqisign.sh                  # installs to /usr/local/sqisign-lvl1
sh sqisignc/build-sqisign.sh /opt/sqisign     # custom prefix
```

Build-host requirements: `cmake >= 3.13`, a C11 compiler, and GMP
development headers + library (`port install gmp` on MacPorts, `pkgin
install gmp` on pkgsrc, `apt install libgmp-dev` on Debian/Ubuntu).

After the build is installed, source the matching env script in the
same shell session you build from:

```
. sqisignc/sqisign-env.sh
```

The script auto-detects the install prefix (defaulting to
`/usr/local/sqisign-lvl1`), exports `PKG_CONFIG_PATH`, and then `go
build` of the `sqisign1` subpackage Just Works. Override with
`SQISIGN_PREFIX=/your/path` if needed.

The resulting Go binaries link the static `libsqisign_lvl1*.a`
archives directly. The build script also locates `libgmp.a` and bakes
its absolute path into `sqisign.pc` (a bare `-lgmp` would make the
linker prefer `libgmp.so`, which lives outside the runtime linker's
default search path on NetBSD pkgsrc / MacPorts), so the binaries
have **no** runtime gmp dependency either. The gmp install on the
build host must therefore ship the static archive — pkgsrc, MacPorts,
and Debian's `libgmp-dev` all do.

**SQIsign-I sizes**: public key 65 bytes, secret key 353 bytes,
**signature 148 bytes** — smaller than every other DNSSEC signature
algorithm currently in use. Round 2 reference signing on Apple Silicon
is ~50 ms per signature in our tests, fast enough for online dynamic
signing; verification is comparable. Server-side performance on other
platforms (x86, ARM cores without crypto extensions) should be
benchmarked before committing to online-signing workflows.

---

## qruov/round2 (QR-UOV-I)

Like SQIsign, QR-UOV is not packaged anywhere and is not in liboqs, so
its reference C library must be built from source once per build host.
The helper script `qruovc/build-qruov.sh` clones the upstream round2
repo (https://github.com/qruov/round2), compiles a single pinned
parameter set, and installs headers + a static `libqruov.a` + a
matching `qruov.pc` under a chosen prefix:

```
sh qruovc/build-qruov.sh                  # installs to /usr/local/qruov-i
sh qruovc/build-qruov.sh ./local-install  # repo-local prefix (gitignored)
```

The pinned parameter set is **QR-UOV-I (q=31, L=3, v=165, m=60)**,
chosen for the smallest signature at NIST security level 1. A given
`libqruov.a` hosts exactly one parameter set (the field arithmetic and
key sizes are compile-time constants); re-pin by editing `QRUOV_PARAMS`
in `build-qruov.sh` and updating the byte constants in `qruovc.go`.

Build-host requirements: a C11 compiler and OpenSSL development headers
+ library (`port install openssl` on MacPorts, `pkgin install openssl`
on pkgsrc, `apt install libssl-dev` on Debian/Ubuntu). The reference's
MGF/PRG and its NIST KAT DRBG depend on libcrypto. The build script
locates `libcrypto.a` (pkg-config's libdir first, then well-known
prefixes) and bakes its absolute path into `qruov.pc`, so the
resulting Go binaries have **no** runtime libcrypto dependency; it
falls back to dynamic `-lcrypto` only when no static archive exists
(in which case NetBSD/macOS binaries may need `LD_LIBRARY_PATH` at
runtime — install an OpenSSL that ships the `.a` instead).

After the build is installed, source the matching env script in the
same shell session you build from:

```
. qruovc/qruov-env.sh
```

The script auto-detects the install prefix (defaulting to
`/usr/local/qruov-i`, and probing `qruovc/local-install/` first),
exports `PKG_CONFIG_PATH`, and then `go build` of the `qruov_q31_l3`
subpackage Just Works. Override with `QRUOV_PREFIX=/your/path` if
needed.

**QR-UOV-I sizes**: public key ~23.6 KB, secret key 32 bytes (a pair of
seeds), **signature 157 bytes**. The trade-off is the opposite of
SQIsign's: a tiny signature paired with a large public key. The 23 KB
DNSKEY exceeds the common EDNS(0) UDP ceiling, so the DNSKEY RRset is
fetched over TCP/DoT/DoQ — a one-time per-key cost; the small signature
keeps ordinary RRSIG-bearing responses compact.

> **RNG note.** The round2 reference ships the NIST KAT deterministic
> DRBG as its `randombytes` source. The `qruovc` adapter reseeds that
> DRBG from the OS CSPRNG before every keygen and signature; this is a
> stopgap appropriate for an experimental codepoint. A production
> integration should patch the reference to call the OS CSPRNG
> directly. The reference also notes its rejection sampling and linear
> solver are not yet constant-time. Experimental use only.
