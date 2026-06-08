# Building the CGO-backed algorithms

The pure-Go algorithms (`mldsa44`, `slhdsa128s`) need nothing — they
compile with a plain `go build`. The remaining algorithms link C
libraries via CGO and need a one-time per-host setup, plus an env
script sourced into the shell session you build from.

There are three C codebases, each with its own build/env scripts:

| Codebase | Algorithms | Packaged? | Setup |
|---|---|---|---|
| liboqs | Falcon-512, MAYO-1, SNOVA-24_5_4 | yes (MacPorts/pkgsrc) | install + `liboqs/liboqs-env.sh` |
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

## liboqs (Falcon-512, MAYO-1, SNOVA-24_5_4)

These use CGO via `liboqs-go`, which needs `pkg-config` to locate a
`liboqs-go.pc` pointing at the liboqs install.

**The easy path** — one command per shell session, works on macOS and
NetBSD:

```
. liboqs/liboqs-env.sh
```

The script detects the OS, copies the matching template from
`liboqs/pkgconfig/`, exports `PKG_CONFIG_PATH`, and on NetBSD also sets
`CGO_LDFLAGS=-lcrypto` (a workaround for Go 1.25's cgo pkg-config
integration filtering `-lcrypto` out of `.pc` Libs lines).

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

pkgsrc ships **only** the static archive (no `.so`), so liboqs ends up
statically linked into the resulting Go binaries. The binaries depend
on `libcrypto.so` from the NetBSD base system (always present); no
`pkg_add liboqs` needed on deploy hosts.

### Linux

Template not yet shipped (coming).

### Full-static, no-OpenSSL alternative (NetBSD / Linux)

If you need the binaries to be **completely** self-contained (no
libcrypto dep either), run `liboqs/build-liboqs-static.sh` once per
build host. It builds a custom liboqs with `OQS_USE_OPENSSL=OFF` (uses
liboqs's internal SHA/AES) and only the three algorithms we use,
installed under a chosen prefix. Useful when the deploy targets don't
have a libcrypto compatible with the build host's libcrypto.

For the standard NetBSD case (deploying to a NetBSD host with the same
major OS version), the pkgsrc + env-script flow above is simpler and
sufficient.

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

The resulting Go binaries link the static `libsqisign_lvl1*.a` archives
directly, and depend dynamically on `libgmp` from the build host's
package set (always present on NetBSD if pkgsrc gmp is installed;
common on Linux).

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
MGF/PRG and its NIST KAT DRBG depend on libcrypto.

After the build is installed, source the matching env script in the
same shell session you build from:

```
. qruovc/qruov-env.sh
```

The script auto-detects the install prefix (defaulting to
`/usr/local/qruov-i`, and probing `qruovc/local-install/` first),
exports `PKG_CONFIG_PATH`, and then `go build` of the `qruov1`
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
