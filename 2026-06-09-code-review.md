# Code review — Go algorithm wrappers

_Reviewed 2026-06-09, against the tree at commit `1644011` ("Add QR-UOV-I
support"), i.e. the state just before the `mayo2/` subpackage was added.
The findings below describe the wrappers as a whole; they apply equally
to the new `mayo2/` wrapper, which deliberately mirrors `mayo1/`._

## What this repo is

`dnssec-algorithms` is an out-of-tree home for DNSSEC signature
algorithms that `miekg/dns` doesn't ship built-in — five post-quantum
schemes plus the plumbing. Each algorithm registers itself with a
`johanix/dns` fork (the `algorithm-registry` branch, pinned via
`replace` in `go.mod`) at `init()` time. The pure-Go packages build and
pass tests with no system dependencies (`pkcs8`, `mldsa44`,
`slhdsa128s`).

## The pattern (consistent and good)

Every algorithm subpackage is two files:

- **`<alg>.go`** — an `Impl` struct satisfying `dns.Algorithm`
  (`Generate`/`Sign`/`Verify`/wire encode/private-key file I/O).
- **`pkcs8.go`** — a `Codec` registered into the dependency-free `pkcs8`
  registry, which `Marshal`/`Parse` iterate in registration order.

The codepoint is deliberately *not* owned by the subpackage — the caller
binds it at `dns.RegisterAlgorithm(N, alg.New())`. That's the right call
for IANA-Unassigned numbers.

CGO is well-isolated into three adapter packages, each owning one C
codebase's build glue and a `crypto.Signer` shape:

- **`liboqs`** (`liboqs/liboqs.go`) → Falcon-512, MAYO-1, MAYO-2, SNOVA —
  via `liboqs-go`.
- **`sqisignc`** (`sqisignc/sqisignc.go`) → SQIsign-I, hand-rolled CGO to
  `the-sqisign`.
- **`qruovc`** (`qruovc/qruovc.go`) → QR-UOV-I, hand-rolled CGO to
  `qruov/round2`.

## Things done particularly well

- **Subtle lifecycle hazards are documented and handled.** liboqs's
  `Clean()` cleanses the secret-key slice in place, so `Sign`/`Generate`
  pass a defensive copy (`liboqs/liboqs.go:63-76`). The QR-UOV NIST-KAT
  DRBG is reseeded from `crypto/rand` under a process-wide mutex before
  each randomized op, with a frank comment that it's a stopgap
  (`qruovc/qruovc.go:30-57,99-117`).
- Both hand-rolled wrappers reconstruct a **detached verify** from the
  NIST signed-message `crypto_sign_open` by prepending the signature —
  correctly, with length assertions.
- Tests exercise the full miekg/dns dispatch path (register → Generate →
  RRSIG + SIG(0) sign/verify → key round-trip), and `local-install/`
  build artifacts are properly `.gitignore`d.

## Observations worth flagging

### 1. The single most fragile coupling: SQIsign symbol namespacing

`sqisignc.go` calls `C.crypto_sign`, but the archive only exports
`sqisign_lvl1_ref_crypto_sign`. The remap in `sqisign_namespace.h`
(`#define crypto_sign SQISIGN_NAMESPACE(crypto_sign)`) only fires when
`SQISIGN_VARIANT` / `SQISIGN_BUILD_TYPE_REF` are defined — supplied today
by the `.pc` Cflags (`-DSQISIGN_VARIANT=lvl1 -DSQISIGN_BUILD_TYPE_REF`).

If those flags ever drop out, `SQISIGN_NAMESPACE(s)` collapses to plain
`s`, and since `cmd/demo` links QR-UOV's *un*-namespaced `crypto_sign` in
the same binary, SQIsign's `C.crypto_sign` would **silently bind to
QR-UOV's signer** instead of failing to link. A two-line guard in the
cgo preamble would turn that into a loud build error:

```c
#if !defined(SQISIGN_VARIANT)
#error "sqisignc: SQISIGN_VARIANT must be set via sqisign.pc Cflags"
#endif
```

(SQIsign namespaces its NIST API symbols; QR-UOV does not. They do not
collide today — verified with `nm` on both archives — precisely because
the namespace flags are set.)

### 2. No build-time check that Go size constants match the C library

`sqisignc` / `qruovc` hardcode `PublicKeySize` / `SecretKeySize` /
`SignatureSize` that must track the C `CRYPTO_*BYTES` macros across
rebuilds. There are good runtime length checks, but drift could be
caught at compile time with a cgo static assertion, e.g.:

```go
var _ = [1]int{}[C.CRYPTO_BYTES-SignatureSize]
```

### 3. `err == liboqs.ErrSig` should be `errors.Is`

In all liboqs wrappers (`falcon512.go:118`, `mayo1.go:114`,
`mayo2.go`, `snova24_5_4.go:118`). Works today only because
`VerifySignature` returns the sentinel unwrapped — fragile if that ever
gets wrapped. If fixed, fix all of them together so they don't drift.

### 4. `PublicKeyToWire` returns the caller's slice without copying

e.g. `falcon512.go:77-83` (and the same shape in the other liboqs
wrappers) while `PublicKeyFromWire` defensively copies — slightly
inconsistent aliasing.

### 5. Secret keys are never zeroized in the hand-rolled wrappers

Secret keys held as plain `[]byte` in `sqisignc` / `qruovc` `Signer`s
live in GC memory and are never wiped (the liboqs path does, via
`Clean()`). Acceptable for experimental codepoints, but worth a note.

## Bottom line

Nothing here is a correctness bug in the current configuration — items
3–5 are hardening nits, and item 1 is a latent footgun rather than an
active one. The architecture (per-algorithm `Impl` + `Codec`, CGO glue
isolated behind adapter packages, codepoint chosen by the caller) is
clean and easy to extend, as the `mayo2/` addition demonstrates.
