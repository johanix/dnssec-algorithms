// Package qruovc provides a thin CGO adapter that lets the QR-UOV
// post-quantum signature reference implementation plug into the
// github.com/miekg/dns algorithm registration API.
//
// It mirrors the role that the sibling sqisignc/ package plays for
// SQIsign — one place to own the CGO build glue and a [crypto.Signer]
// shape — but talks to the QR-UOV team's own round2 reference C
// implementation at https://github.com/qruov/round2. liboqs does not
// ship QR-UOV (only plain UOV, since 0.13.0), so the liboqs/ adapter
// cannot be reused.
//
// # API surface used
//
// QR-UOV's reference is a standard NIST submission: it exports
// crypto_sign_keypair, crypto_sign, and crypto_sign_open with the
// classic signed-message shape (sm = sig || m). We use that NIST API
// directly and reconstruct a detached verify on top of
// crypto_sign_open by prepending the signature to the message
// ourselves, exactly as sqisignc does.
//
// # Parameter set
//
// The QR-UOV parameter set is fixed at C-compile time via -D macros;
// a given static archive hosts exactly one set. This adapter is
// pinned to QR-UOV-I (q=31, L=3, v=165, m=60) — the smallest-signature
// level-1 set (157 bytes). The byte constants below MUST match the
// CRYPTO_* values that build-qruov.sh's generated api.h reports for
// that set; if you re-pin to a different parameter set, rebuild and
// update these constants in lockstep.
//
// # RNG seeding (important)
//
// The round2 reference bundles the NIST KAT deterministic AES-CTR-DRBG
// as its randombytes source. Its global state must be seeded via
// randombytes_init before each randomized operation, or keygen/sign
// produce deterministic (and therefore insecure) output. This adapter
// seeds that DRBG with 48 fresh bytes from Go's crypto/rand before
// every Generate and Sign call, under a process-wide mutex (the DRBG
// state is a single global and is not thread-safe). This is a
// stopgap appropriate for an experimental codepoint; a production
// integration should patch the reference to call the OS CSPRNG
// directly and drop the DRBG entirely.
//
// # Lifecycle
//
// QR-UOV has no init/teardown handle: the secret key is just bytes
// (in fact a 32-byte pair of seeds) the caller hands to crypto_sign.
// This adapter holds sk + pk as plain []byte and re-enters C on every
// call.
//
// # Build setup
//
// Importing this package transitively pulls in libqruov.a + libcrypto.
// The build host needs a working qruov.pc on PKG_CONFIG_PATH. The
// build-qruov.sh helper script in this directory clones, builds, and
// installs the round2 reference for the pinned parameter set and emits
// a matching .pc file. See dnssec-algorithms/qruovc/qruov-env.sh.
package qruovc

// #cgo pkg-config: qruov
// #include <stdlib.h>
// #include <string.h>
// #include "api.h"
// #include "rng.h"
import "C"

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"io"
	"sync"
	"unsafe"
)

// Byte lengths for the pinned QR-UOV-I (q=31, L=3, v=165, m=60)
// parameter set. Values come from the api.h that build-qruov.sh
// generates for this set:
//
//	#define CRYPTO_SECRETKEYBYTES 32
//	#define CRYPTO_PUBLICKEYBYTES 23641
//	#define CRYPTO_BYTES          157
//
// The secret key is a pair of 16-byte seeds; the public key is a
// 16-byte seed plus the packed P3 matrix; the signature is a 16-byte
// salt plus the packed solution vector. If a different parameter set
// is pinned in build-qruov.sh these MUST be updated to whatever the
// regenerated api.h reports.
const (
	PublicKeySize = 23641
	SecretKeySize = 32
	SignatureSize = 157
)

// drbgSeedLen is the entropy width the NIST KAT DRBG's
// randombytes_init expects (48 bytes: 32-byte key + 16-byte V).
const drbgSeedLen = 48

// drbgMu serializes access to the reference implementation's single
// global DRBG state. randombytes / randombytes_init mutate process-
// wide state and are not reentrant.
var drbgMu sync.Mutex

// reseedDRBG draws drbgSeedLen fresh bytes from the OS CSPRNG and
// feeds them to the reference DRBG. Callers must hold drbgMu.
func reseedDRBG() error {
	var seed [drbgSeedLen]byte
	if _, err := io.ReadFull(rand.Reader, seed[:]); err != nil {
		return fmt.Errorf("qruovc reseed: %w", err)
	}
	C.randombytes_init(
		(*C.uchar)(unsafe.Pointer(&seed[0])),
		nil,
		C.int(256),
	)
	return nil
}

// Signer holds a QR-UOV-I keypair. Pub is the packed public key (as it
// appears in DNSKEY rdata); SecretKey is the 32-byte seed pair. Both
// halves are kept so the Signer alone is enough to MarshalBinary into
// a persistable blob.
type Signer struct {
	SecretKey []byte
	Pub       []byte
}

// Public returns the raw public key as a crypto.PublicKey. The
// concrete value is []byte; the qruov_q31_l3 subpackage wraps this in
// PublicKeyToWire / PublicKeyFromWire conversions.
func (s *Signer) Public() crypto.PublicKey { return s.Pub }

// Sign satisfies [crypto.Signer]. message is the input that
// miekg/dns's RRSIG/SIG signing path produces (QR-UOV hashes
// internally — Hash() == 0 — so "pre-hashed" is a misnomer, but the
// interface contract is unchanged).
//
// crypto_sign emits sm = sig || message; we slice off the first
// CRYPTO_BYTES to hand miekg/dns a detached signature.
func (s *Signer) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(s.SecretKey) != SecretKeySize {
		return nil, fmt.Errorf("qruovc sign: secret key length %d, want %d", len(s.SecretKey), SecretKeySize)
	}

	smCap := C.size_t(SignatureSize + len(message))
	smPtr := C.malloc(smCap)
	if smPtr == nil {
		return nil, fmt.Errorf("qruovc sign: malloc(%d) failed", smCap)
	}
	defer C.free(smPtr)

	var mPtr unsafe.Pointer
	if len(message) > 0 {
		mPtr = unsafe.Pointer(&message[0])
	}
	skPtr := unsafe.Pointer(&s.SecretKey[0])

	drbgMu.Lock()
	defer drbgMu.Unlock()
	if err := reseedDRBG(); err != nil {
		return nil, err
	}

	var smLen C.ulonglong
	rc := C.crypto_sign(
		(*C.uchar)(smPtr),
		&smLen,
		(*C.uchar)(mPtr),
		C.ulonglong(len(message)),
		(*C.uchar)(skPtr),
	)
	if rc != 0 {
		return nil, fmt.Errorf("qruovc sign: crypto_sign returned %d", int(rc))
	}

	wantSmLen := C.ulonglong(SignatureSize + len(message))
	if smLen != wantSmLen {
		return nil, fmt.Errorf("qruovc sign: crypto_sign emitted smlen=%d, want %d", smLen, wantSmLen)
	}
	sig := C.GoBytes(smPtr, C.int(SignatureSize))
	return sig, nil
}

// Generate creates a fresh QR-UOV-I keypair via crypto_sign_keypair.
func Generate() (*Signer, error) {
	pk := make([]byte, PublicKeySize)
	sk := make([]byte, SecretKeySize)

	drbgMu.Lock()
	defer drbgMu.Unlock()
	if err := reseedDRBG(); err != nil {
		return nil, err
	}

	rc := C.crypto_sign_keypair(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("qruovc generate: crypto_sign_keypair returned %d", int(rc))
	}
	return &Signer{SecretKey: sk, Pub: pk}, nil
}

// VerifySignature checks a detached signature against message under
// pub. Returns nil on success, [ErrSig] on cryptographic failure, or a
// wrapped error for input-shape problems.
//
// The NIST API exposes only signed-message verify (crypto_sign_open),
// so we rebuild sm = signature || message on the C side and let
// crypto_sign_open both recover m and validate. Verify does not touch
// the DRBG, so it needs no reseed and no lock.
func VerifySignature(pub, message, signature []byte) error {
	if len(pub) != PublicKeySize {
		return fmt.Errorf("qruovc verify: public key length %d, want %d", len(pub), PublicKeySize)
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("qruovc verify: signature length %d, want %d", len(signature), SignatureSize)
	}

	smLen := C.size_t(SignatureSize + len(message))
	smPtr := C.malloc(smLen)
	if smPtr == nil {
		return fmt.Errorf("qruovc verify: malloc(%d) failed", smLen)
	}
	defer C.free(smPtr)
	C.memcpy(smPtr, unsafe.Pointer(&signature[0]), C.size_t(SignatureSize))
	if len(message) > 0 {
		C.memcpy(
			unsafe.Pointer(uintptr(smPtr)+uintptr(SignatureSize)),
			unsafe.Pointer(&message[0]),
			C.size_t(len(message)),
		)
	}

	mPtr := C.malloc(smLen)
	if mPtr == nil {
		return fmt.Errorf("qruovc verify: malloc(%d) failed", smLen)
	}
	defer C.free(mPtr)
	var mLen C.ulonglong

	rc := C.crypto_sign_open(
		(*C.uchar)(mPtr),
		&mLen,
		(*C.uchar)(smPtr),
		C.ulonglong(smLen),
		(*C.uchar)(unsafe.Pointer(&pub[0])),
	)
	if rc != 0 {
		return ErrSig
	}
	return nil
}

// MarshalBinary packs a Signer's secret + public bytes into a single
// byte slice. Layout: secret_bytes || public_bytes (32 + 23641 bytes).
// Both lengths are fixed for the pinned parameter set, so
// UnmarshalBinary can split on the SecretKeySize boundary.
func (s *Signer) MarshalBinary() ([]byte, error) {
	if len(s.SecretKey) != SecretKeySize {
		return nil, fmt.Errorf("qruovc marshal: secret key length %d, want %d", len(s.SecretKey), SecretKeySize)
	}
	if len(s.Pub) != PublicKeySize {
		return nil, fmt.Errorf("qruovc marshal: public key length %d, want %d", len(s.Pub), PublicKeySize)
	}
	out := make([]byte, 0, SecretKeySize+PublicKeySize)
	out = append(out, s.SecretKey...)
	out = append(out, s.Pub...)
	return out, nil
}

// UnmarshalBinary is the inverse of MarshalBinary.
func UnmarshalBinary(buf []byte) (*Signer, error) {
	if len(buf) != SecretKeySize+PublicKeySize {
		return nil, fmt.Errorf("qruovc unmarshal: blob length %d, want %d (sk %d + pk %d)",
			len(buf), SecretKeySize+PublicKeySize, SecretKeySize, PublicKeySize)
	}
	out := &Signer{
		SecretKey: make([]byte, SecretKeySize),
		Pub:       make([]byte, PublicKeySize),
	}
	copy(out.SecretKey, buf[:SecretKeySize])
	copy(out.Pub, buf[SecretKeySize:])
	return out, nil
}
