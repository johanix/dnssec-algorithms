// Package sqisignc provides a thin CGO adapter that lets the
// SQIsign post-quantum signature reference implementation plug into
// the github.com/miekg/dns algorithm registration API.
//
// It mirrors the role that the sibling liboqs/ package plays for
// Falcon / MAYO / SNOVA — one place to own the CGO build glue and a
// [crypto.Signer] shape — but talks to the SQIsign team's own
// reference C library at https://github.com/SQISign/the-sqisign
// rather than to liboqs (which does not ship SQIsign).
//
// # API surface used
//
// SQIsign exports two parallel API layers:
//
//   - "NIST API" symbols (crypto_sign_keypair, crypto_sign,
//     crypto_sign_open), shaped like the legacy NIST PQClean submission
//     interface. These are not namespaced across parameter sets, so a
//     given link unit can host exactly one variant. Detached verify is
//     not available at this layer (the verify form is signed-message:
//     sm = sig || m).
//   - "Core" symbols (sqisign_keypair, sqisign_sign, sqisign_open,
//     sqisign_verify) which the reference header [sig.h] declares.
//     These get namespace-mangled per variant + build type at compile
//     time (e.g. sqisign_lvl1_ref_keypair), driven by the
//     SQISIGN_VARIANT and SQISIGN_BUILD_TYPE_* macros.
//
// We use the NIST API for keypair + sign (simpler symbol surface, no
// per-variant linker juggling needed) and reconstruct a detached
// verify on top of crypto_sign_open by prepending the signature to
// the message ourselves.
//
// Only the level-1 parameter set (SQIsign-I) is wired up. lvl3 / lvl5
// can be added later by linking the corresponding *_nistapi static
// archive into a separate Go subpackage and bumping the byte
// constants.
//
// # Lifecycle
//
// SQIsign has no init/teardown handle the way liboqs does — the
// secret key is just bytes the caller hands to crypto_sign. So this
// adapter holds sk + pk as plain []byte and re-enters C on every
// call. No defer-Clean dance, no defensive copies for cleanse-on-free.
//
// # Build setup
//
// Importing this package transitively pulls in libsqisign_lvl1.a +
// libsqisign_lvl1_nistapi.a (and their sibling .a files) and libgmp.
// The build host needs a working sqisign.pc on PKG_CONFIG_PATH. The
// build-sqisign.sh helper script in this directory clones, builds,
// and installs the-sqisign and emits a matching .pc file. See the
// repo's README.md and dnssec-algorithms/sqisignc/sqisign-env.sh.
package sqisignc

// #cgo pkg-config: sqisign
// #include <stdlib.h>
// #include <string.h>
// #include "api.h"
import "C"

import (
	"crypto"
	"fmt"
	"io"
	"unsafe"
)

// Byte lengths for the SQIsign-I (lvl1) parameter set. Values come
// from the upstream src/nistapi/lvl1/api.h:
//
//	#define CRYPTO_SECRETKEYBYTES 353
//	#define CRYPTO_PUBLICKEYBYTES 65
//	#define CRYPTO_BYTES          148
//
// If upstream bumps these between SQIsign reference releases the
// constants here must be updated in lockstep with a fresh build of
// the C library.
const (
	PublicKeySize = 65
	SecretKeySize = 353
	SignatureSize = 148
)

// Signer holds a SQIsign-I keypair. Pub is the 65-byte compacted
// public key (as it appears in DNSKEY rdata); SecretKey is the
// 353-byte compacted secret key. Both halves are kept so the Signer
// alone is enough to MarshalBinary into a persistable blob.
type Signer struct {
	SecretKey []byte
	Pub       []byte
}

// Public returns the raw 65-byte public key as a crypto.PublicKey.
// The concrete value is []byte; algorithm subpackages (e.g. sqisign1)
// wrap this in PublicKeyToWire / PublicKeyFromWire conversions.
func (s *Signer) Public() crypto.PublicKey { return s.Pub }

// Sign satisfies [crypto.Signer]. message is the pre-hashed input
// that miekg/dns's RRSIG/SIG signing path produces (SQIsign hashes
// internally — Hash() == 0 — so the "pre-hashed" name is a misnomer
// here, but the interface contract is unchanged).
//
// SQIsign's NIST-API crypto_sign emits sm = sig || message; we slice
// off the first CRYPTO_BYTES to hand miekg/dns a detached signature.
func (s *Signer) Sign(_ io.Reader, message []byte, _ crypto.SignerOpts) ([]byte, error) {
	if len(s.SecretKey) != SecretKeySize {
		return nil, fmt.Errorf("sqisignc sign: secret key length %d, want %d", len(s.SecretKey), SecretKeySize)
	}

	// Allocate output buffer for the signed-message form. crypto_sign
	// writes at most CRYPTO_BYTES + mlen bytes.
	smCap := C.size_t(SignatureSize + len(message))
	smPtr := C.malloc(smCap)
	if smPtr == nil {
		return nil, fmt.Errorf("sqisignc sign: malloc(%d) failed", smCap)
	}
	defer C.free(smPtr)

	var smLen C.ulonglong
	var mPtr unsafe.Pointer
	if len(message) > 0 {
		mPtr = unsafe.Pointer(&message[0])
	}
	skPtr := unsafe.Pointer(&s.SecretKey[0])

	rc := C.crypto_sign(
		(*C.uchar)(smPtr),
		&smLen,
		(*C.uchar)(mPtr),
		C.ulonglong(len(message)),
		(*C.uchar)(skPtr),
	)
	if rc != 0 {
		return nil, fmt.Errorf("sqisignc sign: crypto_sign returned %d", int(rc))
	}

	// Upstream sqisign_sign emits sm = signature_to_bytes(sigt) || m
	// and sets *smlen = SIGNATURE_BYTES + mlen. The signature
	// serialization is fixed-width (signature_to_bytes always writes
	// SIGNATURE_BYTES), so the detached signature is exactly the
	// first SignatureSize bytes of sm.
	wantSmLen := C.ulonglong(SignatureSize + len(message))
	if smLen != wantSmLen {
		return nil, fmt.Errorf("sqisignc sign: crypto_sign emitted smlen=%d, want %d", smLen, wantSmLen)
	}
	sig := C.GoBytes(smPtr, C.int(SignatureSize))
	return sig, nil
}

// Generate creates a fresh SQIsign-I keypair via crypto_sign_keypair.
func Generate() (*Signer, error) {
	pk := make([]byte, PublicKeySize)
	sk := make([]byte, SecretKeySize)
	rc := C.crypto_sign_keypair(
		(*C.uchar)(unsafe.Pointer(&pk[0])),
		(*C.uchar)(unsafe.Pointer(&sk[0])),
	)
	if rc != 0 {
		return nil, fmt.Errorf("sqisignc generate: crypto_sign_keypair returned %d", int(rc))
	}
	return &Signer{SecretKey: sk, Pub: pk}, nil
}

// VerifySignature checks a detached signature against message under
// pub. Returns nil on success, [ErrSig] on cryptographic failure, or
// a wrapped error for input-shape problems.
//
// The NIST API exposes only signed-message verify (crypto_sign_open),
// so we rebuild sm = signature || message on the C side and let
// crypto_sign_open both recover m and validate. Upstream's open
// expects the signed-message format produced by crypto_sign — i.e.
// the fixed-width signature followed by the message — and returns
// non-zero on any cryptographic failure.
func VerifySignature(pub, message, signature []byte) error {
	if len(pub) != PublicKeySize {
		return fmt.Errorf("sqisignc verify: public key length %d, want %d", len(pub), PublicKeySize)
	}
	if len(signature) != SignatureSize {
		return fmt.Errorf("sqisignc verify: signature length %d, want %d", len(signature), SignatureSize)
	}

	smLen := C.size_t(SignatureSize + len(message))
	smPtr := C.malloc(smLen)
	if smPtr == nil {
		return fmt.Errorf("sqisignc verify: malloc(%d) failed", smLen)
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

	// crypto_sign_open writes the recovered message into mPtr. We
	// size it at smLen (an upper bound; actual recovered length is
	// smLen - SignatureSize). The recovered bytes are discarded —
	// non-zero return from crypto_sign_open is the verdict.
	mPtr := C.malloc(smLen)
	if mPtr == nil {
		return fmt.Errorf("sqisignc verify: malloc(%d) failed", smLen)
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
// byte slice. Layout: secret_bytes || public_bytes (353 + 65 = 418
// bytes). Both lengths are fixed for SQIsign-I, so UnmarshalBinary
// can split on the SecretKeySize boundary.
//
// As in the liboqs adapter, persisting both halves rather than
// rederiving the public key from the secret key is the simplest
// reliable round-trip — the SQIsign reference impl exposes no public
// "pk from sk" function.
func (s *Signer) MarshalBinary() ([]byte, error) {
	if len(s.SecretKey) != SecretKeySize {
		return nil, fmt.Errorf("sqisignc marshal: secret key length %d, want %d", len(s.SecretKey), SecretKeySize)
	}
	if len(s.Pub) != PublicKeySize {
		return nil, fmt.Errorf("sqisignc marshal: public key length %d, want %d", len(s.Pub), PublicKeySize)
	}
	out := make([]byte, 0, SecretKeySize+PublicKeySize)
	out = append(out, s.SecretKey...)
	out = append(out, s.Pub...)
	return out, nil
}

// UnmarshalBinary is the inverse of MarshalBinary.
func UnmarshalBinary(buf []byte) (*Signer, error) {
	if len(buf) != SecretKeySize+PublicKeySize {
		return nil, fmt.Errorf("sqisignc unmarshal: blob length %d, want %d (sk %d + pk %d)",
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
