// Package pkcs8 provides a registry of out-of-tree PKCS#8 codecs for
// private keys whose algorithm OID is not understood by
// crypto/x509.MarshalPKCS8PrivateKey and ParsePKCS8PrivateKey.
//
// The Go standard library covers RSA, ECDSA and Ed25519. Algorithms
// outside that set (post-quantum, experimental, or otherwise) need an
// algorithm-specific encoder/decoder. This package lets each
// algorithm subpackage register a [Codec]; consumers (typically key
// storage code in applications using miekg/dns) call [Marshal] and
// [Parse] which iterate registered codecs in registration order and
// return the first non-[ErrUnsupported] result.
//
// Each codec is expected to:
//   - Return [ErrUnsupported] from [Codec.MarshalPKCS8] when priv is
//     not the concrete Go type the codec handles.
//   - Return [ErrUnsupported] from [Codec.ParsePKCS8] when the DER's
//     algorithm OID does not match the codec.
//
// The package is dependency-free (stdlib only). Importing it does not
// pull in any specific algorithm or its crypto backend; that happens
// only when a consumer blank-imports an algorithm subpackage such as
// github.com/johanix/dnssec-algorithms/mldsa44.
package pkcs8

import (
	"crypto"
	"errors"
	"sync"
)

// ErrUnsupported indicates a codec did not recognize the supplied
// private key (for [Codec.MarshalPKCS8]) or the supplied DER's
// algorithm OID (for [Codec.ParsePKCS8]). [Marshal] and [Parse] treat
// ErrUnsupported as "try the next codec".
var ErrUnsupported = errors.New("dnssec-algorithms/pkcs8: codec does not support this key/OID")

// Codec marshals to and parses from PKCS#8 DER for one algorithm.
// Implementations are stateless and safe for concurrent use.
type Codec interface {
	// MarshalPKCS8 returns the PKCS#8 DER encoding of priv. Returns
	// ErrUnsupported if priv is not the concrete Go type this codec
	// handles.
	MarshalPKCS8(priv crypto.PrivateKey) ([]byte, error)

	// ParsePKCS8 decodes a PKCS#8 DER blob into a private key.
	// Returns ErrUnsupported if the blob's algorithm OID does not
	// match the codec. Other errors indicate the OID matched but
	// decoding failed.
	ParsePKCS8(der []byte) (crypto.PrivateKey, error)
}

var (
	mu     sync.RWMutex
	codecs []Codec
)

// Register adds c to the registry. Typical usage is from an init
// function in an algorithm subpackage:
//
//	func init() { pkcs8.Register(myCodec{}) }
//
// Registration order matters only when two codecs claim the same key
// type or OID (which is a bug in one of them). First registered wins.
func Register(c Codec) {
	mu.Lock()
	defer mu.Unlock()
	codecs = append(codecs, c)
}

// Marshal returns the PKCS#8 DER encoding of priv by trying each
// registered codec in registration order. Returns [ErrUnsupported] if
// no codec recognizes the key. Use this only when
// [crypto/x509.MarshalPKCS8PrivateKey] does not handle the key type.
func Marshal(priv crypto.PrivateKey) ([]byte, error) {
	mu.RLock()
	defer mu.RUnlock()
	for _, c := range codecs {
		der, err := c.MarshalPKCS8(priv)
		if errors.Is(err, ErrUnsupported) {
			continue
		}
		return der, err
	}
	return nil, ErrUnsupported
}

// Parse decodes PKCS#8 DER by trying each registered codec in
// registration order. Returns [ErrUnsupported] if no codec recognizes
// the algorithm OID. Use this only when
// [crypto/x509.ParsePKCS8PrivateKey] does not handle the blob's OID.
func Parse(der []byte) (crypto.PrivateKey, error) {
	mu.RLock()
	defer mu.RUnlock()
	for _, c := range codecs {
		priv, err := c.ParsePKCS8(der)
		if errors.Is(err, ErrUnsupported) {
			continue
		}
		return priv, err
	}
	return nil, ErrUnsupported
}
