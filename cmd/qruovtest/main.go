// Command qruovtest exercises the QR-UOV-I algorithm end to end
// through the miekg/dns registration API: keygen, RRSIG sign+verify,
// SIG(0) sign+verify, a direct adapter crypto round-trip, and a
// private-key string round-trip. It imports only qruov1 (not the
// liboqs/sqisign subpackages), so it links with just libqruov.a +
// libcrypto.
//
// This is a standalone smoke-test binary; the same coverage lives as
// go tests in qruov1/qruov1_test.go.
package main

import (
	"crypto"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/qruov1"
)

const codepoint = 205

func fail(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "FAIL: "+format+"\n", a...)
	os.Exit(1)
}

func main() {
	if err := dns.RegisterAlgorithm(codepoint, qruov1.New()); err != nil {
		fail("RegisterAlgorithm: %v", err)
	}
	hashStr := "identity (0)"
	if h := dns.AlgorithmToHash[codepoint]; h != 0 {
		hashStr = h.String()
	}
	fmt.Printf("registered QR-UOV-I at codepoint %d (name %q, hash %s)\n",
		codepoint, dns.AlgorithmToString[codepoint], hashStr)

	const zone = "example.com."

	// --- DNSKEY generation -------------------------------------------
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: zone, Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: codepoint,
	}
	priv, err := dnskey.Generate(0)
	if err != nil {
		fail("DNSKEY.Generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		fail("generated private key is not a crypto.Signer (%T)", priv)
	}
	keytag := dnskey.KeyTag()
	if keytag == 0 {
		fail("DNSKEY.KeyTag() == 0 for a large QR-UOV key — fork buffer fix missing; bump the github.com/johanix/dns dependency")
	}
	fmt.Printf("generated DNSKEY: public key %d base64 chars, keytag %d\n",
		len(dnskey.PublicKey), keytag)

	// --- private-key string round-trip -------------------------------
	privStr := dnskey.PrivateKeyString(priv)
	fmt.Printf("private key string: %d bytes\n", len(privStr))
	np, err := dnskey.NewPrivateKey(privStr)
	if err != nil {
		fail("NewPrivateKey round-trip: %v", err)
	}
	if _, ok := np.(crypto.Signer); !ok {
		fail("round-tripped private key is not a crypto.Signer (%T)", np)
	}
	fmt.Println("private-key string round-trip: OK")

	// --- direct adapter crypto round-trip ----------------------------
	{
		msg := []byte("the quick brown fox jumps over the lazy dog")
		rawSig, err := signer.Sign(nil, msg, crypto.Hash(0))
		if err != nil {
			fail("direct Sign: %v", err)
		}
		fmt.Printf("direct sign: %d-byte signature\n", len(rawSig))

		impl := qruov1.New()
		pubWire, err := impl.PublicKeyToWire(signer.Public())
		if err != nil {
			fail("PublicKeyToWire: %v", err)
		}
		pub, err := impl.PublicKeyFromWire(pubWire)
		if err != nil {
			fail("PublicKeyFromWire: %v", err)
		}
		if err := impl.Verify(pub, msg, rawSig); err != nil {
			fail("direct Verify (should succeed): %v", err)
		}
		fmt.Println("direct verify (valid): OK")

		bad := append([]byte(nil), msg...)
		bad[0] ^= 0xff
		if err := impl.Verify(pub, bad, rawSig); err == nil {
			fail("direct Verify accepted a tampered message")
		}
		fmt.Println("direct verify (tampered -> rejected): OK")

		// Second signature over the same message must still verify
		// (confirms per-call RNG reseeding doesn't corrupt state).
		rawSig2, err := signer.Sign(nil, msg, crypto.Hash(0))
		if err != nil {
			fail("direct Sign (2nd): %v", err)
		}
		if err := impl.Verify(pub, msg, rawSig2); err != nil {
			fail("direct Verify of 2nd signature: %v", err)
		}
		fmt.Println("direct verify (2nd independent signature): OK")
	}

	now := time.Now()

	// --- RRSIG sign + verify -----------------------------------------
	a1 := &dns.A{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}}
	a1.A = net.ParseIP("192.0.2.1")
	a2 := &dns.A{Hdr: dns.RR_Header{Name: zone, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}}
	a2.A = net.ParseIP("192.0.2.2")
	rrset := []dns.RR{a1, a2}

	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: zone, Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   codepoint,
		Labels:      2,
		OrigTtl:     3600,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		KeyTag:      keytag,
		SignerName:  zone,
	}
	if err := rrsig.Sign(signer, rrset); err != nil {
		fail("RRSIG.Sign: %v", err)
	}
	fmt.Printf("RRSIG signed: signature %d base64 chars\n", len(rrsig.Signature))
	if err := rrsig.Verify(dnskey, rrset); err != nil {
		fail("RRSIG.Verify (should succeed): %v", err)
	}
	fmt.Println("RRSIG verify (valid): OK")

	a2.A = net.ParseIP("192.0.2.3")
	if err := rrsig.Verify(dnskey, rrset); err == nil {
		fail("RRSIG.Verify accepted a tampered RRset")
	}
	fmt.Println("RRSIG verify (tampered -> rejected): OK")
	a2.A = net.ParseIP("192.0.2.2")

	// --- SIG(0) sign + verify ----------------------------------------
	key := &dns.KEY{DNSKEY: *dnskey}
	key.Hdr.Rrtype = dns.TypeKEY

	m := new(dns.Msg)
	m.SetQuestion(zone, dns.TypeA)
	sig0 := &dns.SIG{
		RRSIG: dns.RRSIG{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY, Ttl: 0},
			Algorithm:  codepoint,
			Expiration: uint32(now.Add(time.Hour).Unix()),
			Inception:  uint32(now.Add(-time.Hour).Unix()),
			KeyTag:     keytag,
			SignerName: zone,
		},
	}
	buf, err := sig0.Sign(signer, m)
	if err != nil {
		fail("SIG(0) Sign: %v", err)
	}
	fmt.Printf("SIG(0) signed message: %d bytes on the wire\n", len(buf))

	if err := sig0.Verify(key, buf); err != nil {
		fail("SIG(0) Verify (should succeed): %v", err)
	}
	fmt.Println("SIG(0) verify (valid): OK")

	fmt.Println("\nALL CHECKS PASSED")
}
