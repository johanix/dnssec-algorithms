package qruov1_test

import (
	"crypto"
	"net"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/johanix/dnssec-algorithms/qruov1"
)

// codepoint is the experimental DNSSEC algorithm number this test
// binds QR-UOV-I to. It matches the convention used by the demo and
// the tdns apps; any private-use value would do.
const codepoint = 205

// Registration is process-global in miekg/dns, so do it once.
func init() {
	if err := dns.RegisterAlgorithm(codepoint, qruov1.New()); err != nil {
		panic("RegisterAlgorithm: " + err.Error())
	}
}

// newKey generates a fresh QR-UOV-I DNSKEY + signer.
func newKey(t *testing.T) (*dns.DNSKEY, crypto.Signer) {
	t.Helper()
	dnskey := &dns.DNSKEY{
		Hdr:       dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeDNSKEY, Class: dns.ClassINET, Ttl: 3600},
		Flags:     257,
		Protocol:  3,
		Algorithm: codepoint,
	}
	priv, err := dnskey.Generate(0)
	if err != nil {
		t.Fatalf("DNSKEY.Generate: %v", err)
	}
	signer, ok := priv.(crypto.Signer)
	if !ok {
		t.Fatalf("generated private key is not a crypto.Signer (%T)", priv)
	}
	return dnskey, signer
}

func TestRegistration(t *testing.T) {
	if got := dns.AlgorithmToString[codepoint]; got != "QRUOV1" {
		t.Errorf("AlgorithmToString[%d] = %q, want QRUOV1", codepoint, got)
	}
	if got := dns.StringToAlgorithm["QRUOV1"]; got != codepoint {
		t.Errorf("StringToAlgorithm[QRUOV1] = %d, want %d", got, codepoint)
	}
	if got := dns.AlgorithmToHash[codepoint]; got != 0 {
		t.Errorf("AlgorithmToHash[%d] = %v, want 0 (identity)", codepoint, got)
	}
}

func TestKeyGen(t *testing.T) {
	dnskey, _ := newKey(t)
	// 23641 raw public-key bytes -> base64. The exact base64 length is
	// ceil(23641/3)*4 = 31524.
	if got := len(dnskey.PublicKey); got != 31524 {
		t.Errorf("public key base64 length = %d, want 31524", got)
	}
}

func TestPrivateKeyRoundTrip(t *testing.T) {
	dnskey, priv := newKey(t)
	privStr := dnskey.PrivateKeyString(priv)
	np, err := dnskey.NewPrivateKey(privStr)
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	if _, ok := np.(crypto.Signer); !ok {
		t.Fatalf("round-tripped key is not a crypto.Signer (%T)", np)
	}
}

// TestDirectCrypto exercises the raw sign/verify path of the
// registered algorithm, independent of the high-level RRSIG/SIG
// packing (which trips over the fork's 4 KB KeyTag/pack-buffer limit
// for large PQ keys — see TestRRSIGSignVerify). This is the core test
// that the QR-UOV C library, the CGO marshalling, and the per-call RNG
// reseeding all work end to end.
func TestDirectCrypto(t *testing.T) {
	_, signer := newKey(t)
	impl := qruov1.New()
	msg := []byte("the quick brown fox jumps over the lazy dog")

	sig, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) != 157 {
		t.Errorf("signature length = %d, want 157", len(sig))
	}

	pubWire, err := impl.PublicKeyToWire(signer.Public())
	if err != nil {
		t.Fatalf("PublicKeyToWire: %v", err)
	}
	pub, err := impl.PublicKeyFromWire(pubWire)
	if err != nil {
		t.Fatalf("PublicKeyFromWire: %v", err)
	}

	if err := impl.Verify(pub, msg, sig); err != nil {
		t.Errorf("Verify of valid signature: %v", err)
	}

	bad := append([]byte(nil), msg...)
	bad[0] ^= 0xff
	if err := impl.Verify(pub, bad, sig); err == nil {
		t.Error("Verify accepted a tampered message")
	}

	// A second signature over the same message must also verify —
	// confirms per-call RNG reseeding doesn't corrupt the DRBG state.
	sig2, err := signer.Sign(nil, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("Sign (2nd): %v", err)
	}
	if err := impl.Verify(pub, msg, sig2); err != nil {
		t.Errorf("Verify of 2nd independent signature: %v", err)
	}
}

func TestSIG0SignVerify(t *testing.T) {
	dnskey, signer := newKey(t)
	now := time.Now()

	key := &dns.KEY{DNSKEY: *dnskey}
	key.Hdr.Rrtype = dns.TypeKEY

	m := new(dns.Msg)
	m.SetQuestion("example.com.", dns.TypeA)
	sig0 := &dns.SIG{
		RRSIG: dns.RRSIG{
			Hdr:        dns.RR_Header{Name: ".", Rrtype: dns.TypeSIG, Class: dns.ClassANY, Ttl: 0},
			Algorithm:  codepoint,
			Expiration: uint32(now.Add(time.Hour).Unix()),
			Inception:  uint32(now.Add(-time.Hour).Unix()),
			KeyTag:     12345, // SIG.Verify only checks KeyTag != 0, not a match
			SignerName: "example.com.",
		},
	}
	buf, err := sig0.Sign(signer, m)
	if err != nil {
		t.Fatalf("SIG(0) Sign: %v", err)
	}
	if err := sig0.Verify(key, buf); err != nil {
		t.Errorf("SIG(0) Verify: %v", err)
	}
}

// TestRRSIGSignVerify exercises the full high-level RRSIG path with a
// real KeyTag. This relies on the fork sizing its DNSKEY packing
// buffers to the key (commit "dnssec: size DNSKEY scratch buffers to
// the key, not DefaultMsgSize"); before that fix k.KeyTag() returned 0
// for the 23 KB QR-UOV key and RRSIG.Verify rejected on the
// rr.KeyTag != k.KeyTag() guard.
func TestRRSIGSignVerify(t *testing.T) {
	dnskey, signer := newKey(t)
	now := time.Now()

	keytag := dnskey.KeyTag()
	if keytag == 0 {
		t.Fatal("DNSKEY.KeyTag() == 0 for a large QR-UOV key — fork buffer fix missing; bump the github.com/johanix/dns dependency")
	}

	a := &dns.A{Hdr: dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 3600}}
	a.A = net.ParseIP("192.0.2.1")
	rrset := []dns.RR{a}

	rrsig := &dns.RRSIG{
		Hdr:         dns.RR_Header{Name: "example.com.", Rrtype: dns.TypeRRSIG, Class: dns.ClassINET, Ttl: 3600},
		TypeCovered: dns.TypeA,
		Algorithm:   codepoint,
		Labels:      2,
		OrigTtl:     3600,
		Expiration:  uint32(now.Add(24 * time.Hour).Unix()),
		Inception:   uint32(now.Add(-time.Hour).Unix()),
		KeyTag:      keytag,
		SignerName:  "example.com.",
	}
	if err := rrsig.Sign(signer, rrset); err != nil {
		t.Fatalf("RRSIG.Sign: %v", err)
	}
	if err := rrsig.Verify(dnskey, rrset); err != nil {
		t.Fatalf("RRSIG.Verify: %v", err)
	}

	// Tamper: flip the address and confirm verification now fails.
	a.A = net.ParseIP("192.0.2.2")
	if err := rrsig.Verify(dnskey, rrset); err == nil {
		t.Error("RRSIG.Verify accepted a tampered RRset")
	}
}
