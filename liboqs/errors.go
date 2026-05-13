package liboqs

import "errors"

// ErrSig indicates a signature failed verification (well-formed
// inputs, cryptographically invalid). Equivalent in spirit to
// [github.com/miekg/dns.ErrSig], duplicated here so the liboqs/
// subpackage stays independent of miekg/dns (algorithm subpackages
// translate to dns.ErrSig at their boundary).
var ErrSig = errors.New("dnssec-algorithms/liboqs: bad signature")
