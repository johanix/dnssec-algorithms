package sqisignc

import "errors"

// ErrSig indicates a signature failed verification (well-formed
// inputs, cryptographically invalid). Algorithm subpackages translate
// this to dns.ErrSig at their boundary, matching the convention
// established by sibling adapter liboqs.ErrSig.
var ErrSig = errors.New("dnssec-algorithms/sqisignc: bad signature")
