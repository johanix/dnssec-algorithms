package qruovc

import "errors"

// ErrSig indicates a signature failed verification (well-formed
// inputs, cryptographically invalid). Algorithm subpackages translate
// this to dns.ErrSig at their boundary, matching the convention
// established by sibling adapters sqisignc.ErrSig and liboqs.ErrSig.
var ErrSig = errors.New("dnssec-algorithms/qruovc: bad signature")
