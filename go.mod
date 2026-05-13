module github.com/johanix/dnssec-algorithms

go 1.25.0

require (
	github.com/cloudflare/circl v1.6.3
	github.com/miekg/dns v1.1.70
)

require (
	golang.org/x/crypto v0.49.0 // indirect
	golang.org/x/mod v0.34.0 // indirect
	golang.org/x/net v0.52.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.42.0 // indirect
	golang.org/x/tools v0.43.0 // indirect
)

// Until the algorithm-registration API lands upstream, depend on the
// johanix/dns fork's algorithm-registry branch (which carries the
// Algorithm interface and dispatch registry).
replace github.com/miekg/dns => github.com/johanix/dns v0.0.0-20260513105419-747cbcbc3ac8
