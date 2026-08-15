// Separate module: the NEAR SDK is heavy and chain-specific, so it stays out of
// the offline core (blockchain-agnostic invariant) — same quarantine as the other
// chain submitters. NEAR is non-EVM (named accounts, yoctoNEAR, Borsh); the
// humanAnchor is bound in the attestation (native transfer has no memo).
//
// First build on the Mac (let near-api-go pull its own uint128 version — do NOT
// `go get golang-uint128@latest`, that tag was repointed to lukechampine.com):
//   cd clients/near-pay
//   go get github.com/eteu-technologies/near-api-go@latest
//   go mod tidy && go build -o near-pay .
module github.com/rudizee007/spt-txn-poc/clients/near-pay

go 1.25.13

require (
	github.com/eteu-technologies/golang-uint128 v1.1.2-eteu
	github.com/eteu-technologies/near-api-go v0.0.1
)

require (
	github.com/eteu-technologies/borsh-go v0.3.2 // indirect
	github.com/mr-tron/base58 v1.2.0 // indirect
)
