// Separate module: the Aptos SDK is chain-specific, so it stays out of the
// offline core (blockchain-agnostic invariant) — same quarantine as
// clients/hcs-anchor and clients/hedera-pay.
//
// First build on the Mac:
//   cd clients/aptos-pay
//   go get github.com/aptos-labs/aptos-go-sdk@latest
//   go mod tidy && go build -o aptos-pay .
module github.com/rudizee007/spt-txn-poc/clients/aptos-pay

go 1.25.13

require github.com/aptos-labs/aptos-go-sdk v1.13.0

require (
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/hasura/go-graphql-client v0.15.1 // indirect
	github.com/hdevalence/ed25519consensus v0.2.0 // indirect
)
