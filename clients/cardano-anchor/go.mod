// Separate module: the Cardano SDK is heavy and chain-specific, so it stays out
// of the offline core (blockchain-agnostic invariant) — same quarantine as the
// other chain clients. Cardano = anchor pattern (native tx metadata, no Plutus),
// mirroring the Sui/Aptos/Starknet anchors.
//
// First build on the Mac (echovl/cardano-go is WIP — expect a couple of API
// tweaks; see LIB-CHECK markers in main.go):
//   cd clients/cardano-anchor
//   go get github.com/echovl/cardano-go@latest
//   go mod tidy && go build -o cardano-anchor .
module github.com/rudizee007/spt-txn-poc/clients/cardano-anchor

go 1.25.13

require github.com/echovl/cardano-go v0.1.13

require (
	filippo.io/edwards25519 v1.1.1 // indirect
	github.com/blockfrost/blockfrost-go v0.1.0 // indirect
	github.com/echovl/ed25519 v0.2.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
)
