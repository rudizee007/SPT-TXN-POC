// Separate module: the Hedera SDK is heavy and chain-specific, so it is
// quarantined here and NEVER enters the main spt-poc module's dependency graph
// (the blockchain-agnostic invariant — the authorization core must not import a
// ledger SDK). Build it on its own:
//
//	cd clients/hcs-anchor
//	go get github.com/hiero-ledger/hiero-sdk-go/v2@latest
//	go mod tidy
//	go build .
//
// The `verify` subcommand uses only the standard library (public mirror-node
// REST); only `create-topic` and `anchor` pull in the SDK.
module github.com/rudizee007/spt-txn-poc/clients/hcs-anchor

go 1.25.13

require github.com/hiero-ledger/hiero-sdk-go/v2 v2.83.0

require (
	github.com/btcsuite/btcd/btcec/v2 v2.5.0 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/rs/zerolog v1.35.1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/grpc v1.83.0 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
