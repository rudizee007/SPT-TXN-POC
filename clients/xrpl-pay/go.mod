// Separate module so the XRPL SDK dependency stays OUT of the offline core
// (mirrors clients/hcs-anchor). The core `go build ./...` never pulls this in.
//
// First build on the Mac:
//   cd clients/xrpl-pay && go mod tidy && go build ./...
module github.com/rudizee007/spt-txn-poc/clients/xrpl-pay

go 1.25.13

require github.com/Peersyst/xrpl-go v0.2.0

require (
	github.com/bsv-blockchain/go-sdk v1.2.9 // indirect
	github.com/decred/dcrd/crypto/ripemd160 v1.0.2 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.4.1 // indirect
	github.com/go-viper/mapstructure/v2 v2.5.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/modern-go/concurrent v0.0.0-20180228061459-e0a39a4cb421 // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/ugorji/go/codec v1.2.11 // indirect
	golang.org/x/crypto v0.55.0 // indirect
)
