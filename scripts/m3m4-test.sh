#!/bin/sh
# Run the M3 + M4 unit/integration tests. Intended for the OpenBSD host where
# the Go toolchain lives (GOPATH=$HOME/go). Pure stdlib — no module
# downloads required for the new packages.
set -e
cd "$(dirname "$0")/.."

echo "== go vet (M3/M4 packages) =="
go vet ./internal/tbac/... ./internal/cttoken/... ./internal/ledger/... \
       ./internal/dpop/... ./internal/txntoken/...

echo "== go test (verbose) =="
go test -v ./internal/tbac/... ./internal/cttoken/... ./internal/ledger/... \
            ./internal/dpop/... ./internal/txntoken/...

echo
echo "All M3/M4 tests passed."
