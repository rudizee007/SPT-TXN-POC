package verify_test

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/rudizee007/spt-txn-poc/pkg/verify"
)

// Example shows the whole embed surface: load a registry snapshot once, then
// verify presentations offline. (Not executed — no live snapshot fixture — but
// compiled, so it pins the public API.)
func Example() {
	// The publication key is pinned in config, not discovered. This is the root
	// of trust for every offline verification below, so it is the one thing an
	// operator must place deliberately.
	pub, err := hex.DecodeString("<64 hex chars: the publisher's ed25519 public key>")
	if err != nil {
		panic(err)
	}

	// Load the locally-cached Trust Registry snapshot once at startup. Both
	// halves are required: the manifest carries the signature, the body carries
	// the records, and a body on its own authenticates nothing.
	v, err := verify.FromSignedSnapshot(
		"/var/spt-txn/registry-snapshot.manifest.json",
		"/var/spt-txn/registry-snapshot.json",
		verify.SnapshotOptions{
			PinnedKeys: []ed25519.PublicKey{pub},
			MaxAge:     24 * time.Hour,
		},
	)
	if err != nil {
		panic(err)
	}

	// Per request: hand the engine the presented tokens + the transaction.
	d := v.Verify(context.Background(), verify.Input{
		TxnToken:  "<spt-txn JWT>",
		CAT:       "<root CAT JWT>",
		CTChain:   []string{"<ct JWT>"},
		DPoPProof: "<dpop proof JWT>",
		HTM:       "POST",
		HTU:       "https://vasp.example/transfer",
		Audience:  "vasp.example",
		Txn: verify.TxnContext{
			Chain:       "xrpl",
			Beneficiary: "rBeneficiaryAddr",
			Amount:      "100",
			Currency:    "XRP",
			Timestamp:   1750000000,
		},
	})

	if d.Allow {
		fmt.Println("authorized")
	} else {
		fmt.Printf("denied at step %d (%s): %s\n", d.Step, d.StepName, d.Reason)
	}
}
