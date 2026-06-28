package verify_test

import (
	"context"
	"fmt"

	"github.com/violetskysecurity/spt-txn-poc/pkg/verify"
)

// Example shows the whole embed surface: load a registry snapshot once, then
// verify presentations offline. (Not executed — no live snapshot fixture — but
// compiled, so it pins the public API.)
func Example() {
	// Load the locally-cached Trust Registry snapshot once at startup.
	v, err := verify.FromSnapshot("/var/spt-txn/registry-snapshot.json")
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
