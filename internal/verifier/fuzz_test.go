package verifier_test

// Fuzz the eight-step engine: no matter what garbage is fed as the token / CAT /
// CT / DPoP strings, the verifier must (a) never panic and (b) never return
// ALLOW. With an empty Trust Registry no issuer key resolves, so a sound engine
// denies every input at step 1 or later — fails closed. This is the adversarial
// complement to the hand-written TestSec_* cases.
//   go test ./internal/verifier/ -run x -fuzz FuzzVerify_NeverAllowsGarbage

import (
	"context"
	"testing"

	"github.com/violetskysecurity/spt-txn-poc/internal/ledger"
	"github.com/violetskysecurity/spt-txn-poc/internal/trustregistry"
	"github.com/violetskysecurity/spt-txn-poc/internal/verifier"
)

func FuzzVerify_NeverAllowsGarbage(f *testing.F) {
	f.Add("header.payload.sig", "cat-token", "ct-token", "dpop-proof")
	f.Add("", "", "", "")
	f.Add("....", "a.b.c", "x.y.z", "p.q.r")
	f.Fuzz(func(t *testing.T, tok, cat, ct, dpop string) {
		reg, err := trustregistry.NewMockRegistry("")
		if err != nil {
			t.Skip()
		}
		eng := verifier.New(reg)
		d := eng.Verify(context.Background(), verifier.Input{
			TxnToken:  tok,
			CAT:       cat,
			CT:        ct,
			DPoPProof: dpop,
			HTM:       "POST",
			HTU:       "https://foss.violetskysecurity.com/b/verify",
			Audience:  "domain-b.execorg",
			Txn: ledger.TxnContext{
				Chain: "xrpl", Beneficiary: "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW",
				Amount: "1", Currency: "XRP", Timestamp: 1750000000,
			},
		})
		if d.Allow {
			t.Fatalf("garbage input was ALLOWED (tok=%q cat=%q ct=%q)", tok, cat, ct)
		}
	})
}
