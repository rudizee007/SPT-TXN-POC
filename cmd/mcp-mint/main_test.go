package main

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
)

const (
	tTool   = "payments.transfer"
	tArgs   = `{"amount":"3000","currency":"USD","beneficiary":"acct-A"}`
	tTarget = "mcp://payments"
	tAud    = "payments.example"
)

func mintOK(t *testing.T, args string) *Output {
	t.Helper()
	out, err := mint(tTool, args, tTarget, tAud, "3000", "USD", 10000, false)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	return out
}

// The token must verify against the public key the command prints. If these
// ever drift, every demo run fails at the PEP for a reason that has nothing to
// do with what the demo is showing.
func TestMint_TokenVerifiesAgainstThePrintedKey(t *testing.T) {
	out := mintOK(t, tArgs)
	pub, err := hex.DecodeString(out.TTSPublicKey)
	if err != nil {
		t.Fatalf("tts_pub is not hex: %v", err)
	}
	claims, err := txntoken.Verify(out.Token, pub)
	if err != nil {
		t.Fatalf("the minted token does not verify against the printed key: %v", err)
	}
	if got := claims["aud"]; got != tAud {
		t.Fatalf("aud = %v, want %q", got, tAud)
	}
	if intent.BoundDigestFromClaims(claims) != out.IntentDigest {
		t.Fatal("the token's bound intent digest is not the one reported")
	}
}

// The whole point of the artifact: the digest covers the arguments, so one
// changed byte is a different intent.
func TestMint_ADifferentArgumentIsADifferentIntent(t *testing.T) {
	honest := mintOK(t, tArgs)
	mutated := mintOK(t, `{"amount":"3000","currency":"USD","beneficiary":"attacker-B"}`)
	if honest.IntentDigest == mutated.IntentDigest {
		t.Fatal("mutating the beneficiary did not change the intent digest — the binding is not binding")
	}

	// And the honest token's digest must reject the mutated call.
	err := intent.Match(honest.IntentDigest, intent.Intent{
		Tool:   tTool,
		Params: json.RawMessage(`{"amount":"3000","currency":"USD","beneficiary":"attacker-B"}`),
		Target: tTarget,
	})
	if err == nil {
		t.Fatal("the honest token's digest matched a mutated call")
	}
}

// Key material must not be reused between runs; a fixed demo key is a demo key
// that ends up somewhere real.
func TestMint_KeysAreFreshPerRun(t *testing.T) {
	a := mintOK(t, tArgs)
	b := mintOK(t, tArgs)
	if a.TTSPublicKey == b.TTSPublicKey {
		t.Fatal("two runs produced the same tts key")
	}
	if a.Token == b.Token {
		t.Fatal("two runs produced the same token")
	}
}

func TestMint_RendersAToolsCallCarryingTheToken(t *testing.T) {
	out := mintOK(t, tArgs)
	var m struct {
		Method string `json:"method"`
		Params struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
			Meta      map[string]any  `json:"_meta"`
		} `json:"params"`
	}
	if err := json.Unmarshal(out.ToolsCall, &m); err != nil {
		t.Fatalf("tools_call is not valid JSON: %v", err)
	}
	if m.Method != "tools/call" || m.Params.Name != tTool {
		t.Fatalf("wrong tools/call shape: %s", out.ToolsCall)
	}
	if m.Params.Meta["spt-txn/token"] != out.Token {
		t.Fatal("the rendered tools/call does not carry the minted token")
	}
}

func TestMint_RefusesArgumentsThatAreNotAJSONObject(t *testing.T) {
	for _, bad := range []string{`[1,2]`, `"a string"`, `{not json`, `null`, ``} {
		if _, err := mint(tTool, bad, tTarget, tAud, "3000", "USD", 10000, false); err == nil {
			t.Fatalf("-args %q was accepted", bad)
		}
	}
}

// The leaf token is TRANSACTION-bound, not scope-carrying: the ceiling lives in
// the CT chain and the leaf references it. This pins the three bindings the leaf
// is actually responsible for, because an earlier version of this test asserted
// the leaf carried `currency` and it does not — the assertion was wrong, not the
// code, and a test that encodes a misreading of the design is worse than none.
func TestMint_LeafCarriesItsThreeBindings(t *testing.T) {
	out := mintOK(t, tArgs)
	pub, _ := hex.DecodeString(out.TTSPublicKey)
	claims, err := txntoken.Verify(out.Token, pub)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{
		"spt_intent_digest",    // which call this authorizes
		"spt_txn_context_hash", // which transaction it is bound to
		"spt_ct_ref",           // which delegated capability it descends from
		"cnf",                  // which holder key may present it
	} {
		if _, ok := claims[c]; !ok {
			b, _ := json.Marshal(claims)
			t.Fatalf("leaf claim %q is absent: %s", c, b)
		}
	}
	if claims["spt_txn_chain"] != "none" {
		t.Fatalf("spt_txn_chain = %v, want the chain-neutral adapter", claims["spt_txn_chain"])
	}
}
