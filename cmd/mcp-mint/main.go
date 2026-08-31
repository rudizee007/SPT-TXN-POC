// Command mcp-mint issues a demo SPT-Txn token bound to one MCP tool-call, so
// cmd/mcp-pep has something to enforce against.
//
// # This is demo and development tooling, not an issuer
//
// A production deployment mints tokens from a real identity root through the
// TTS; this command stands up a throwaway CAT -> CT -> SPT-Txn chain in memory
// with freshly generated keys and prints the leaf token. It adds no issuance
// logic of its own — every token here is produced by internal/{cattoken,
// cttoken,txntoken}, the same functions the services use. What it exists for is
// that nothing else in the tree emits an intent-bound token an EXTERNAL policy
// enforcement point can consume: cmd/spt-demo builds one in process and
// verifies it in the same process, which proves the chain but leaves the PEP
// with nothing to be handed.
//
// Keys are generated per run and discarded. Do not point anything at this that
// you would not also point at /dev/urandom.
//
//	mcp-mint -tool payments.transfer -target mcp://payments \
//	         -audience payments.example -args '{"amount":"3000","currency":"USD"}'
//
// It prints a JSON object carrying the tts public key (which mcp-pep verifies
// against), the token, and a ready-to-paste tools/call message.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/cattoken"
	"github.com/rudizee007/spt-txn-poc/internal/cttoken"
	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/internal/ledger"
	"github.com/rudizee007/spt-txn-poc/internal/tbac"
	"github.com/rudizee007/spt-txn-poc/internal/txntoken"
)

func main() {
	tool := flag.String("tool", "", "the MCP tool name the token authorizes (required)")
	argsJSON := flag.String("args", "{}", "the tool arguments, as a JSON object — bound byte-exact")
	target := flag.String("target", "", "the wrapped server's identity; must equal mcp-pep's -server-identity (required)")
	audience := flag.String("audience", "", "the executing domain; must equal mcp-pep's -audience (required)")
	ceiling := flag.Int("ceiling", 10000, "the root CAT's max_amount ceiling")
	amount := flag.String("amount", "3000", "the transaction amount to bind")
	currency := flag.String("currency", "USD", "the currency the ceiling and amount are denominated in")
	allowUnpriced := flag.Bool("allow-unpriced", false, "mint even though -args declares no "+
		"amount. Only for a tool that genuinely moves no money: without an amount in the "+
		"arguments, the ceiling bounds a value the tool never sees")
	logKeyOut := flag.String("log-key-out", "", "if set, write a fresh hex receipt-log key here for mcp-pep's -log-key-file")
	flag.Parse()

	if *tool == "" || *target == "" || *audience == "" {
		flag.Usage()
		fmt.Fprintln(os.Stderr, "\n-tool, -target and -audience are required. -target and -audience must "+
			"match the mcp-pep instance exactly: a token minted for another server or another domain "+
			"is supposed to be refused, and if these drift you will be demonstrating that instead.")
		os.Exit(2)
	}

	out, err := mint(*tool, *argsJSON, *target, *audience, *amount, *currency, *ceiling, *allowUnpriced)
	if err != nil {
		fmt.Fprintln(os.Stderr, "mint:", err)
		os.Exit(1)
	}

	if *logKeyOut != "" {
		_, logKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			fmt.Fprintln(os.Stderr, "log key:", err)
			os.Exit(1)
		}
		if err := os.WriteFile(*logKeyOut, []byte(hex.EncodeToString(logKey)+"\n"), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "log key:", err)
			os.Exit(1)
		}
		out.LogKeyFile = *logKeyOut
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, "encode:", err)
		os.Exit(1)
	}
}

// Output is everything a demo operator needs to drive mcp-pep in one paste.
type Output struct {
	TTSPublicKey string          `json:"tts_pub"`
	Token        string          `json:"token"`
	IntentDigest string          `json:"intent_digest"`
	ToolsCall    json.RawMessage `json:"tools_call"`
	LogKeyFile   string          `json:"log_key_file,omitempty"`
	Note         string          `json:"note"`
}

func mint(tool, argsJSON, target, audience, amount, currency string, ceiling int, allowUnpriced bool) (*Output, error) {
	if !json.Valid([]byte(argsJSON)) {
		return nil, fmt.Errorf("-args is not valid JSON")
	}
	var probe map[string]any
	dec := json.NewDecoder(strings.NewReader(argsJSON))
	dec.UseNumber() // keep 3000 and "3000" distinguishable and lossless
	if err := dec.Decode(&probe); err != nil {
		return nil, fmt.Errorf("-args must be a JSON object: %w", err)
	}
	if err := reconcile(probe, amount, currency, allowUnpriced); err != nil {
		return nil, err
	}

	ctPub, ctPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("ct issuer key: %w", err)
	}
	ttsPub, ttsPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tts issuer key: %w", err)
	}
	agentPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("agent key: %w", err)
	}
	subPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("sub-agent key: %w", err)
	}

	const issuer = "did:web:demo.invalid"

	// The ceiling carries its currency: a monetary bound with no unit beside it
	// bounds the amount in every currency at once, and tbac refuses to seal one.
	cat, err := cattoken.Issue(cattoken.IssueRequest{
		Issuer: issuer, Subject: "workload:demo", PrincipalName: "demo",
		Scope: cattoken.CapabilityScope{
			"action": "payment", "max_amount": ceiling, "currency": currency,
		},
		DelegationDepthMax: 3, TTL: 4 * time.Minute, HolderPublicKey: agentPub,
	}, ctPriv)
	if err != nil {
		return nil, fmt.Errorf("issue CAT: %w", err)
	}

	ctA, err := cttoken.Issue(cttoken.IssueRequest{
		Issuer: issuer, ParentCAT: cat.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": ceiling * 4 / 5, "currency": currency},
		HolderPublicKey: agentPub,
	}, ctPriv)
	if err != nil {
		return nil, fmt.Errorf("issue CT_A: %w", err)
	}
	ctB, err := cttoken.Delegate(cttoken.DelegateRequest{
		Issuer: issuer, ParentCT: ctA.Token, ParentIssuerKey: ctPub,
		RequestedScope:  tbac.Scope{"max_amount": ceiling / 2, "currency": currency},
		HolderPublicKey: subPub,
	}, ctPriv)
	if err != nil {
		return nil, fmt.Errorf("delegate CT_B: %w", err)
	}

	declared := intent.Intent{
		Tool:   tool,
		Params: json.RawMessage(argsJSON),
		Target: target,
	}
	digest, err := declared.Digest()
	if err != nil {
		return nil, fmt.Errorf("intent digest: %w", err)
	}

	l, err := ledger.Get("none")
	if err != nil {
		return nil, fmt.Errorf("ledger adapter: %w", err)
	}
	txn, err := txntoken.Issue(txntoken.IssueRequest{
		Issuer: issuer, Audience: audience, ParentCT: ctB.Token, ParentIssuerKey: ctPub,
		HolderPublicKey: subPub, Ledger: l,
		Txn: ledger.TxnContext{
			Chain: "none", Originator: "demo:originator", Beneficiary: "demo:beneficiary",
			Amount: amount, Currency: currency, Timestamp: time.Now().Unix(),
		},
		IntentDigest: digest,
	}, ttsPriv)
	if err != nil {
		return nil, fmt.Errorf("issue SPT-Txn token: %w", err)
	}

	call, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call",
		"params": map[string]any{
			"name":      tool,
			"arguments": json.RawMessage(argsJSON),
			"_meta":     map[string]any{"spt-txn/token": txn.Token},
		},
	})
	if err != nil {
		return nil, fmt.Errorf("render tools/call: %w", err)
	}

	return &Output{
		TTSPublicKey: hex.EncodeToString(ttsPub),
		Token:        txn.Token,
		IntentDigest: digest,
		ToolsCall:    call,
		Note: "Demo keys, generated for this run and discarded. The token is bound to this exact " +
			"tool, these exact arguments and this target; changing any byte of the arguments is " +
			"the prompt-injection case and must be refused.",
	}, nil
}

// reconcile refuses to mint a token whose CEILING and whose INTENT describe
// different payments.
//
// The token carries two independent statements about money:
//
//   - TxnContext.Amount, which the CAT -> CT ceiling chain constrains at
//     issuance and which nothing downstream ever executes;
//   - the tool arguments, which ARE what executes, bound byte-exact by the
//     intent digest and enforced at the PEP (internal/decision, "intent
//     binding: the actual call must match the declared action").
//
// Both are bound. Neither was checked against the other. So `-amount 3000`
// with `-args '{"amount":"99999999"}'` minted cleanly: the delegation chain
// bounded 3000, the PEP faithfully enforced that the call was exactly the one
// declared, and 99999999 is what reached the wrapped server. Every individual
// control worked; the ceiling simply bounded a number with no causal relation
// to the action.
//
// A capability that constrains a value nothing acts on is decoration. This is
// the join.
func reconcile(args map[string]any, amount, currency string, allowUnpriced bool) error {
	raw, priced := args["amount"]
	if !priced {
		if allowUnpriced {
			return nil
		}
		return fmt.Errorf("-args declares no \"amount\", so the ceiling would bound a value " +
			"the tool never sees. Add an amount to -args, or pass -allow-unpriced if this " +
			"tool genuinely moves no money")
	}
	got, ok := scalarString(raw)
	if !ok {
		return fmt.Errorf("-args \"amount\" is %T; it must be a JSON string or number", raw)
	}
	if got != amount {
		return fmt.Errorf("-args says amount %q but -amount says %q. The ceiling constrains "+
			"-amount; the tool executes -args. They must be the same payment", got, amount)
	}
	if cur, ok := args["currency"]; ok {
		gotCur, ok := scalarString(cur)
		if !ok {
			return fmt.Errorf("-args \"currency\" is %T; it must be a JSON string", cur)
		}
		if gotCur != currency {
			return fmt.Errorf("-args says currency %q but -currency says %q. A ceiling in one "+
				"currency does not bound a payment in another", gotCur, currency)
		}
	}
	return nil
}

// scalarString renders a JSON string or number as the literal it was written
// as. json.Number preserves the source text, so "3000" and 3000 both yield
// "3000" while 3000.0 stays distinct -- the same strictness ledger.ParseAmount
// applies, rather than a float round-trip that would make 3000.0000001 equal.
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case json.Number:
		return t.String(), true
	}
	return "", false
}
