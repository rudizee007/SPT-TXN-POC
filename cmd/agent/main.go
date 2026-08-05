// Command agent is the autonomous payer in the agentic-x402 demo (P1). It runs
// the full loop:
//
//  1. GET the merchant's metered resource  -> 402 Payment Required (+ requirements)
//  2. ask the gate (gatesvc) to AUTHORIZE that payment
//     3a. gate DENY  -> the agent refuses; nothing is signed (this is a valid, safe outcome)
//     3b. gate ALLOW -> settle on XRPL via clients/xrpl-pay (P0), stamping the humanAnchor
//  4. retry GET resource?proof=<txhash>  -> 200 + content
//
// The agent holds NO authority of its own: it can only spend what the gate
// authorizes, and the gate enforces the human-delegated scope cryptographically.
// This is the deterministic agent; a later step swaps in an LLM decision loop
// in front of the same gate (the gate is agent-agnostic).
//
//	# terminals: gatesvc and merchantsvc running; xrpl-pay built; SPT_XRPL_SEED set
//	go run ./cmd/agent -pay-bin ../clients/xrpl-pay/xrpl-pay
//	go run ./cmd/agent -dry-pay        # run the loop but print the pay command instead of settling
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"
)

type requirement struct {
	Price     string `json:"price"`
	Currency  string `json:"currency"`
	PayTo     string `json:"payto"`
	SourceTag string `json:"sourcetag"`
	Network   string `json:"network"`
}

type decision struct {
	Allow       bool   `json:"allow"`
	Reason      string `json:"reason"`
	StepName    string `json:"step_name"`
	Destination string `json:"destination"`
	Amount      string `json:"amount"`
	Currency    string `json:"currency"`
	SourceTag   string `json:"source_tag"`
	Memo        string `json:"memo"`
	ContextHash string `json:"context_hash"`
}

func main() {
	merchant := flag.String("merchant", "http://127.0.0.1:8402/resource", "merchant resource URL")
	gateURL := flag.String("gate", "http://127.0.0.1:8401/gate/authorize", "gate authorize URL")
	payBin := flag.String("pay-bin", "", "path to the built xrpl-pay binary (required unless -dry-pay)")
	payEndpoint := flag.String("pay-endpoint", "", "override xrpl-pay endpoint (default: xrpl-pay's testnet)")
	dryPay := flag.Bool("dry-pay", false, "run the loop but print the pay command instead of settling")
	flag.Parse()

	log.SetPrefix("agent: ")
	client := &http.Client{Timeout: 30 * time.Second}

	// 1. Hit the metered resource -> expect 402 with requirements.
	req, err := fetchRequirement(client, *merchant)
	if err != nil {
		log.Fatalf("merchant: %v", err)
	}
	log.Printf("merchant requires: pay %s %s to %s (SourceTag %s) on %s",
		req.Price, req.Currency, req.PayTo, req.SourceTag, req.Network)

	// 2. Ask the gate whether this payment is authorized. Keep the raw decision:
	// it is the verification bundle the merchant will re-check (P2).
	d, bundle, err := authorize(client, *gateURL, req)
	if err != nil {
		log.Fatalf("gate: %v", err)
	}

	// 3a. DENY -> refuse. This is a first-class, safe outcome.
	if !d.Allow {
		log.Printf("GATE DENY (%s): %s", d.StepName, d.Reason)
		log.Printf("agent refuses to pay — nothing signed.")
		return
	}
	log.Printf("GATE ALLOW — settling %s %s to %s, humanAnchor %s", d.Amount, d.Currency, d.Destination, d.Memo)

	// 3b. Settle on the ledger via the pay backend (unless -dry-pay).
	if *dryPay {
		fmt.Printf("\n[dry-pay] would settle on %s:\n  -to %s -amount %s -currency %s -memo %s\n",
			req.Network, d.Destination, d.Amount, d.Currency, d.Memo)
		return
	}
	if *payBin == "" {
		log.Fatal("-pay-bin is required (path to the pay backend binary), or use -dry-pay")
	}
	txHash, err := settle(*payBin, *payEndpoint, d)
	if err != nil {
		log.Fatalf("settle: %v", err)
	}
	log.Printf("settled on %s: tx %s", req.Network, txHash)

	// 4. Redeem: hand the merchant the tx hash + the verification bundle. The
	// merchant re-runs the eight-step verifier before delivering (P2).
	content, err := redeem(client, *merchant, txHash, bundle)
	if err != nil {
		log.Fatalf("redeem: %v", err)
	}
	log.Printf("resource delivered (merchant verified attestation): %s", content)
}

func fetchRequirement(c *http.Client, merchant string) (requirement, error) {
	resp, err := c.Get(merchant)
	if err != nil {
		return requirement{}, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusPaymentRequired {
		return requirement{}, fmt.Errorf("expected 402, got %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var req requirement
	if err := json.Unmarshal(body, &req); err != nil {
		return requirement{}, fmt.Errorf("parse 402 body: %w", err)
	}
	return req, nil
}

// authorize returns the decoded decision (for the settle fields) and the raw
// response bytes (the verification bundle, relayed verbatim to the merchant).
func authorize(c *http.Client, gateURL string, req requirement) (decision, []byte, error) {
	payload, _ := json.Marshal(map[string]string{
		"price": req.Price, "currency": req.Currency, "payto": req.PayTo, "sourcetag": req.SourceTag,
	})
	resp, err := c.Post(gateURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		return decision{}, nil, err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var d decision
	if err := json.Unmarshal(raw, &d); err != nil {
		return decision{}, nil, fmt.Errorf("parse decision: %w", err)
	}
	return d, raw, nil
}

// settle execs xrpl-pay (-json) and returns the tx hash. xrpl-pay reads the
// payer seed from $SPT_XRPL_SEED in the inherited environment.
func settle(payBin, endpoint string, d decision) (string, error) {
	args := []string{
		"-to", d.Destination, "-amount", d.Amount, "-currency", d.Currency,
		"-sourcetag", d.SourceTag, "-memo", d.Memo, "-context-hash", d.ContextHash, "-json",
	}
	if endpoint != "" {
		args = append(args, "-endpoint", endpoint)
	}
	cmd := exec.Command(payBin, args...)
	cmd.Stderr = os.Stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("pay backend: %w", err)
	}
	var res struct {
		TxHash   string `json:"tx_hash"`
		Explorer string `json:"explorer"`
	}
	if err := json.Unmarshal(bytes.TrimSpace(out), &res); err != nil {
		return "", fmt.Errorf("parse xrpl-pay output %q: %w", string(out), err)
	}
	if res.Explorer != "" {
		log.Printf("explorer: %s", res.Explorer)
	}
	return res.TxHash, nil
}

// redeem posts the tx hash + the verification bundle to the merchant's redeem
// endpoint. The merchant re-runs the eight-step verifier before delivering.
func redeem(c *http.Client, merchant, txHash string, bundle []byte) (string, error) {
	payload, _ := json.Marshal(struct {
		TxHash string          `json:"tx_hash"`
		Bundle json.RawMessage `json:"bundle"`
	}{TxHash: txHash, Bundle: bundle})
	resp, err := c.Post(merchant+"/redeem", "application/json", bytes.NewReader(payload))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("merchant refused (%d): %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return strings.TrimSpace(string(body)), nil
}
