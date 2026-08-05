// Command merchantsvc is a metered resource server that speaks x402 AND
// cryptographically verifies the SPT-Txn attestation before delivering — P2 of
// the agentic-x402 demo. This is what makes it more than vanilla x402: it does
// not trust "a payment happened", it checks that the payment was AUTHORIZED,
// in-scope, bound to THIS merchant, and signed by a known issuer.
//
// Flow:
//
//	GET  /resource            -> 402 + payment requirements (unpaid)
//	POST /resource/redeem      { "tx_hash": "...", "bundle": <gate.Decision> }
//	   1. the attestation must authorize a payment to THIS merchant for the price
//	   2. re-run the eight-step verifier on the attestation (signature, expiry,
//	      audience, revocation, DPoP, capability chain, scope, context-hash bind)
//	   3. only then deliver the resource
//
// Issuer public keys are fetched once at startup from the gate's trusted
// /gate/registry endpoint (NOT from the agent — the agent is untrusted). The
// signed token pins the issuer signature and the context hash, so a tampered
// bundle fails verification.
//
//	go run ./cmd/merchantsvc -price 1000 -payto rLNVi… -gate http://127.0.0.1:8401
package main

import (
	"context"
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/gate"
	"github.com/rudizee007/spt-txn-poc/internal/trustregistry"
	"github.com/rudizee007/spt-txn-poc/internal/verifier"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8402", "listen address")
	price := flag.String("price", "1000", "price in XRP drops")
	currency := flag.String("currency", "XRP", "currency")
	payto := flag.String("payto", "rsA2LpzuawewSBQXkiju3YQTMzW13pAAdW", "merchant XRPL pay-to address")
	sourceTag := flag.String("sourcetag", "402", "x402 SourceTag the payer should stamp")
	network := flag.String("network", "xrpl", "ledger label advertised in the 402 requirements (xrpl, hedera, …)")
	gateURL := flag.String("gate", "http://127.0.0.1:8401", "gate base URL (for the trusted issuer registry)")
	flag.Parse()

	log.SetPrefix("merchantsvc: ")

	// Fetch issuer keys from the gate (trusted channel) and build a verifier
	// registry. Retry: the gate may still be starting.
	reg, err := fetchRegistry(*gateURL)
	if err != nil {
		log.Fatalf("fetch issuer registry from %s: %v", *gateURL, err)
	}
	eng := verifier.New(reg)
	log.Printf("issuer registry loaded from %s", *gateURL)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "service": "merchantsvc"})
	})

	// Unpaid: return the payment requirements.
	mux.HandleFunc("/resource", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		log.Printf("402 — payment required for /resource")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusPaymentRequired) // 402
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": "payment required", "price": *price, "currency": *currency,
			"payto": *payto, "sourcetag": *sourceTag, "network": *network,
		})
	})

	// Redeem: verify the attestation, then deliver.
	mux.HandleFunc("/resource/redeem", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var body struct {
			TxHash string        `json:"tx_hash"`
			Bundle gate.Decision `json:"bundle"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			refuse(w, http.StatusBadRequest, "invalid redeem body")
			return
		}
		b := body.Bundle
		if b.Attestation == "" || b.Txn == nil {
			refuse(w, http.StatusBadRequest, "missing attestation or txn in bundle")
			return
		}

		// (1) The attestation must authorize a payment to THIS merchant for the
		// advertised price. This stops a valid attestation for some OTHER payment
		// from unlocking this resource.
		if b.Txn.Beneficiary != *payto || b.Txn.Amount != *price || b.Txn.Currency != *currency {
			log.Printf("REFUSE %s — attestation not bound to this payment (to=%s amt=%s cur=%s)",
				body.TxHash, b.Txn.Beneficiary, b.Txn.Amount, b.Txn.Currency)
			refuse(w, http.StatusForbidden, "attestation does not authorize a payment to this merchant for the required amount")
			return
		}

		// (2) Re-run the eight-step verifier. Step 1 (issuer signature) and step 8
		// (context-hash binding) mean a tampered bundle cannot pass, so trusting the
		// agent-relayed bundle is safe given the trusted issuer keys.
		dec := eng.Verify(context.Background(), verifier.Input{
			TxnToken: b.Attestation, DPoPProof: b.DPoP, HTM: b.HTM, HTU: b.HTU,
			CTChain: b.CTChain, CAT: b.CAT, Txn: *b.Txn, Audience: b.Audience,
		})
		if !dec.Allow {
			log.Printf("REFUSE %s — attestation failed verification at step %d (%s): %s",
				body.TxHash, dec.Step, dec.StepName, dec.Reason)
			refuse(w, http.StatusForbidden, "attestation failed verification: "+dec.Reason)
			return
		}

		log.Printf("DELIVER %s — attestation verified (authorized, in-scope, bound to this payment)", body.TxHash)
		writeJSON(w, http.StatusOK, map[string]any{
			"resource": "premium-market-data",
			"payload":  "42.0",
			"paid_by":  body.TxHash,
			"verified": true,
		})
	})

	log.Printf("listening on %s (price %s %s -> %s, SourceTag %s)", *addr, *price, *currency, *payto, *sourceTag)
	log.Fatal(http.ListenAndServe(*addr, mux))
}

// fetchRegistry loads the gate's issuer public keys and builds a verifier
// registry. Retries for a short while so it tolerates the gate still starting.
func fetchRegistry(gateURL string) (*trustregistry.MockRegistry, error) {
	client := &http.Client{Timeout: 3 * time.Second}
	var lastErr error
	for i := 0; i < 20; i++ {
		resp, err := client.Get(gateURL + "/gate/registry")
		if err != nil {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		data, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var payload struct {
			Records []*trustregistry.Record `json:"records"`
		}
		if err := json.Unmarshal(data, &payload); err != nil {
			return nil, err
		}
		reg, err := trustregistry.NewMockRegistry("")
		if err != nil {
			return nil, err
		}
		n := 0
		for _, rec := range payload.Records {
			if rec == nil {
				continue
			}
			if err := reg.Register(context.Background(), rec); err != nil {
				return nil, err
			}
			n++
		}
		if n == 0 {
			lastErr = err
			time.Sleep(time.Second)
			continue
		}
		return reg, nil
	}
	return nil, lastErr
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func refuse(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"delivered": false, "error": msg})
}
