package conformance

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rudizee007/spt-txn-poc/internal/intent"
	"github.com/rudizee007/spt-txn-poc/internal/statuslist"
	"github.com/rudizee007/spt-txn-poc/internal/suite"
	"github.com/rudizee007/spt-txn-poc/pkg/receipt"
)

func vectorPath(name string) string {
	return filepath.Join("..", "..", "docs", "conformance", name)
}

func readVectors(t *testing.T, name string, dst any) {
	t.Helper()
	raw, err := os.ReadFile(vectorPath(name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		t.Fatalf("decode %s: %v", name, err)
	}
}

// Intent digests: the Go implementation must reproduce the independently
// computed digest for each {tool, params, target}. This is the critical
// canonicalization surface (docs/THREAT-MODEL.md §4.1).
func TestConformance_IntentDigests(t *testing.T) {
	var doc struct {
		Vectors []struct {
			Tool         string          `json:"tool"`
			Params       json.RawMessage `json:"params"`
			Target       string          `json:"target"`
			IntentDigest string          `json:"intent_digest"`
		} `json:"vectors"`
	}
	readVectors(t, "intent-digests.json", &doc)
	if len(doc.Vectors) == 0 {
		t.Fatal("no intent vectors")
	}
	for i, v := range doc.Vectors {
		got, err := intent.Intent{Tool: v.Tool, Params: v.Params, Target: v.Target}.Digest()
		if err != nil {
			t.Errorf("vector %d (%s): %v", i, v.Tool, err)
			continue
		}
		if got != v.IntentDigest {
			t.Errorf("vector %d (%s): digest\n got  %s\n want %s", i, v.Tool, got, v.IntentDigest)
		}
	}
}

// Receipt signing inputs: another implementation that reproduces these exact
// bytes and signs them with the log key produces interoperable receipts.
func TestConformance_ReceiptSigningInputs(t *testing.T) {
	var doc struct {
		Vectors []struct {
			Receipt struct {
				V            string `json:"v"`
				PEP          string `json:"pep"`
				Decision     string `json:"decision"`
				Class        string `json:"class"`
				RulePath     string `json:"rule_path"`
				TokenHash    string `json:"token_hash"`
				PolicyHash   string `json:"policy_hash"`
				TS           int64  `json:"ts"`
				Nonce        string `json:"nonce"`
				IntentDigest string `json:"intent_digest"`
				Jurisdiction string `json:"jurisdiction"`
			} `json:"receipt"`
			SigningInputHex string `json:"signing_input_hex"`
		} `json:"vectors"`
	}
	readVectors(t, "receipt-signing-inputs.json", &doc)
	if len(doc.Vectors) == 0 {
		t.Fatal("no receipt vectors")
	}
	for i, v := range doc.Vectors {
		r := receipt.Receipt{
			V: v.Receipt.V, PEP: v.Receipt.PEP, Decision: v.Receipt.Decision,
			Class: v.Receipt.Class, RulePath: v.Receipt.RulePath,
			TokenHash: v.Receipt.TokenHash, PolicyHash: v.Receipt.PolicyHash,
			TS: v.Receipt.TS, Nonce: v.Receipt.Nonce,
			IntentDigest: v.Receipt.IntentDigest, Jurisdiction: v.Receipt.Jurisdiction,
		}
		si, err := r.SigningInput()
		if err != nil {
			t.Errorf("vector %d: %v", i, err)
			continue
		}
		if got := hex.EncodeToString(si); got != v.SigningInputHex {
			t.Errorf("vector %d: signing input\n got  %s\n want %s", i, got, v.SigningInputHex)
		}
	}
}

// Envelope suite signing inputs (crypto-agility): suite id is domain-separated
// and covered — an independent implementation must build the same bytes.
func TestConformance_SuiteSigningInputs(t *testing.T) {
	var doc struct {
		Vectors []struct {
			Suite           string `json:"suite"`
			PayloadHex      string `json:"payload_hex"`
			SigningInputHex string `json:"signing_input_hex"`
		} `json:"vectors"`
	}
	readVectors(t, "suite-signing-inputs.json", &doc)
	if len(doc.Vectors) == 0 {
		t.Fatal("no suite vectors")
	}
	for i, v := range doc.Vectors {
		payload, err := hex.DecodeString(v.PayloadHex)
		if err != nil {
			t.Fatalf("vector %d payload hex: %v", i, err)
		}
		got := hex.EncodeToString(suite.SigningInput(v.Suite, payload))
		if got != v.SigningInputHex {
			t.Errorf("vector %d (%s): signing input\n got  %s\n want %s", i, v.Suite, got, v.SigningInputHex)
		}
	}
}

// Status-list decode: the Go decoder must inflate an independently-produced
// zlib bit array and read the same statuses. Decode is the interop direction
// (compressed bytes are not required to be byte-identical across compressors).
func TestConformance_StatusListDecode(t *testing.T) {
	var doc struct {
		Vectors []struct {
			Bits    int    `json:"bits"`
			Entries int    `json:"entries"`
			Lst     string `json:"lst"`
			Checks  []struct {
				Idx    int `json:"idx"`
				Status int `json:"status"`
			} `json:"checks"`
		} `json:"vectors"`
	}
	readVectors(t, "status-list-decode.json", &doc)
	if len(doc.Vectors) == 0 {
		t.Fatal("no status-list vectors")
	}
	for i, v := range doc.Vectors {
		l, err := statuslist.Decode(statuslist.Encoded{Bits: v.Bits, Lst: v.Lst}, v.Entries)
		if err != nil {
			t.Errorf("vector %d (bits=%d): decode: %v", i, v.Bits, err)
			continue
		}
		for _, c := range v.Checks {
			got, err := l.Get(c.Idx)
			if err != nil {
				t.Errorf("vector %d idx %d: %v", i, c.Idx, err)
				continue
			}
			if int(got) != c.Status {
				t.Errorf("vector %d (bits=%d) idx %d: got %d want %d", i, v.Bits, c.Idx, got, c.Status)
			}
		}
	}
}
