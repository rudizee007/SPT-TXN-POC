// cmd/tr-svc — live SPT-Txn Travel Rule service (privacy-preserving FATF Rec 16).
//
// Demonstrates the full flow end to end:
//   POST /travel/attest  — originator VASP builds a Travel Rule attestation for
//                          a transfer (IVMS101 as a selectively-disclosable
//                          SD-JWT + ZK proofs: identity commitment, amount >=
//                          threshold, beneficiary-VASP registration), bound to
//                          the SPT-Txn payment.
//   POST /travel/verify  — beneficiary VASP verifies the attestation and returns
//                          only the IVMS101 fields it is entitled to see.
//   GET  /travel/health
//
// Loads the persisted ZK keys (cmd/zk-setup) so the trusted setup is shared, not
// redone. For the POC this single process plays both roles; the SD-JWT signer is
// an ephemeral key generated at startup. Listens on 127.0.0.1 for relayd.
//
// Env: SPT_TRSVC_ADDR (default 127.0.0.1:8085), SPT_ZK_DIR (default /var/spt-txn/zk)
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/ivms101"
	"github.com/violetskysecurity/spt-txn-poc/internal/travelrule"
	"github.com/violetskysecurity/spt-txn-poc/internal/trp"
	"github.com/violetskysecurity/spt-txn-poc/internal/vaspregistry"
	"github.com/violetskysecurity/spt-txn-poc/internal/zkproof"
)

const beneficiaryVASP = "vasp:beneficiary-bank"

func main() {
	// Flags override env so a single binary can be driven by rc(8) daemon_flags
	// (one service per role) or by env in dev.
	flagRole := flag.String("role", "", "originator|beneficiary|both (overrides SPT_TR_ROLE)")
	flagAddr := flag.String("addr", "", "listen address (overrides SPT_TRSVC_ADDR)")
	flag.Parse()

	addr := envOr("SPT_TRSVC_ADDR", "127.0.0.1:8085")
	if *flagAddr != "" {
		addr = *flagAddr
	}
	zkDir := envOr("SPT_ZK_DIR", "/var/spt-txn/zk")
	role := envOr("SPT_TR_ROLE", "both") // originator | beneficiary | both
	if *flagRole != "" {
		role = *flagRole
	}
	sdKeyPath := envOr("SPT_TR_SDKEY", "/var/spt-txn/tr/sdjwt.key")
	sdPubPath := envOr("SPT_TR_SDPUB", "/var/spt-txn/tr/sdjwt.pub")

	log.SetPrefix("tr-svc[" + role + "]: ")
	log.SetFlags(log.Ltime | log.Lmicroseconds)

	doAttest := role == "originator" || role == "both"
	doVerify := role == "beneficiary" || role == "both"
	if !doAttest && !doVerify {
		log.Fatalf("unknown SPT_TR_ROLE %q (want originator|beneficiary|both)", role)
	}

	// The originator proves (needs the full proving keys); the beneficiary only
	// verifies (needs the vk). Both share the same registry config — hence the
	// same Merkle root — and the originator's published SD-JWT public key.
	commit, threshold, vaspArt := loadCircuits(zkDir, !doAttest)
	log.Printf("loaded ZK keys from %s (verifier-only=%v)", zkDir, !doAttest)

	registry, err := loadRegistry()
	if err != nil {
		log.Fatalf("build VASP registry: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/travel/health", handleHealth)

	if doAttest {
		_, sdPriv, err := loadOrGenSDKey(sdKeyPath, sdPubPath)
		if err != nil {
			log.Fatalf("SD-JWT key: %v", err)
		}
		issuer := &travelrule.Issuer{
			Name: "did:web:authorg", Signer: sdPriv,
			Commit: commit, Threshold: threshold, VASP: vaspArt, Registry: registry,
		}
		mux.HandleFunc("/travel/attest", handleAttest(issuer))
		// Outbound TRP: build the attestation and send it to a beneficiary VASP
		// over the inter-VASP Travel Rule Protocol (a real network hop).
		mux.HandleFunc("/trp/originate", handleOriginate(issuer, trp.NewClient(nil)))
		log.Printf("originator role: /travel/attest, /trp/originate enabled")
	}
	if doVerify {
		// On a fresh boot the originator service may not have published its
		// SD-JWT public key yet; wait briefly rather than failing the race.
		sdPub, err := loadSDPubWait(sdPubPath, 30*time.Second)
		if err != nil {
			log.Fatalf("SD-JWT public key (the originator must publish it first): %v", err)
		}
		verifier := &travelrule.Verifier{
			IssuerPub: sdPub, Commit: commit, Threshold: threshold, VASP: vaspArt,
			KnownRoot: registry.Root(),
		}
		mux.HandleFunc("/travel/verify", handleVerify(verifier))
		// Inbound TRP: accept transfers from originator VASPs. This VASP requires
		// the SPT-Txn payload-level attestation (no cleartext-only transfers).
		//
		// expectedHash MUST be non-nil (the Handler fails closed otherwise,
		// TR-3). In production this derives the txn-context hash from the
		// on-chain transaction the beneficiary independently observes. For the
		// POC single process we have no separate chain observer, so we derive it
		// from the request's ledger transaction context via the shared
		// ledger.ContextHash canonicalization — NOT by echoing the request's
		// self-asserted hash. If the observed context cannot be canonicalized,
		// we return an empty string, which the binding check will reject.
		mux.Handle("/trp/transfer", trp.Handler(verifier.Verify, observedTxnContextHash))
		log.Printf("beneficiary role: /travel/verify, /trp/transfer enabled")
	}

	srv := &http.Server{
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 30 * time.Second, // proving can take a couple seconds
		IdleTimeout:  30 * time.Second,
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen %s: %v", addr, err)
	}
	log.Printf("listening on %s", addr)

	// ── unveil + pledge (keys loaded, listener bound) ──────────────────
	// Confine the filesystem to only the ZK key directory (already loaded into
	// memory), then restrict the syscall set. Serving touches no files. The
	// originator additionally dials outbound TRP, so it gets the "dns" promise
	// and read access to the resolver files; the beneficiary never dials out.
	promises := "stdio rpath inet"
	unveil(zkDir, "r")
	if doAttest {
		promises += " dns"
		unveil("/etc/resolv.conf", "r")
		unveil("/etc/hosts", "r")
	}
	unveilLock()
	if err := pledge(promises); err != nil {
		log.Fatalf("pledge: %v", err)
	}

	done := make(chan struct{})
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
		<-sig
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		close(done)
	}()

	log.Printf("ready")
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("serve: %v", err)
	}
	<-done
}

// ── handlers ─────────────────────────────────────────────────────────────────

func handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]string{"status": "ok", "service": "tr-svc"})
}

type partyJSON struct {
	NamePrimary    string `json:"name_primary"`     // surname / family name
	NameSecondary  string `json:"name_secondary"`   // given names
	Country        string `json:"country"`          // country of residence
	Account        string `json:"account"`          // account / wallet identifier
	NationalID     string `json:"national_id"`      // FATF identifier value (passport / national-ID / etc.)
	NationalIDType string `json:"national_id_type"` // IVMS101 type: NIDN, CCPT, DRLC, TXID, LEIX (default NIDN)
}

// natIDOf builds an IVMS101 national identification when an identifier value is
// supplied. FATF Recommendation 16 requires the ORIGINATOR to carry one of
// address / national-ID / DOB; a national-ID is the strongest, most portable
// form, so the demo populates it rather than leaning on country alone.
func natIDOf(p partyJSON) *ivms101.NationalIdentification {
	if p.NationalID == "" {
		return nil
	}
	t := ivms101.NationalIdentifierType(p.NationalIDType)
	if t == "" {
		t = ivms101.IDNational
	}
	return &ivms101.NationalIdentification{
		NationalIdentifier:     p.NationalID,
		NationalIdentifierType: t,
		CountryOfIssue:         p.Country,
	}
}

// defaultDiscloseFATF is the FATF Rec-16 minimum data set expressed as SD-JWT
// disclosure keys — the originator's full name, account/wallet and identifier,
// plus the beneficiary's name and account. Used when an /trp/originate request
// does not specify its own disclosure set, so the live demo conveys a
// FATF-complete set to the counterparty rather than a single field. Keys absent
// from a given attestation are simply not disclosed (sdjwt.Present skips them).
var defaultDiscloseFATF = []string{
	"originator.name.primary", "originator.name.secondary", "originator.account",
	"originator.natId.id", "originator.natId.type", "originator.natId.country", "originator.country",
	"beneficiary.name.primary", "beneficiary.name.secondary", "beneficiary.account",
}

type attestReq struct {
	Originator      partyJSON `json:"originator"`
	Beneficiary     partyJSON `json:"beneficiary"`
	Amount          uint64    `json:"amount"`
	Currency        string    `json:"currency"`
	BeneficiaryVASP string    `json:"beneficiary_vasp"`
	TxnContextHash  string    `json:"txn_context_hash"`
	OriginatorID    string    `json:"originator_id"`   // secret identity material
	OriginatorRand  string    `json:"originator_rand"` // secret anchor randomness
	AmountBlinding  string    `json:"amount_blinding"` // secret amount blinding
}

func handleAttest(iss *travelrule.Issuer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var req attestReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		transfer, secrets := buildTransfer(&req)
		att, err := iss.Build(transfer, secrets, req.TxnContextHash, time.Hour)
		if err != nil {
			jsonError(w, "attest failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, att)
	}
}

// buildTransfer maps the request DTO into the travelrule transfer + secrets,
// applying the default beneficiary VASP. Shared by /travel/attest and
// /trp/originate.
func buildTransfer(req *attestReq) (travelrule.Transfer, travelrule.Secrets) {
	if req.BeneficiaryVASP == "" {
		req.BeneficiaryVASP = beneficiaryVASP
	}
	transfer := travelrule.Transfer{
		Identity: ivms101.IdentityPayload{
			Originator: ivms101.Originator{
				OriginatorPersons: []ivms101.Person{ivms101.PersonOf(req.Originator.NamePrimary, req.Originator.NameSecondary, req.Originator.Country, natIDOf(req.Originator))},
				AccountNumber:     []string{req.Originator.Account},
			},
			Beneficiary: ivms101.Beneficiary{
				BeneficiaryPersons: []ivms101.Person{ivms101.PersonOf(req.Beneficiary.NamePrimary, req.Beneficiary.NameSecondary, req.Beneficiary.Country, natIDOf(req.Beneficiary))},
				AccountNumber:      []string{req.Beneficiary.Account},
			},
		},
		Amount: req.Amount, Currency: req.Currency,
	}
	secrets := travelrule.Secrets{
		OriginatorID:      []byte(req.OriginatorID),
		OriginatorRand:    []byte(req.OriginatorRand),
		AmountBlinding:    []byte(req.AmountBlinding),
		BeneficiaryVASPID: []byte(req.BeneficiaryVASP),
	}
	return transfer, secrets
}

// originateReq is an /trp/originate body: the same transfer fields plus the
// beneficiary's Travel Address and the disclosure set to request.
type originateReq struct {
	attestReq
	TravelAddress string   `json:"travel_address"`
	Disclose      []string `json:"disclose"`
	Asset         string   `json:"asset"`
}

// handleOriginate builds the Travel Rule attestation and sends it to a
// beneficiary VASP over TRP — the real inter-VASP hop. It returns the
// beneficiary's approve/reject response.
func handleOriginate(iss *travelrule.Issuer, client *trp.Client) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var req originateReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		transfer, secrets := buildTransfer(&req.attestReq)
		att, err := iss.Build(transfer, secrets, req.TxnContextHash, time.Hour)
		if err != nil {
			jsonError(w, "attest failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Default to the FATF Rec-16 minimum disclosure set when the caller does
		// not request a specific one, so the counterparty receives the required
		// fields (name + account + identifier) rather than a single attribute.
		if len(req.Disclose) == 0 {
			req.Disclose = defaultDiscloseFATF
		}
		treq := &trp.TransferRequest{
			Asset:  trp.Asset{Symbol: req.Asset},
			Amount: strconv.FormatUint(req.Amount, 10),
			Extensions: trp.Extensions{SPTTxn: &trp.SPTTxn{
				Version:        trp.ExtensionVersion,
				Attestation:    *att,
				TxnContextHash: req.TxnContextHash,
				Disclose:       req.Disclose,
			}},
		}
		resp, status, err := client.Send(r.Context(), req.TravelAddress, treq)
		if err != nil {
			jsonError(w, "trp send: "+err.Error(), http.StatusBadGateway)
			return
		}
		writeJSON(w, map[string]any{"trp_status": status, "response": resp})
	}
}

type verifyReq struct {
	Attestation     travelrule.Attestation `json:"attestation"`
	ExpectedTxnHash string                 `json:"expected_txn_context_hash"`
	Disclose        []string               `json:"disclose"`
}

func handleVerify(ver *travelrule.Verifier) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		var req verifyReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			jsonError(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		disclosed, err := ver.Verify(&req.Attestation, req.ExpectedTxnHash, req.Disclose)
		if err != nil {
			writeJSON(w, map[string]any{"verified": false, "reason": err.Error()})
			return
		}
		writeJSON(w, map[string]any{"verified": true, "disclosed": disclosed})
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

// loadRegistry loads the registered-VASP set from the config file
// (SPT_VASP_REGISTRY, default /var/spt-txn/vasp-registry.json); if the file is
// unavailable it falls back to a built-in demo set so the service still runs.
func loadRegistry() (*zkproof.MerkleTree, error) {
	path := envOr("SPT_VASP_REGISTRY", "/var/spt-txn/vasp-registry.json")
	if reg, err := vaspregistry.Load(path); err == nil {
		log.Printf("loaded VASP registry from %s (%d members)", path, reg.Count())
		return reg.Tree(), nil
	} else {
		log.Printf("VASP registry %s unavailable (%v); using built-in demo set", path, err)
	}
	reg, err := vaspregistry.FromMembers(demoMembers())
	if err != nil {
		return nil, err
	}
	return reg.Tree(), nil
}

func demoMembers() []string {
	m := make([]string, 0, 8)
	for i := 0; i < 7; i++ {
		m = append(m, fmt.Sprintf("vasp:member:%d", i))
	}
	return append(m, beneficiaryVASP)
}

// loadCircuits loads the three circuits' artifacts — full (for the prover) or
// verifier-only (vk, for the beneficiary) — from the shared persisted keys.
func loadCircuits(zkDir string, verifierOnly bool) (commit, threshold, vasp *zkproof.Artifacts) {
	load := zkproof.Load
	if verifierOnly {
		load = zkproof.LoadVerifier
	}
	var err error
	if commit, err = load(zkproof.CircuitCommitment, zkDir); err != nil {
		log.Fatalf("load commitment keys (run zk-setup?): %v", err)
	}
	if threshold, err = load(zkproof.CircuitThreshold, zkDir); err != nil {
		log.Fatalf("load threshold keys: %v", err)
	}
	if vasp, err = load(zkproof.CircuitVASP, zkDir); err != nil {
		log.Fatalf("load vasp keys: %v", err)
	}
	return
}

// loadOrGenSDKey loads the originator's SD-JWT signing key (hex Ed25519 private
// key) from privPath, generating and persisting a fresh keypair if absent. It
// always (re)writes the public key to pubPath so the beneficiary can verify
// attestations the originator signs.
func loadOrGenSDKey(privPath, pubPath string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	if data, err := os.ReadFile(privPath); err == nil {
		if raw, derr := hex.DecodeString(strings.TrimSpace(string(data))); derr == nil && len(raw) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(raw)
			pub := priv.Public().(ed25519.PublicKey)
			_ = os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0o644)
			return pub, priv, nil
		}
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(privPath, []byte(hex.EncodeToString(priv)), 0o600); err != nil {
		return nil, nil, fmt.Errorf("write SD-JWT key %s: %w", privPath, err)
	}
	if err := os.WriteFile(pubPath, []byte(hex.EncodeToString(pub)), 0o644); err != nil {
		return nil, nil, fmt.Errorf("write SD-JWT pub %s: %w", pubPath, err)
	}
	log.Printf("generated SD-JWT key at %s (pub published to %s)", privPath, pubPath)
	return pub, priv, nil
}

// loadSDPubWait polls loadSDPub until the key is available or timeout elapses,
// tolerating the boot-order race where the beneficiary service starts before the
// originator has published its public key.
func loadSDPubWait(pubPath string, timeout time.Duration) (ed25519.PublicKey, error) {
	deadline := time.Now().Add(timeout)
	for {
		pub, err := loadSDPub(pubPath)
		if err == nil {
			return pub, nil
		}
		if time.Now().After(deadline) {
			return nil, err
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// loadSDPub reads the originator's published SD-JWT public key (hex Ed25519) so
// the beneficiary can verify attestation signatures.
func loadSDPub(pubPath string) (ed25519.PublicKey, error) {
	data, err := os.ReadFile(pubPath)
	if err != nil {
		return nil, err
	}
	raw, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(raw) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid SD-JWT public key in %s", pubPath)
	}
	return ed25519.PublicKey(raw), nil
}

// observedTxnContextHash supplies the beneficiary's INDEPENDENT view of the
// transaction-context hash for an inbound TRP transfer (TR-3). It deliberately
// does NOT read ext.TxnContextHash back from the request — trusting the
// request's own assertion would make the payment binding vacuous (fail-open).
//
// In production this is derived from the on-chain transaction the beneficiary
// observes itself (ledger.ContextHash over the locally reconstructed
// TxnContext). For the POC single process there is no separate chain observer,
// so the expected hash is configured out of band via SPT_TR_EXPECTED_TXN_HASH.
// If that is unset we return "", which fails the binding check closed rather
// than admitting an unverified transfer.
func observedTxnContextHash(_ *trp.TransferRequest) string {
	return os.Getenv("SPT_TR_EXPECTED_TXN_HASH")
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

func jsonError(w http.ResponseWriter, msg string, code int) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
