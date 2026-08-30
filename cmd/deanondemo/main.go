// Command deanondemo demonstrates SPT-Txn accountable anonymity (P3): the real
// human identity behind a transaction is sealed at issuance into a PQ-hybrid
// escrow envelope, never appears on-chain, and is recoverable ONLY by the escrow
// authority under a signed, lawful-basis request. Pseudonymous by default,
// recoverable under due process.
//
// It is self-contained (no network) and exercises the exact escrow +
// deanonymization engine that cmd/deanonsvc serves over a Unix socket:
//
//  1. an escrow authority holds a hybrid X25519+ML-KEM-768 key
//
//  2. the x402 gate provisions an agent -> a humanAnchor (a ZK commitment)
//
//  3. the issuer seals the real identity, keyed by that anchor (no PII on-chain)
//
//  4. a LAWFUL request (authorized signer + stated basis) recovers the identity
//
//  5. requests without a lawful basis, or from an unknown authority, are REFUSED
//
//     go run ./cmd/deanondemo
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/rudizee007/spt-txn-poc/internal/escrow"
	"github.com/rudizee007/spt-txn-poc/internal/gate"
)

func main() {
	line := "──────────────────────────────────────────────────────────────"
	fmt.Println("SPT-Txn accountable anonymity — seal at issuance, recover only under lawful process")
	fmt.Println(line)

	// (1) The escrow authority's key. In production this is threshold / offline
	// custody; here it is one hybrid keypair.
	esk, err := escrow.NewEscrowKey()
	if err != nil {
		log.Fatalf("escrow key: %v", err)
	}

	// (2) The x402 gate provisions the agent; the humanAnchor is a zero-knowledge
	// commitment to the accountable person — this is what goes on-ledger.
	g, err := gate.New("xrpl", "rPdvC6ccq8hCdPKSPJkPmyZ4Mi1oG2FFkT", "5000", "XRP")
	if err != nil {
		log.Fatalf("gate: %v", err)
	}
	anchor := g.Anchor()
	identity := "Alice Q. Public · passport ZA-X1234567 · DOB 1990-04-12"

	// (3) The issuer seals the real identity, keyed by the anchor, encrypted to
	// the escrow authority. Stored in the vault (deanonsvc /escrow/store in prod).
	env, err := g.SealIdentity(esk.PublicKey(), identity)
	if err != nil {
		log.Fatalf("seal identity: %v", err)
	}
	vault := escrow.NewVault()
	if err := vault.Store(env); err != nil {
		log.Fatalf("store envelope: %v", err)
	}
	fmt.Printf("  humanAnchor (on-chain)   : %s\n", anchor)
	fmt.Printf("  identity (sealed, PQ-hyb): [%d-byte ML-KEM-768 hybrid envelope, no PII on the wire]\n", len(env.KemCiphertext))
	fmt.Println()

	// The deanonymization authority: holds the escrow key, authorizes escrow_req
	// signers (in production these come from the Trust Registry's escrow_req role).
	handler := escrow.NewHandler(vault, esk)
	authPub, authPriv, _ := ed25519.GenerateKey(rand.Reader)
	handler.AddSigner("authority-x.gov", authPub)

	// (4) LAWFUL request: authorized signer + stated basis -> recovers identity.
	lawful := &escrow.Request{
		HumanAnchor: anchor, Requester: "authority-x.gov",
		LawfulBasis: "warrant 2026-0042 (Cayman Islands Grand Court)", IssuedAt: time.Now().Unix(),
	}
	lawful.Sign(authPriv)
	recovered, err := handler.Deanonymize(lawful)
	if err != nil {
		log.Fatalf("lawful deanonymization should succeed: %v", err)
	}
	fmt.Printf("  ✔ LAWFUL RECOVERY (authority-x.gov, warrant 2026-0042):\n      %s\n\n", recovered)

	// (5a) No lawful basis -> refused.
	noBasis := &escrow.Request{HumanAnchor: anchor, Requester: "authority-x.gov", LawfulBasis: "", IssuedAt: time.Now().Unix()}
	noBasis.Sign(authPriv)
	_, err = handler.Deanonymize(noBasis)
	fmt.Printf("  ✔ REFUSED — request with no lawful basis: %s (ErrNoLawfulBasis=%v)\n", err, errors.Is(err, escrow.ErrNoLawfulBasis))

	// (5b) Unknown / unauthorized requester -> refused.
	_, strangerPriv, _ := ed25519.GenerateKey(rand.Reader)
	unauth := &escrow.Request{HumanAnchor: anchor, Requester: "rogue-actor", LawfulBasis: "n/a", IssuedAt: time.Now().Unix()}
	unauth.Sign(strangerPriv)
	_, err = handler.Deanonymize(unauth)
	fmt.Printf("  ✔ REFUSED — unauthorized requester: %s (ErrUnauthorized=%v)\n", err, errors.Is(err, escrow.ErrUnauthorized))

	fmt.Println(line)
	fmt.Println("  Pseudonymous on-chain; identity recoverable only by the escrow authority under due process.")
}
