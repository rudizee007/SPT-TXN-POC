// Package regdisclosure assembles a minimal, verifiable disclosure package for a
// competent authority (a lawful TFR/MiCA recordkeeping request) WITHOUT exposing
// more than the legal basis allows.
//
// A package contains exactly two things and nothing else:
//
//   - an SD-JWT presentation that reveals ONLY the IVMS101 fields the authority
//     is entitled to (everything else stays hidden inside the issuer-signed
//     credential), and
//   - a Merkle inclusion proof that the relevant audit entry sits under a
//     published, audit-key-signed root — proving the record existed and was not
//     altered, without handing over the rest of the log.
//
// The regulator verifies the package offline against the issuer and audit public
// keys. This is data-minimisation by construction, not by promise.
package regdisclosure

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"time"

	"github.com/violetskysecurity/spt-txn-poc/internal/audit"
	"github.com/violetskysecurity/spt-txn-poc/internal/sdjwt"
)

// Request is a competent authority's scoped ask.
type Request struct {
	Fields     []string // selectively-disclosable claim names the authority may see
	LegalBasis string   // e.g. court order / statutory reference (recorded, not validated)
	Requester  string   // the requesting authority's identifier
}

// Package is the minimal evidence handed to the authority.
type Package struct {
	Presentation string         // SD-JWT presentation revealing only Request.Fields
	Disclosed    map[string]any // the revealed claims (manifest convenience)
	Entry        audit.Entry    // the single audit entry being disclosed
	Index        int            // its position in the log
	Count        int            // entries covered by Root
	Proof        [][]byte       // Merkle inclusion path for Entry
	Root         audit.SignedRoot
	LegalBasis   string
	Requester    string
	CreatedAt    int64
}

// Build produces a disclosure package: it presents only req.Fields from the
// issued SD-JWT, sanity-checks the presentation against the issuer key, and
// attaches a Merkle inclusion proof for entries[entryIndex] under root.
func Build(combinedSDJWT string, issuerPub ed25519.PublicKey, req Request, entries []audit.Entry, entryIndex int, root audit.SignedRoot) (*Package, error) {
	if req.LegalBasis == "" || req.Requester == "" {
		return nil, errors.New("regdisclosure: legal basis and requester are required")
	}
	if root.Count != len(entries) {
		return nil, fmt.Errorf("regdisclosure: signed root covers %d entries, log has %d", root.Count, len(entries))
	}
	pres, err := sdjwt.Present(combinedSDJWT, req.Fields)
	if err != nil {
		return nil, fmt.Errorf("regdisclosure: present: %w", err)
	}
	disclosed, err := sdjwt.Verify(pres, issuerPub)
	if err != nil {
		return nil, fmt.Errorf("regdisclosure: verify presentation: %w", err)
	}
	proof, err := audit.MerkleProof(entries, entryIndex)
	if err != nil {
		return nil, fmt.Errorf("regdisclosure: audit proof: %w", err)
	}
	return &Package{
		Presentation: pres,
		Disclosed:    disclosed,
		Entry:        entries[entryIndex],
		Index:        entryIndex,
		Count:        len(entries),
		Proof:        proof,
		Root:         root,
		LegalBasis:   req.LegalBasis,
		Requester:    req.Requester,
		CreatedAt:    time.Now().UTC().Unix(),
	}, nil
}

// Verify checks the package end to end as the authority would: the SD-JWT is
// issuer-signed and parses; the audit root is signed by the domain's audit key;
// and the disclosed entry is provably included under that root. Fails closed.
func (p *Package) Verify(issuerPub, auditPub ed25519.PublicKey) error {
	if _, err := sdjwt.Verify(p.Presentation, issuerPub); err != nil {
		return fmt.Errorf("regdisclosure: sd-jwt: %w", err)
	}
	if !audit.VerifyRoot(p.Root, auditPub) {
		return errors.New("regdisclosure: audit root signature invalid")
	}
	if p.Root.Count != p.Count {
		return errors.New("regdisclosure: entry count does not match signed root")
	}
	if !audit.VerifyInclusion(p.Entry.Hash, p.Index, p.Count, p.Proof, p.Root.Root) {
		return errors.New("regdisclosure: audit entry not included under signed root")
	}
	return nil
}
