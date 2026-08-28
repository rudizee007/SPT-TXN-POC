package verify_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rudizee007/spt-txn-poc/pkg/trustsnapshot"
	"github.com/rudizee007/spt-txn-poc/pkg/verify"
)

// signSnapshot signs the body file at bodyPath with a fresh publication key and
// writes the manifest beside it. Returns the manifest path and the pinned key.
//
// It is also the round-trip proof that the generator and the verifier agree: if
// Sign and Verify ever disagree about the signing input or the body digest, every
// test in this file fails at once rather than one of them quietly passing.
func signSnapshot(t *testing.T, bodyPath string, issuedAt time.Time) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatal(err)
	}
	m, err := trustsnapshot.Sign(body, "snapshot-1", issuedAt, []string{"domain-a"}, nil, priv)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	raw, err := trustsnapshot.MarshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := bodyPath + ".manifest.json"
	if err := os.WriteFile(manifestPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return manifestPath, pub
}

func freshOpts(pub ed25519.PublicKey) verify.SnapshotOptions {
	return verify.SnapshotOptions{PinnedKeys: []ed25519.PublicKey{pub}, MaxAge: time.Hour}
}

// CONTROL: a correctly signed snapshot loads. Every refusal below is meaningless
// until this passes.
func TestFromSignedSnapshot_LoadsACorrectlySignedSnapshot(t *testing.T) {
	body := writeBody(t, seedRecords(t))
	manifest, pub := signSnapshot(t, body, time.Now())

	if _, err := verify.FromSignedSnapshot(manifest, body, freshOpts(pub)); err != nil {
		t.Fatalf("a correctly signed snapshot was refused: %v", err)
	}
}

// The acceptance criterion for the whole change: a validly signed manifest
// paired with a body carrying one extra issuer record must be refused. This is
// the file-write attack — append a record with your own key, and every eight-step
// verification downstream accepts chains you minted — expressed as a test.
func TestFromSignedSnapshot_RefusesABodyThatIsNotTheSignedBody(t *testing.T) {
	recs := seedRecords(t)
	body := writeBody(t, recs)
	manifest, pub := signSnapshot(t, body, time.Now())

	// Now append an attacker-controlled issuer record to the body, leaving the
	// signed manifest untouched.
	attackerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recs = append(recs, record("did:web:bank-issuer", "ct_issuer", attackerPub))
	if err := os.WriteFile(body, marshalBody(t, recs), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = verify.FromSignedSnapshot(manifest, body, freshOpts(pub))
	if err == nil {
		t.Fatal("a body carrying an unsigned issuer record was accepted as a root of trust")
	}
	if !errors.Is(err, trustsnapshot.ErrDigestMismatch) {
		t.Errorf("wrong diagnosis: want ErrDigestMismatch, got: %v", err)
	}
}

// Same ids, different key material. A digest that covered only issuer ids would
// pass this; it must not.
func TestFromSignedSnapshot_RefusesSubstitutedKeyMaterialUnderTheSameIDs(t *testing.T) {
	recs := seedRecords(t)
	body := writeBody(t, recs)
	manifest, pub := signSnapshot(t, body, time.Now())

	swapped, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	recs[0].PublicKey = swapped
	if err := os.WriteFile(body, marshalBody(t, recs), 0o600); err != nil {
		t.Fatal(err)
	}

	_, err = verify.FromSignedSnapshot(manifest, body, freshOpts(pub))
	if !errors.Is(err, trustsnapshot.ErrDigestMismatch) {
		t.Fatalf("key material was swapped under the same ids and accepted: %v", err)
	}
}

func TestFromSignedSnapshot_RefusesAnUnpinnedOrEmptyKeySet(t *testing.T) {
	body := writeBody(t, seedRecords(t))
	manifest, _ := signSnapshot(t, body, time.Now())

	t.Run("empty pin set", func(t *testing.T) {
		_, err := verify.FromSignedSnapshot(manifest, body, verify.SnapshotOptions{MaxAge: time.Hour})
		if !errors.Is(err, trustsnapshot.ErrNoPinnedKeys) {
			t.Fatalf("want ErrNoPinnedKeys, got: %v", err)
		}
	})
	t.Run("wrong key", func(t *testing.T) {
		other, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		_, err = verify.FromSignedSnapshot(manifest, body, freshOpts(other))
		if !errors.Is(err, trustsnapshot.ErrBadSignature) {
			t.Fatalf("want ErrBadSignature, got: %v", err)
		}
	})
}

func TestFromSignedSnapshot_RefusesATamperedManifest(t *testing.T) {
	body := writeBody(t, seedRecords(t))
	manifest, pub := signSnapshot(t, body, time.Now())

	for name, mutate := range map[string]func(m map[string]any){
		"flipped signature byte": func(m map[string]any) {
			s := m["signature_hex"].(string)
			flipped := "0" + s[1:]
			if s[0] == '0' {
				flipped = "1" + s[1:]
			}
			m["signature_hex"] = flipped
		},
		"short signature":   func(m map[string]any) { m["signature_hex"] = "abcd" },
		"non-hex signature": func(m map[string]any) { m["signature_hex"] = "zz" },
		"changed id":        func(m map[string]any) { m["id"] = "snapshot-2" },
		"changed digest":    func(m map[string]any) { m["digest_hex"] = "00" },
		"changed issued_ms": func(m map[string]any) { m["issued_ms"] = float64(1) },
		"unregistered alg":  func(m map[string]any) { m["alg"] = "HMAC-SHA256" },
		"wrong sig_domain":  func(m map[string]any) { m["sig_domain"] = "spt-cp/ot-trust-bundle-v1" },
	} {
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(manifest)
			if err != nil {
				t.Fatal(err)
			}
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			mutate(m)
			tampered := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(tampered, marshal(t, m), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := verify.FromSignedSnapshot(tampered, body, freshOpts(pub)); err == nil {
				t.Fatal("a tampered manifest was accepted")
			}
		})
	}
}

// A suite this build cannot verify must be refused outright. Trial-verifying
// under a suite the manifest did not name reintroduces exactly the ambiguity
// `alg` exists to remove.
func TestFromSignedSnapshot_RefusesASuiteItCannotVerify(t *testing.T) {
	body := writeBody(t, seedRecords(t))
	manifest, pub := signSnapshot(t, body, time.Now())

	raw, _ := os.ReadFile(manifest)
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	m["alg"] = trustsnapshot.AlgHybrid87
	p := filepath.Join(t.TempDir(), "manifest.json")
	if err := os.WriteFile(p, marshal(t, m), 0o600); err != nil {
		t.Fatal(err)
	}

	opts := freshOpts(pub)
	opts.AcceptAlgs = []string{trustsnapshot.AlgEdDSA, trustsnapshot.AlgHybrid87}
	_, err := verify.FromSignedSnapshot(p, body, opts)
	if !errors.Is(err, trustsnapshot.ErrAlgUnsupported) {
		t.Fatalf("want ErrAlgUnsupported, got: %v", err)
	}
}

func TestFromSignedSnapshot_Staleness(t *testing.T) {
	body := writeBody(t, seedRecords(t))
	manifest, pub := signSnapshot(t, body, time.Now().Add(-48*time.Hour))

	t.Run("refused by default", func(t *testing.T) {
		_, err := verify.FromSignedSnapshot(manifest, body, freshOpts(pub))
		if !errors.Is(err, trustsnapshot.ErrStale) {
			t.Fatalf("want ErrStale, got: %v", err)
		}
	})
	t.Run("allowed only on an explicit operator choice", func(t *testing.T) {
		opts := freshOpts(pub)
		opts.AllowStale = true
		if _, err := verify.FromSignedSnapshot(manifest, body, opts); err != nil {
			t.Fatalf("an explicitly-allowed stale snapshot was refused: %v", err)
		}
	})
	t.Run("no max_age configured is an error, not no bound", func(t *testing.T) {
		opts := freshOpts(pub)
		opts.MaxAge = 0
		if _, err := verify.FromSignedSnapshot(manifest, body, opts); err == nil {
			t.Fatal("an unset max_age was treated as no bound")
		}
	})
}

func TestFromSignedSnapshot_RefusesAMissingManifestOrBody(t *testing.T) {
	body := writeBody(t, seedRecords(t))
	manifest, pub := signSnapshot(t, body, time.Now())
	missing := filepath.Join(t.TempDir(), "nope.json")

	if _, err := verify.FromSignedSnapshot(missing, body, freshOpts(pub)); err == nil {
		t.Fatal("a missing manifest was treated as a fresh deploy")
	}
	if _, err := verify.FromSignedSnapshot(manifest, missing, freshOpts(pub)); err == nil {
		t.Fatal("a missing body was accepted")
	}
}

// A record this package would refuse through its own API must not arrive through
// a file either. Load-time validation is what makes that true.
func TestFromSignedSnapshot_RefusesAnInvalidRecordEvenWhenCorrectlySigned(t *testing.T) {
	recs := seedRecords(t)
	recs[0].PublicKey = []byte{1, 2, 3} // not 32 bytes
	body := writeBody(t, recs)
	manifest, pub := signSnapshot(t, body, time.Now())

	if _, err := verify.FromSignedSnapshot(manifest, body, freshOpts(pub)); err == nil {
		t.Fatal("a signed snapshot carrying a structurally invalid record was loaded")
	}
}

// The manifest names one suite, and there are two different reasons to refuse
// it: the name is not one this format defines, or it is defined but this build
// cannot verify it. Asserting only "something failed" lets either branch be
// deleted with the suite still green — which is exactly what the mutation pass
// found before these existed.
func TestFromSignedSnapshot_DistinguishesUnregisteredFromUnsupportedSuites(t *testing.T) {
	body := writeBody(t, seedRecords(t))
	manifest, pub := signSnapshot(t, body, time.Now())

	withAlg := func(t *testing.T, alg string) error {
		t.Helper()
		raw, err := os.ReadFile(manifest)
		if err != nil {
			t.Fatal(err)
		}
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["alg"] = alg
		p := filepath.Join(t.TempDir(), "manifest.json")
		if err := os.WriteFile(p, marshal(t, m), 0o600); err != nil {
			t.Fatal(err)
		}
		opts := freshOpts(pub)
		opts.AcceptAlgs = []string{trustsnapshot.AlgEdDSA, trustsnapshot.AlgHybrid87, "HMAC-SHA256"}
		_, err = verify.FromSignedSnapshot(p, body, opts)
		return err
	}

	t.Run("a name this format does not define", func(t *testing.T) {
		if err := withAlg(t, "HMAC-SHA256"); !errors.Is(err, trustsnapshot.ErrUnregisteredAlg) {
			t.Fatalf("want ErrUnregisteredAlg, got: %v", err)
		}
	})
	t.Run("defined but not implemented here", func(t *testing.T) {
		if err := withAlg(t, trustsnapshot.AlgHybrid87); !errors.Is(err, trustsnapshot.ErrAlgUnsupported) {
			t.Fatalf("want ErrAlgUnsupported, got: %v", err)
		}
	})
	t.Run("registered but outside this deployment's accept-set", func(t *testing.T) {
		raw, _ := os.ReadFile(manifest)
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			t.Fatal(err)
		}
		m["alg"] = trustsnapshot.AlgMLDSA87
		p := filepath.Join(t.TempDir(), "manifest.json")
		if err := os.WriteFile(p, marshal(t, m), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := verify.FromSignedSnapshot(p, body, freshOpts(pub)); !errors.Is(err, trustsnapshot.ErrAlgNotAccepted) {
			t.Fatalf("want ErrAlgNotAccepted, got: %v", err)
		}
	})
}

// A signature of the wrong length is MALFORMED, not "a signature that failed to
// verify". The distinction matters operationally — one is a broken publisher or
// a truncated transfer, the other is an attack or a key rotation you missed —
// and without asserting it the length check is decoration.
func TestFromSignedSnapshot_AMisshapenSignatureIsMalformedNotUnverified(t *testing.T) {
	body := writeBody(t, seedRecords(t))
	manifest, pub := signSnapshot(t, body, time.Now())

	for name, sig := range map[string]string{
		"empty":      "",
		"too short":  "abcd",
		"one byte":   "ab",
		"63 bytes":   strings.Repeat("ab", 63),
		"65 bytes":   strings.Repeat("ab", 65),
		"odd length": "abc",
		"not hex":    strings.Repeat("zz", 64),
	} {
		t.Run(name, func(t *testing.T) {
			raw, _ := os.ReadFile(manifest)
			var m map[string]any
			if err := json.Unmarshal(raw, &m); err != nil {
				t.Fatal(err)
			}
			m["signature_hex"] = sig
			p := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(p, marshal(t, m), 0o600); err != nil {
				t.Fatal(err)
			}
			_, err := verify.FromSignedSnapshot(p, body, freshOpts(pub))
			if !errors.Is(err, trustsnapshot.ErrMalformed) {
				t.Fatalf("want ErrMalformed, got: %v", err)
			}
		})
	}
}
