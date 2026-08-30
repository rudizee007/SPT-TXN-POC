package trustregistry

// Regression test for the OpenVerified TOCTOU (adversarial review 8, fix 2).
//
// OpenVerified read the body, verified it, and then called
// NewPersistentRegistry(bodyPath) -- which re-read the same path. Anyone able to
// write that file between the two reads (the entire adversary this function
// exists to stop) substituted their own records AFTER the signature check, and
// OpenVerified returned success with attacker-chosen ct_issuer keys installed.
//
// Why no existing test caught it: the suite tampers with the file BEFORE the
// call and asserts ErrDigestMismatch. That proves the signature check works. It
// says nothing about which bytes get loaded once the check has passed.
//
// This is the fifth appearance of validate-then-re-read in this codebase, so the
// property is stated as a race the test can actually lose:
//
//	OpenVerified must NEVER return success with a record that was not in the
//	bytes whose signature it verified.
//
// A failed verification is a safe outcome and is skipped. Only success-with-a-
// foreign-key is a bypass.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func TestOpenVerified_LoadsTheBytesItVerified_UnderConcurrentSwap(t *testing.T) {
	bodyPath, manifestPath, pub := signedFixture(t)

	legit, err := os.ReadFile(bodyPath)
	if err != nil {
		t.Fatal(err)
	}
	attackerPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tampered := injectRecord(t, legit, attackerPub)

	dir := filepath.Dir(bodyPath)
	legitSrc := filepath.Join(dir, "legit.body.json")
	tamperedSrc := filepath.Join(dir, "tampered.body.json")
	if err := os.WriteFile(legitSrc, legit, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tamperedSrc, tampered, 0o600); err != nil {
		t.Fatal(err)
	}

	// Writers swap the body between the signed content and the tampered content
	// via rename, so a reader always sees one whole file or the other -- a torn
	// read would only ever produce a parse error and mask the defect.
	var stop atomic.Bool
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			srcs := []string{legitSrc, tamperedSrc}
			for n := 0; !stop.Load(); n++ {
				b, err := os.ReadFile(srcs[(n+w)%2])
				if err != nil {
					continue
				}
				tmp := bodyPath + ".swap"
				if err := os.WriteFile(tmp, b, 0o600); err != nil {
					continue
				}
				_ = os.Rename(tmp, bodyPath)
			}
		}(w)
	}
	defer func() {
		stop.Store(true)
		wg.Wait()
	}()

	for i := 0; i < 4000; i++ {
		reg, err := OpenVerified(manifestPath, bodyPath, opts(pub))
		if err != nil {
			continue // the read caught the tampered body: refused, which is correct
		}
		recs, err := reg.List(context.Background(), RoleCTIssuer)
		reg.Close()
		if err != nil {
			continue
		}
		for _, r := range recs {
			if bytes.Equal(r.PublicKey, attackerPub) {
				t.Fatalf("TOCTOU at iteration %d: OpenVerified returned SUCCESS carrying a "+
					"ct_issuer key that was never in the bytes it verified", i)
			}
		}
	}
}
