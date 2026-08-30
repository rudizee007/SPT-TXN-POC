package main

// Regression test for the CAT signing seed reaching the log (adversarial
// review 8, fix 3).
//
// cmd/workload-bridge printed `hex.EncodeToString(priv.Seed())` in a log line
// suggesting how to pin the key across restarts. That seed signs every CAT the
// process issues, and a log line is the widest distribution channel it could
// have: stdout, journald, the container runtime, and whatever aggregator ships
// them onward, all read by people not trusted with a signing key.
//
// This is a SOURCE-LEVEL guard, which is unusual and needs justifying. The key
// generation lives in main(), which no test can call, so there is no runtime
// seam to assert on. The alternative -- refactoring main() to make it testable
// -- is a larger change than the defect warrants and would itself go in
// untested. A source guard is cruder, but it fails loudly the moment anyone
// reintroduces the pattern, which is the property actually wanted here: this
// exact defect has now been introduced twice in this repository and fixed twice.
//
// Both halves of the idp-bridge / workload-bridge pair are checked, because the
// way this defect survived was being fixed in one twin and not the other.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// Any log/print call on the same line as a Seed() call. Deliberately broad: a
// false positive here is a comment away from being resolved, a false negative
// is a signing key in a log aggregator.
var seedToLog = regexp.MustCompile(`(?i)(log\.(Print|Fatal|Panic)\w*|fmt\.(Print|Fprint|Sprint)\w*)\([^)]*\.Seed\(\)`)

func TestCATSigningSeedIsNeverWrittenToTheLog(t *testing.T) {
	for _, path := range []string{
		"main.go",
		"../idp-bridge/main.go",
	} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		for n, line := range strings.Split(string(src), "\n") {
			trimmed := strings.TrimSpace(line)
			if strings.HasPrefix(trimmed, "//") {
				continue // a comment describing the defect is not the defect
			}
			if seedToLog.MatchString(line) {
				t.Errorf("SECURITY: %s:%d writes an Ed25519 signing seed to the log:\n\t%s",
					path, n+1, trimmed)
			}
		}
	}
}

// The seed must still be obtainable by an operator who asks for it -- otherwise
// the fix just makes the key unpinnable and someone reverts it. Both twins offer
// a file-based escape hatch with mode 0600.
func TestCATSigningSeedHasAFileBasedEscapeHatch(t *testing.T) {
	for path, envVar := range map[string]string{
		"main.go":               "SPT_WL_CAT_SEED_OUT",
		"../idp-bridge/main.go": "SPT_IDP_CAT_SEED_OUT",
	} {
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		s := string(src)
		if !strings.Contains(s, envVar) {
			t.Errorf("%s: no %s escape hatch; the seed is unobtainable and the "+
				"log line will come back", path, envVar)
		}
		if !strings.Contains(s, "0o600") {
			t.Errorf("%s: seed file is not written 0600", path)
		}
	}
}
