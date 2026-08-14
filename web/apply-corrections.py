#!/usr/bin/env python3
"""Apply the 2026-08-13 site corrections to index.html and llms.txt.

IDEMPOTENT. Run it as many times as you like; it applies only what is missing
and reports what it did. That matters because the deployed site and this
repository diverged — the site gained PQChecker.html, its links, and sitemap /
llms.txt entries, while this copy gained these corrections. Whichever set is
copied over the other, running this afterwards restores the corrections.

WHAT IT FIXES, and why each one matters:

1. The eight verification steps. The published order in
   draft-coetzee-oauth-spt-txn-tokens (identical in -02 and -03) is:
   Signature, Temporal validity, Audience, Revocation, Sender constraint,
   Chain, Scope, Context binding.

   The site listed: Signature, Issuer Trust, Temporal Validity, Revocation,
   Scope Verification, Delegation Depth, Human Anchor, Scope Hash Binding.

   That omitted Audience and Sender constraint entirely — on a page that
   separately advertises DPoP — so it read as an authorization engine that
   checks neither who a token was minted for nor that the presenter holds the
   bound key. Issuer trust, delegation depth and human-anchor consistency are
   all part of step 6 (Chain) in the draft, not separate steps.

   This was never correct against any published draft. An AI drafting a spec
   section took its step numbering from this page, which is how the error
   nearly reached the IETF draft itself.

2. The draft version. Published and citable is -03. The page said -02.

3. The audit claim. "verified by the security audit" — definite article, no
   qualifier — reads as a third-party engagement. Nothing has been externally
   audited, and this is the sentence a procurement reviewer asks about first.

NOT DONE HERE, deliberately — these need your judgement, not a script:
  * The open-core boundary is stated nowhere on the page, and the "You run"
    column lists publishing a signed Trust Registry snapshot in the same
    breath as the open-source verifier. CLAUDE.md §2 puts registry, revocation
    *distribution* and snapshot *hosting* on the commercial side.
  * "running today" / "Live ·" headings, with nothing in production.
  * The mainnet ZK claim whose two links point at Sepolia.
  * The FIPS 203 · 204 badge, where 204 is only a migration path.
  * "No shipping product completes that sentence today."
"""
import io
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))

OLD_CARDS = """      <div class="step">
        <div class="step-n">02</div>
        <div class="step-title">Issuer Trust</div>"""

NEW_CARDS_MARKER = '<div class="step-title">Sender Constraint</div>'

OLD_STEPS_JS = ("var steps=['Signature Verification','Issuer Trust','Temporal Validity',"
                "'Revocation Check','Scope Verification','Delegation Depth','Human Anchor',"
                "'Scope Hash Binding'];")

REPLACEMENTS = [
    ("index.html", "IETF Draft -02 ↗", "IETF Draft -03 ↗",
     "draft version in the hero button"),
    ("index.html", "IETF Internet-Draft · Revision -02",
     "IETF Internet-Draft · Revision -03", "draft version in the publications block"),
    ("index.html",
     "Revision -02 adds algorithm agility and a post-quantum migration path.",
     "Revision -03 is the current published version; datatracker is the authoritative "
     "source for what it contains.", "draft changelog sentence"),
    ("index.html",
     "The mutating issuance endpoints are never edge-exposed (verified by the security audit).",
     "The mutating issuance endpoints are never edge-exposed — enforced by socket-only "
     "binding and OpenBSD <code>unveil</code>, and confirmed by our own review. No part of "
     "this system has been externally audited.", "unsupported audit claim"),
    ("llms.txt", "revision -02", "revision -03", "draft version"),
]


def main() -> int:
    applied, already, missing, absent = [], [], [], []

    for fname, old, new, label in REPLACEMENTS:
        path = os.path.join(HERE, fname)
        if not os.path.exists(path):
            # Not a failure. The script is often run from a staging directory
            # holding only the file being deployed; a file that is not here
            # cannot be wrong here. Reporting it as blocking taught the operator
            # to ignore a red line, which is the opposite of the point.
            absent.append(f"{fname}: not in this directory ({label})")
            continue
        s = io.open(path, encoding="utf8").read()
        if new in s and old not in s:
            already.append(f"{fname}: {label}")
            continue
        if old not in s:
            missing.append(f"{fname}: could not find the text to replace ({label})")
            continue
        n = s.count(old)
        io.open(path, "w", encoding="utf8").write(s.replace(old, new))
        applied.append(f"{fname}: {label} ({n}x)")

    # The step cards and the demo's step array are structural; report rather
    # than attempt a blind splice, because a partial application here would
    # leave the page internally inconsistent, which is worse than either state.
    idx = os.path.join(HERE, "index.html")
    if os.path.exists(idx):
        s = io.open(idx, encoding="utf8").read()
        cards_ok = NEW_CARDS_MARKER in s
        js_ok = OLD_STEPS_JS not in s and "'Sender Constraint'" in s
        if cards_ok and js_ok:
            already.append("index.html: eight-step cards and demo array")
        else:
            missing.append(
                "index.html: the EIGHT-STEP CARDS and/or the demo's step array are the "
                "pre-correction version. These are a structural rewrite, not a string swap "
                "— re-apply them by hand or from git history (they fold Issuer Trust, "
                "Delegation Depth and Human Anchor into step 6 Chain, and add Audience as "
                "step 3 and Sender Constraint as step 5). The demo's scenario `fail` "
                "indices must be remapped at the same time or it will stop at the wrong "
                "step: exp->2, aud->3, rev->4, holder->5, iss/depth/anchor->6, scope->7, "
                "txn->8.")

    for group, items in (("applied", applied), ("already correct", already),
                         ("not present here (fine)", absent), ("NEEDS ATTENTION", missing)):
        if items:
            print(f"\n{group}:")
            for i in items:
                print(f"  - {i}")

    if missing:
        print("\nSome corrections were not applied. Do not deploy until they are.")
        return 1
    print("\nAll scripted corrections are in place.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
