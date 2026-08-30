# FIPS 140-3 plan for SPT-Txn (decision record)

> Status 2026-06-30: **no buyer is currently requiring FIPS.** Therefore the plan
> is to make a FIPS 140-3 path a **ready, tested deployment option** (cheap, no
> migration), so we can answer "yes, we have a FIPS 140-3 story" credibly the day
> an org asks — without paying for it before then. Companion to
> `PLATFORM-AND-OSS-STRATEGY.md` (§2/§2a), which this operationalizes.

---

## 0. TL;DR

- **Do NOT replace LibreSSL with wolfSSL/wolfCrypt on OpenBSD.** It is high-friction,
  partly unsupported, commercially licensed, and buys us nothing over the free path.
- **Use the Go FIPS 140-3 module** (Go Cryptographic Module, CMVP **cert #5247**,
  shipped in Go 1.24+). Our services are already Go — this is a build/runtime flag,
  not a rewrite, and it covers the trust-critical crypto and (via TLS-in-Go)
  data-in-transit, on any OS including OpenBSD.
- **Defer the FIPS-validated Linux profile** (RHEL/Rocky/Ubuntu Pro) until a buyer's
  policy actually mandates full-OS (Layer 3) validation.
- **Be honest about scope:** FIPS 140-3 covers the *transport and classical* crypto.
  SPT-Txn's distinctive **zero-knowledge layer (Groth16/BN254, Poseidon2, Baby
  Jubjub, Ed25519) is outside the FIPS canon by nature** — no library, wolfCrypt
  included, can make those "FIPS-validated." That boundary must be stated, not hidden.

---

## 1. What is actually in the stack (correcting the premise)

There is **no OpenSSL** in the web services to replace.

- **TLS termination** = OpenBSD **LibreSSL** via **relayd** (with **httpd** behind it).
- **Application crypto** = **Go standard-library crypto** inside the Go services
  (`tr-svc` / Travel-Rule, agent-verify), plus the ZK stack (gnark).
- So "swap OpenSSL for wolfCrypt" targets a component that does not exist here.

## 2. Why wolfCrypt-on-OpenBSD is the wrong lever

1. **LibreSSL is welded into OpenBSD base.** relayd, httpd, ssh, and the userland
   link it through `libtls`. OpenBSD does not support substituting a different TLS
   library for base daemons; doing so means maintaining a forked base indefinitely
   against a project that is philosophically opposed to FIPS.
2. **wolfCrypt FIPS is a paid, fixed, embedded-oriented build** (CMVP certs #4718 /
   #5041). Validation applies only to the exact build in the exact boundary; modify
   the build or step outside it and the certificate does not apply.
3. **FIPS 140-3 is a boundary + process claim, not a library swap.** Dropping a FIPS
   library into an unsupported slot yields the cost and none of the certifiable boundary.
4. **It duplicates, at a price, what Go already gives us for free** (cert #5247).
5. **It still does nothing for the ZK layer** (see §5) — no C FIPS library validates
   Poseidon2 / BN254 / Groth16 either.

## 3. The right lever: the Go FIPS 140-3 module (free, validated, portable)

CMVP **certificate #5247** — the FIPS 140-3 Go Cryptographic Module v1.0.0, in Go 1.24+.
Pure Go (no cgo, no OpenSSL dependency), so it runs on OpenBSD unchanged.

- **Build:** `GOFIPS140=v1.0.0 go build ./...` (selects the validated module version;
  defaults FIPS mode on).
- **Run:** `GODEBUG=fips140=on` (enforce approved algorithms at runtime).
  `fips140=only` is for test/assessment (it errors/panics on non-approved algorithms —
  useful to *discover* what in our code is outside the boundary; not for production).
- **Covers:** AES-GCM, SHA-2/3, HMAC, ECDSA (P-256/384/521), RSA, HKDF, DRBG, and
  ML-KEM (FIPS 203) for PQ-secure TLS (X25519MLKEM768). ML-DSA (FIPS 204) lands in the
  Go 1.26 module.
- **TLS-in-Go lever:** terminate TLS **inside the Go service** with this module instead
  of at relayd. That pulls data-in-transit into the validated boundary **even on
  non-FIPS OpenBSD**, and reduces our dependence on LibreSSL for the FIPS claim.

## 4. FIPS boundary layers and who needs what

| Layer | Covers | How we satisfy it | Who asks |
|---|---|---|---|
| **1. Application crypto** | token signing/verification, hashing, the data we protect | Go FIPS module (`GODEBUG=fips140=on`) | Most VASPs |
| **2. Data-in-transit (TLS)** | TLS termination | Terminate TLS in the Go service via the Go FIPS module | Some VASPs |
| **3. Full OS** | kernel, disk, system libs, SSH | Deploy same Go binaries on FIPS-validated Linux (RHEL/Rocky/Ubuntu Pro) | FedRAMP/FISMA-style only |

Current posture: **build Layers 1+2 as a profile now; defer Layer 3.**

### 4a. Layer-3 OS choice — AlmaLinux (free, validated); NOT FreeBSD (documented 2026-06-30)

If a buyer ever mandates full-OS (Layer 3) FIPS, the target is **AlmaLinux in FIPS
mode** — a free, RHEL-compatible OS with actual OS-level CMVP-validated crypto modules:
**Kernel Crypto API (cert #4750)** and **OpenSSL FIPS provider (cert #4823)** active,
with GnuTLS / NSS / libgcrypt in the CMVP pipeline (9.6). Enable with
`fips-mode-setup --enable` plus FIPS system-wide crypto-policies. Preferred over
RHEL / Ubuntu Pro because the OS itself carries no license cost.

**Alternative OS (co-equal): Rocky Linux (via CIQ).** Rocky Linux is the other free,
RHEL-compatible distribution with the same OS-level FIPS 140-3 story; **CIQ** (Rocky's
commercial sponsor) provides the FIPS-validated modules and ongoing certified support —
the Rocky-world counterpart to AlmaLinux + TuxCare. Either works identically for our Go
binaries; the choice between AlmaLinux/TuxCare and Rocky/CIQ comes down to support
relationship and price, not capability. Both keep the OS free to stand up, with
continuous certified patching being the paid piece (TuxCare ESU or CIQ support).

**Cost caveat (honest):** the OS and FIPS mode are free to stand up, but FIPS
certificates are pinned to a *specific validated build*, so keeping continuous certified
compliance with security patches over time is a **paid TuxCare (CloudLinux) ESU**
subscription. Budget that only when a buyer requires *ongoing* certification, not to
stand up a demo or answer an RFP checkbox.

**FreeBSD rejected as a Layer-3 target.** FreeBSD base has **no** OS-level FIPS
validation — the same gap as our current OpenBSD. The most it offers is installing the
OpenSSL 3.1.2 FIPS provider (validated; FreeBSD 13.1 is a listed *tested* environment)
for application crypto, which is app-layer FIPS, no better than the free Go module and
with more setup. Switching OpenBSD → FreeBSD would gain **nothing** on FIPS. For full-OS
FIPS, only a validated Linux (AlmaLinux / Rocky / RHEL / Ubuntu Pro) qualifies.

**Layer-3 hosting (chosen).** Run the AlmaLinux FIPS node on **DigitalOcean or Akamai
(Linode)** — simplest UX, predictable flat pricing, one-click/custom AlmaLinux images.
FIPS validation is a property of the OS crypto modules, so the provider is
FIPS-agnostic; DigitalOcean/Linode is fine for standing up and demonstrating the
Layer-3 profile. Escalate to a compliance-boundary cloud (**AWS GovCloud / Azure
Government**) *only* if a specific buyer is US-federal / FedRAMP and requires it. Prefer
a dedicated-CPU plan + full-disk encryption for the security-by-design posture.

## 5. What FIPS 140-3 can and CANNOT cover in SPT-Txn (the honesty centerpiece)

FIPS validates a fixed list of *approved algorithms*. Much of SPT-Txn's distinctive
cryptography is deliberately outside that list, and **no vendor (wolfCrypt included)
can change that** — these primitives are not in the FIPS canon:

- **Zero-knowledge layer — OUT of FIPS by nature.** Groth16 over **BN254**, **Poseidon2**
  hashing, **Baby Jubjub EdDSA** in-circuit. There is no FIPS-validated zk-SNARK
  primitive; this is modern research crypto. It cannot be "FIPS 140-3 validated,"
  from Go, wolfCrypt, or anyone.
- **Ed25519 token signing — needs a swap for a FIPS-approved signature.** EdDSA is now
  in FIPS 186-5, but if a buyer requires FIPS-approved signing today, move token
  signing to **ECDSA P-256** (approved now) or **ML-DSA / Dilithium** (FIPS 204, our
  documented PQ migration path — which conveniently is also the FIPS-approved path).
  The framework already has algorithm-agility dispatch for exactly this.
- **What CAN be in the boundary:** TLS (AES-GCM/ECDHE/ECDSA/SHA-2), SHA-256 context
  hashing, HMAC, DRBG, and (post-swap) ECDSA/ML-DSA signatures.

**Correct framing for a buyer:** "SPT-Txn's transport and classical token cryptography
run in the FIPS 140-3-validated Go Cryptographic Module (CMVP #5247). The
zero-knowledge selective-disclosure layer uses modern primitives (Groth16/BN254,
Poseidon2) that are outside the FIPS-approved algorithm set by nature; that layer is
documented, and an independent audit of it is sought rather than complete; it can be disabled for deployments whose scope
forbids non-approved algorithms." Never imply the ZK layer is FIPS-validated.

## 6. Phased plan (low effort now, buyer-triggered later)

**Phase 0 — now (a few days, no migration):**
1. Add a **FIPS build profile**: `GOFIPS140=v1.0.0` build tag/target in the Makefile/CI
   for `tr-svc` and agent-verify. Keep the normal (non-FIPS) build as default.
2. Run the test suite with `GODEBUG=fips140=only` to **enumerate** every call that hits
   a non-approved algorithm (this will flag Ed25519, Poseidon2, BN254, Baby Jubjub).
   Record the list — that IS the "outside the boundary" inventory for §5.
3. Gate the ZK/agentic features behind a build flag so a "FIPS-strict" build compiles
   without the non-approved primitives (for buyers whose scope forbids them).
4. Write the buyer-facing claim wording (from §5) into the sales/integration doc.

**Phase 1 — on first buyer interest (Layer 2):**
5. Add an optional **TLS-in-Go** listener (Go FIPS module) as an alternative to relayd
   termination, so data-in-transit is in the validated boundary. Keep relayd for
   non-FIPS deployments.

**Phase 2 — only if a buyer mandates Layer 3:**
6. Stand up the **FIPS-validated Linux profile** (**AlmaLinux in FIPS mode preferred —
   free & CMVP-validated**, see §4a; Rocky / RHEL / Ubuntu Pro as alternatives) with the
   same Go binaries + `GOFIPS140`. CI matrix builds/tests both OpenBSD and Linux. No code
   change — the OpenBSD-specific `pledge`/`unveil` bits are already behind build tags.

**Phase 3 — signature approval (if required):**
7. Flip token signing to ECDSA P-256 or ML-DSA via the existing algorithm-agility
   dispatch, for buyers who require FIPS-approved signatures.

## 7. Where wolfCrypt could ever legitimately fit

Essentially never for this stack. The only scenarios: (a) a future **C or embedded**
component that needs a validated C library, or (b) a customer who contractually
requires a **specific** validated C module in a dedicated appliance. In those cases put
wolfCrypt in a **purpose-built TLS-terminating proxy on Linux**, in its exact validated
boundary — not spliced into OpenBSD base. For our Go services, the Go module is
strictly better (free, portable, no boundary surgery).

## 8. License & cost risk — the decisive factor (RISK, documented 2026-06-30)

Beyond the engineering friction, adopting wolfCrypt carries a **licensing and cost
risk** that on its own rules it out for this project. Comparison against what we run
today (LibreSSL) and the recommended path (Go module):

| | **LibreSSL (current)** | **wolfSSL / wolfCrypt** | **Go FIPS module** |
|---|---|---|---|
| License | Permissive (ISC + OpenSSL/SSLeay) | **GPLv2 OR commercial** | Permissive (BSD-style Go license) |
| Cost | Free | Free under GPLv2, else **$7,500 / product**; FIPS = separate commercial engagement | Free |
| Apache-2.0 compatible? | **Yes** | **No** under the free GPLv2 (copyleft conflict); only via the paid commercial license | **Yes** |
| Copyleft obligation | None | **GPLv2 copyleft** on the free path | None |
| Already in our stack? | **Yes** (relayd/httpd, OpenBSD base) | No | N/A (we are Go) |
| TLS 1.3 | Yes (4.3.0) | Yes | Yes |
| PQ-hybrid TLS (X25519MLKEM768) | **Yes** | Yes | Yes |
| FIPS 140-3 certificate | **No** | Yes (#4718 / #5041) | **Yes (#5247)** |

**The risk, stated plainly:** wolfCrypt's only usable-for-us path is the **$7,500/product
commercial license** (plus a separate FIPS engagement), because the free **GPLv2 path is
license-incompatible with our Apache-2.0 codebase** — GPLv2 copyleft would infect the
combined work (Apache-2.0 is one-way compatible with GPLv3, not GPLv2). So we would pay,
and take on a licensing entanglement, to obtain a FIPS capability the **free,
Apache-2.0-compatible Go module already provides**.

LibreSSL, by contrast, is **free, permissively licensed, already integrated, TLS-1.3 and
PQ-hybrid capable** — its *only* gap versus wolfCrypt is the FIPS certificate, and that
gap is closed by the Go module at **zero cost and zero license conflict**.

**Decision:** do not adopt wolfCrypt. The license + cost risk is decisive on top of the
engineering friction (§2). Keep LibreSSL for transport; add the Go FIPS module as the
validated-crypto lever when a buyer requires the certificate.

## 9. Bottom line

We get a genuine, defensible FIPS 140-3 story with a **build flag and a documented
profile**, on our existing OpenBSD host, at near-zero cost and risk — and we keep the
OpenBSD `pledge`/`unveil` hardening story intact. The wolfCrypt-on-OpenBSD route is
more cost, more risk, more maintenance, a **$7,500+ license with an Apache-2.0
conflict**, and no more coverage. The one non-negotiable is honesty about the ZK layer
sitting outside the FIPS boundary; that candor is itself a security-by-design signal.
