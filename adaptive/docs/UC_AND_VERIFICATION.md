# UC Framework and Verification

Maps the Universal Composability (UC) argument to the executable slices in `pkg/uc`, `pkg/identity`, and `pkg/crypto`.

## Two meanings of “adaptive”

| Concept | Meaning in this codebase |
|---------|--------------------------|
| **Adaptive corruption** | UC adversary model: declared `STATIC` or `ADAPTIVE_ERASURE` (`AdversaryModel`) |
| **Strategy adaptivity** | Public deterministic maps \(f_{\mathrm{id}}\), \(f_{\mathrm{enc}}\) over metadata \(\mathcal{C}\) |

Strategy functions are **not secret**. Security claims are: chosen modes execute correctly, and strategy inputs cannot be forged (fail-closed).

## Ideal functionality stack

\[
\mathcal{F}_{\mathrm{adaptive}}
=
\mathcal{F}_{\mathrm{id\text{-}strategy}}
\circ
\mathcal{F}_{\mathrm{id\text{-}protect}}
\circ
\mathcal{F}_{\mathrm{enc\text{-}strategy}}
\circ
\mathcal{F}_{\mathrm{enc}}
\]

| Layer | Code | Input | Output |
|-------|------|-------|--------|
| \(\mathcal{F}_{\mathrm{id\text{-}strategy}}\) | `EvaluateIdentityPolicy` + `ValidateStrategyInput` | \(\mathcal{C}\) | \(\mu\in\{\mathrm{real},\mathrm{pseudonym},\mathrm{anonymous}\}\) |
| \(\mathcal{F}_{\mathrm{id\text{-}protect}}\) / \(\mathcal{F}_{\mathrm{nym}}\) | `pkg/identity` | \(\mu,\mathit{uid},\mathit{sid}\) | handle \(h\) |
| \(\mathcal{F}_{\mathrm{enc\text{-}strategy}}\) | `EvaluateDataPolicy` | \((s,d,\ell,\mathit{cfg})\) | scheme \(\sigma\) |
| \(\mathcal{F}_{\mathrm{enc}}\) / \(\mathcal{F}_{\mathrm{SC}}\) | `pkg/crypto` | \(\sigma,m\) | ciphertext |

Identity HMAC keys and encryption keys are independent → **standard UC** (not JUC/GUC).

### Candidates, not per-pair ideals

- \(\mathcal{F}_{\mathrm{nym}}\): \(\pi_{\mathrm{pseudo}}\), \(\pi_{\mathrm{anon}}\) are candidates, not separate ideals.
- \(\mathcal{F}_{\mathrm{SC}}\): ECDH / SSS / PRE tokens are candidates feeding the secure-channel ideal.
- \(\rho_{\mathrm{app}}\) (`RhoApp`) only calls \(\mathcal{F}_{\mathrm{nym}}\) and \(\mathcal{F}_{\mathrm{SC}}\).
- Experiment **E11** checks all \(3\times 4\) identity×data pairs without building one \(F\) per pair.

## Real / ideal / simulator

| Object | Type | Behaviour |
|--------|------|-----------|
| \(\pi_{\mathrm{adaptive}}\) | `Protocol` | Real composition; may pin `OnlineStrategy` |
| \(\mathcal{F}_{\mathrm{adaptive}}\) | `FAdaptive` | Ideal; re-selects strategies; may abort on integrity fail |
| \(\mathcal{S}\) | `Simulator` | Dummy uid + equal-length random plaintext; matches `PublicTrace` |

`PublicTrace` is the environment’s view: context fields, IAPP, DAPP, scheme id, fallback / integrity flags — **no** private uid or plaintext.

## Simulator cases (code-backed)

1. **Public strategy I/O** — \(\mathcal{S}\) copies \((\mathcal{C},\mu,\sigma)\) from \(\mathcal{F}\).
2. **Mode switch** — anonymous sessions use `SimulatedAnonymous()` (unlinkable from pseudonyms).
3. **Composition ciphertext** — random equal-length plaintext under the same scheme.
4. **Input tamper** — validation fail → safest fallback + abort of Protect/Encrypt.

## Theorem (paper-ready statement)

> Assume unlinkable anonymous credentials and IND-CCA encryption primitives. Protocol \(\pi_{\mathrm{adaptive}}\) UC-realizes
> \(\mathcal{F}_{\mathrm{adaptive}}=(\mathcal{F}_{\mathrm{id\text{-}strategy}},\mathcal{F}_{\mathrm{id\text{-}protect}},\mathcal{F}_{\mathrm{enc\text{-}strategy}},\mathcal{F}_{\mathrm{enc}})\).
> Adversary: static corruption; adaptive corruption requires secure erasure.

Proof outline: sub-protocols realize sub-functionalities → strategy integrity → universal composition → corruption model. Executable evidence is the E1–E11 suite.

## Effectiveness experiments (`RunVerification`)

Implemented in `pkg/uc/verify.go`:

| ID | Name | Pass criterion |
|----|------|----------------|
| E1 | Strategy function deterministic | Public-trace identity rate \(=1\) |
| E2 | Tampered strategy input fail-closes | Always anonymous + level ≥ 3 |
| E3 | Simulator matches public I/O | Real vs \(\mathcal{S}\) traces equal |
| E4 | Pseudonym → anonymous unlinkability | Handles differ; anon mode correct |
| E5 | Intra-phase link / cross-phase unlink | Same scope equal; cross-phase differ |
| E6 | Single-algorithm encrypt/decrypt | Plaintext recovered |
| E7 | Multi-algorithm composition | Cascade/STE decrypt OK |
| E8 | Ciphertext does not echo plaintext | Distinguisher advantage \(< 0.35\) |
| E9 | ModeConfig raises floor | Forced anonymous + composition |
| E10 | Request content in public trace | \(q\) reflected; expected IAPP/DAPP |
| E11 | \(\mathcal{F}_{\mathrm{nym}}\times\mathcal{F}_{\mathrm{SC}}\) composition | All pairs trace/decrypt/unlink OK |

```bash
cd adaptive
go test ./pkg/uc ./pkg/reasoning ./pkg/context ./pkg/identity ./pkg/crypto
go run ./cmd/uc_verify -out ./benchmark_output -trials 64 -audit golden
```

Artefacts:

| File | Content |
|------|---------|
| `benchmark_output/uc_verification_report.json` | Per-experiment metrics |
| `benchmark_output/uc_verification_table.tex` | LaTeX table for papers |
| `benchmark_output/uc_pillar_snapshot.json` | Four UC-oriented pillars + IdealStack marks |

## UC-oriented pillars

Weaker than a full UC proof, but isomorphic variables:

| Pillar | In a full UC proof | In this repo |
|--------|--------------------|--------------|
| Modeling assumptions | Math premises | Engineering + experiment constraints |
| Protocol code | ITMs | Go slices \(\pi/\mathcal{F}/\mathcal{S}/\rho\) |
| Crypto assumptions | Reduction targets | Observable lemma premises |
| Composition | UC theorem | Hybrid checks + `IdealSpec` strategy config |

`ExtractSnapshot` publishes into `VerificationStore` for the monitor (`QueryLatestVerifiedOK`, `RequireVerifiedPair`).

## Audit wiring

| Mode | \(\pi\) rules | \(\mathcal{F}\) rules | Use |
|------|---------------|-----------------------|-----|
| `golden` (default) | `LoadCoordinatorFromEnv()` | Built-in `DefaultRuleSet` | Detect production YAML drift |
| `synced` | Same coordinator | Same coordinator | After intentional dual update |

API: `NewGoldenAuditPair`, `NewSyncedAuditPair`, `NewAuditPair`. Lemma suite `RunVerification` always uses bilateral defaults and is independent of audit sampling.
