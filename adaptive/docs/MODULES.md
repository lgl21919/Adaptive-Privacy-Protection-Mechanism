# Module Reference

Code-accurate reference for packages under `adaptive/`.

## Directory tree

```
adaptive/
├── config/adaptive_rules.yaml     # declarative IAPP/DAPP rule base
├── cmd/
│   ├── adaptive_benchmark/        # adaptivity experiments → JSON/CSV/TeX
│   └── uc_verify/                 # UC effectiveness suite E1–E11
├── pkg/
│   ├── context/                   # Context-Awareness Module
│   ├── reasoning/                 # Logical Reasoning Engine + coordinator
│   ├── identity/                  # F_id-protect / F_nym
│   ├── crypto/                    # F_enc / F_SC
│   └── uc/                        # UC composition, monitor, verification
├── benchmark_output/              # generated reports (git-tracked samples OK)
└── docs/                          # this documentation
```

Module path: `privacy-protection/adaptive` (`go 1.21`).

---

## `pkg/context`

| File | Role |
|------|------|
| `context.go` | `ContextVector`, `SemanticState`, `ContextInput`, `ModeConfig`, `Capture`, `ValidateStrategyInput`, HMAC helpers |

**Key APIs**

- `NewContextAwarenessModule().Capture(in)` → `*SemanticState` with tokens and `StateKey`
- `ValidateStrategyInput(in)` → error on phase/role / integrity failure
- Normalization: empty → `*`; `PAPER` → `MANUSCRIPT`; non-REVIEW `r` → `*`

---

## `pkg/reasoning`

| File | Role |
|------|------|
| `engine.go` | Rules, `LogicalReasoningEngine`, `AdaptiveCoordinator`, `SafestFallback`, `ApplyModeConfig`, `EvaluatePolicy` / Identity / Data |
| `weights.go` | `PolicyWeightStore` — verified strategies get high weight; failed/unmapped get low |
| `coord_env.go` | `LoadCoordinatorFromEnv`, `ADAPTIVE_RULES_PATH`, process-wide singleton + shared weights |
| `catalog_sync.go` | `ConfigCatalogVersion`, strategy vocabulary helpers |
| `static_vs_adaptive.go` | Fitness cases comparing static baselines vs adaptive picks |

**IAPP tokens:** `REAL_IDENTITY`, `PSEUDONYMOUS`, `ANONYMOUS`  
**DAPP tokens:** `ECDH_HKDF`, `SSS`, `PROXY_REENCRYPTION`, `MPC`, `PUBLIC`

**Selection rule:** among matching YAML rules, maximize `(security_weight, priority)` — not first-match alone.

**Coordinator entry points**

```go
coord, _ := reasoning.LoadCoordinatorFromEnv() // or NewDefaultCoordinator / NewCoordinatorFromFile
dec, _  := coord.EvaluatePolicy(in)            // joint IAPP+DAPP
idDec,_ := coord.EvaluateIdentityPolicy(in)
dataDec,_ := coord.EvaluateDataPolicy(in)
```

Production importers (`identity-policy`, `data-policy`) should use the env singleton so golden UC audit shares the same rule instance.

---

## `pkg/identity`

| File | Role |
|------|------|
| `protect.go` | `Protector.Protect`, real HMAC id, PRF pseudonym, random anonymous, `SimulatedAnonymous` |

| Mode | Derivation | Linkability |
|------|------------|-------------|
| `REAL_IDENTITY` | `HMAC(master, "real\|uid")` | global |
| `PSEUDONYMOUS` | `HMAC(master, "pseudo\|uid\|sid\|phase\|mode\|role")` | same scope only |
| `ANONYMOUS` | fresh random | none |

---

## `pkg/crypto`

| File | Role |
|------|------|
| `scheme.go` | `Scheme`, `Executor.Encrypt/Decrypt`, AES-GCM, CASCADE, SIGN_THEN_ENCRYPT |

| ComposeMode | Behaviour |
|-------------|-----------|
| `SINGLE` / default | One AES-GCM seal |
| `CASCADE` | Nested seals over `Algorithms` |
| `SIGN_THEN_ENCRYPT` | HMAC then cascade |
| `NONE` / `PUBLIC` | Pass-through plaintext |

This is a **UC correctness / IND-style stub**, not the production ECDH/SSS/PRE/MPC stack in `data-policy`.

---

## `pkg/uc`

| File | Role |
|------|------|
| `model.go` | `PublicTrace`, `AdaptiveRequest`, `OnlineStrategy`, adversary model |
| `protocol.go` | \(\pi_{\mathrm{adaptive}}\) — `Protocol.Invoke`, `InvokeWithMonitor` |
| `ideal.go` | \(\mathcal{F}_{\mathrm{adaptive}}\) — always re-selects from rules; ignores `OnlineStrategy` |
| `simulator.go` | \(\mathcal{S}\) — dummy uid / random plaintext, public-trace matching |
| `fnym.go` / `fsc.go` / `candidates.go` | \(\mathcal{F}_{\mathrm{nym}}\), \(\mathcal{F}_{\mathrm{SC}}\), candidate realisations |
| `rho.go` / `compose.go` | \(\rho_{\mathrm{app}}\), composition checks (E11) |
| `ideal_map.go` | `IdealSpec` — (IAPP,DAPP) → F-port bindings |
| `verification_map.go` | Spec ⊕ runtime `Verified` marks |
| `event_detector.go` | Hot-path event intake |
| `monitor_controller.go` | Closed-loop entry: `ObserveProduction`, `PrepareInput` |
| `feedback_governor.go` / `governor.go` | Weight sync + ModeConfig lift |
| `audit_pair.go` / `tau_compare.go` | golden/synced audit; \(\pi\) vs \(S(\mathcal{F})\) |
| `spec_sync.go` | Hot-path YAML ↔ IdealSpec vocabulary sync |
| `pillar_snapshot.go` | UC-oriented four-pillar snapshot after verification |
| `verify.go` | E1–E11 experiment suite |
| `attack_instances.go` | Attack-scenario fixtures for tests |

**Important distinction**

| World | Strategy selection |
|-------|-------------------|
| \(\pi\) with `OnlineStrategy` set | Pins production IAPP/DAPP |
| \(\pi\) without online pin | Re-runs `EvaluatePolicy` |
| \(\mathcal{F}\) | Always re-selects from its engine; ignores online pin |

---

## Commands

### `cmd/uc_verify`

```bash
cd adaptive
go run ./cmd/uc_verify -out ./benchmark_output -trials 64 -audit golden
```

Flags: `-out`, `-trials`, `-audit golden|synced`.

Outputs: `uc_verification_report.json`, `uc_verification_table.tex`, `uc_pillar_snapshot.json`.

### `cmd/adaptive_benchmark`

```bash
cd adaptive
go run ./cmd/adaptive_benchmark -out ./benchmark_output
```

Runs IAPP mode-switch, DAPP level-switch, YAML hot-update, and full rule coverage. See [EXPERIMENTS.md](./EXPERIMENTS.md).
