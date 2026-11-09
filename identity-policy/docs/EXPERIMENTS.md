# Identity Policy Experiments and Quick Start

How to exercise Π_id code: identity seeding / on-chain latency, anonymity-set measurement, and simulated deanonymisation attacks.

## Prerequisites

| Requirement | When needed |
|-------------|-------------|
| Go **1.21+** | All Go CLIs |
| Sibling `../adaptive` module | Adaptive IAPP path / workspace build |
| Local SQLite users DB | Anonymity & deanonymisation experiments |
| Fabric test-network + deployed chaincode | `identity_manager` / `paper_manager` on-chain paths |

```bash
cd identity-policy
go mod tidy
```

Detailed Chinese logic notes also exist at repo root of this module (`ANONYMITY_EXPERIMENT_*.md`, `DEANONYMISATION_SIM_*.md`, `PERFORMANCE_TESTING.md`); this file is the concise English entry point aligned with the code.

---

## 0. Prepare identity data (recommended first)

`cmd/identity_manager` seeds / expands the local DB (reviewer pools, publication mirrors for cross-phase checks) and can push identities on-chain:

```bash
cd identity-policy
go run ./cmd/identity_manager
```

Typical side effects:

- Ensures a reviewer pool (e.g. 40 reviewers; 20 sampled per review mode)
- Mirrors double-blind reviewers into PUBLICATION rows for cross-phase linkage checks
- Calls Fabric `SaveUserIdentity` with per-op latency aggregation (`internal/utils` performance helpers)

Database default under the CLI cwd: `./academic_publishing.db`. Anonymity / attack CLIs auto-resolve common relative paths if you run them from `cmd/*/`.

Paper / messaging workflow (also reports chain latency):

```bash
go run ./cmd/paper_manager
```

Requires `config.yaml` Fabric CCP/wallet settings and a running network.

---

## 1. Anonymity-set size experiment

**Goal:** Quantify observer-facing anonymity-set sizes per `(phase, review_mode, role)` and check a threshold (default **≥ 50**).

| Code | Role |
|------|------|
| `cmd/anonymity_experiment/main.go` | CLI entry |
| `internal/utils/anonymity.go` | Observable keys, equivalence classes, metrics |

```bash
cd identity-policy
go run ./cmd/anonymity_experiment
```

**Scope:** `SUBMISSION` and `REVIEW` rows from `users`.

**Observable identity model (high level):**

| Phase / mode | AUTHOR | REVIEWER | EDITOR |
|--------------|--------|----------|--------|
| SUBMISSION | real (`on_chain_identity`) | — | real |
| REVIEW + DOUBLE_BLIND | pseudonym | pseudonym | real |
| REVIEW + SINGLE_BLIND | real | pseudonym | real |
| REVIEW + OPEN | real | real | real |

With `collapsePseudonyms=true`, users that only expose pseudonyms/anonymous handles in a scenario are treated as indistinguishable for set-size measurement.

**Per-scenario metrics:** population, equivalence-group count, min / avg / max set size, threshold pass rate.  
Focus line: **REVIEW + DOUBLE_BLIND + REVIEWER**.

If no scenarios print, run `identity_manager` (or otherwise populate `users`) first.

---

## 2. Deanonymisation attack simulation

**Goal:** Under controlled threat models, measure how auxiliary information shrinks candidate sets (queue-local unique match = “success”).

| Code | Role |
|------|------|
| `cmd/deanonymisation_sim/main.go` | CLI entry |
| `internal/utils/deanonymisation_sim.go` | Attack keys, Monte Carlo, DB evaluation |

```bash
cd identity-policy
go run ./cmd/deanonymisation_sim
```

### A. Metadata attacks on double-blind reviewers

Cohort: `REVIEW + DOUBLE_BLIND + REVIEWER`.

| Scenario | Attacker side information |
|----------|---------------------------|
| `METADATA_INSTITUTION` | Institution / affiliation attribute |
| `METADATA_EMAIL_DOMAIN` | Domain parsed from `off_chain_id` email form |
| `METADATA_COMBINED_LEAK` | Institution × domain composite key |

Outputs: evaluated targets, unique-match count, ambiguous count, no-signal count, success / ambiguity rates, average candidate-set size.

### B. Cross-mode side channels (REVIEW only, reviewers)

Link the same subject across **DOUBLE_BLIND ↔ SINGLE_BLIND** when an identifier appears in both modes:

| Scenario | Link key |
|----------|----------|
| `CROSS_PHASE_SIDE_CHANNEL` | `off_chain_id` |
| `CROSS_PHASE_ONCHAIN_ID` | `on_chain_identity` |
| `CROSS_PHASE_PHASE_PSEUDONYM` | `phase_pseudonym` |

### C. Synthetic Monte Carlo vs real DB

Rows vary reviewer count × institution/domain slot counts; last row contrasts the real double-blind cohort under the combined metadata key.

**Interpretation:** fewer institution/domain slots → higher unique-match rate → weaker anonymity; high cross-mode link rate → configuration/leak risk between blind modes.

---

## 3. On-chain latency (Fabric)

Documented in detail in `PERFORMANCE_TESTING.md`. Summary:

| CLI | Measured ops |
|-----|----------------|
| `cmd/identity_manager` | `SaveUserIdentity` |
| `cmd/paper_manager` | `SubmitPaper`, `SendMessage` |

Stats: total / success / fail, min / avg / max latency, wall-clock elapsed (`internal/utils/performance.go`).

---

## Suggested paper evidence mapping

| Claim | Artefact / command |
|-------|--------------------|
| IAPP switches visibility with review mode | Adaptive YAML + `GetVisibilityPolicy` / `EvaluateAdaptivePolicy` |
| Double-blind reviewer pool meets anonymity threshold | `go run ./cmd/anonymity_experiment` |
| Metadata leak shrinks anonymity | `go run ./cmd/deanonymisation_sim` (section A/C) |
| Blind-mode misconfiguration enables linkage | deanonymisation section B |
| Identity / paper chain ops latency acceptable | identity_manager / paper_manager performance blocks |

## Configuration checklist

| Knob | Effect |
|------|--------|
| `ADAPTIVE_RULES_PATH` | Changes IAPP decisions in exported `identitypolicy` manager |
| `config.yaml` | Fabric endpoints for identity / paper CLIs |
| SQLite `users` population | Required for anonymity & attack experiments |
| Reviewer pool size in `identity_manager` | Drives anonymity-set and attack cohort sizes |

Architecture and package map: [ARCHITECTURE.md](./ARCHITECTURE.md).
