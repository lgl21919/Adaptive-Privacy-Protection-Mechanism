# Experiments and Reproducibility

## Prerequisites

- Go **1.21+**
- From `adaptive/`: `go mod tidy` (YAML only for core; Fabric not required)

## 1. Unit / package tests

```bash
cd adaptive
go test ./pkg/context ./pkg/reasoning ./pkg/identity ./pkg/crypto ./pkg/uc
```

Notable suites:

| Package | What it covers |
|---------|----------------|
| `pkg/reasoning` | Rule matching, tamper fallback, weights, static-vs-adaptive fitness |
| `pkg/uc` | \(\pi/\mathcal{F}/\mathcal{S}\), composition, monitor closed loop, spec sync, attack fixtures |

## 2. UC verification CLI (`cmd/uc_verify`)

Proves effectiveness claims E1–E11 and writes paper tables.

```bash
cd adaptive
go run ./cmd/uc_verify -out ./benchmark_output -trials 64 -audit golden
```

| Flag | Default | Meaning |
|------|---------|---------|
| `-out` | `./benchmark_output` | Output directory |
| `-trials` | `64` | Trials for randomized experiments (floor 32 in suite) |
| `-audit` | `golden` | `golden` or `synced` audit wiring |

Outputs: `uc_verification_report.json`, `uc_verification_table.tex`, `uc_pillar_snapshot.json`.

Exit codes: `1` if any experiment fails; `2` if golden audit detects production-rule drift from `DefaultRuleSet`.

Details: [UC_AND_VERIFICATION.md](./UC_AND_VERIFICATION.md).

## 3. Adaptivity benchmark (`cmd/adaptive_benchmark`)

Supports paper claims on **context awareness**, **logical reasoning**, and **hot-updatable rules** (no chaincode redeploy).

```bash
cd adaptive
go run ./cmd/adaptive_benchmark -out ./benchmark_output
```

### Experiment matrix

| Experiment | Controlled variables | Expected effect |
|------------|----------------------|-----------------|
| Exp.1 IAPP | Fix role/data; vary review mode \(r\) | IAPP switches (e.g. AUTHOR: DB→pseudo, SB/OPEN→real) |
| Exp.2 DAPP | Fix phase; vary security level \(\ell\) | DAPP escalates ECDH → PRE/SSS → MPC |
| Exp.3 Hot update | Edit YAML in memory / reload | IAPP/DAPP change; `chaincode_redeploy=no` |
| Coverage | All IAPP + DAPP rules | Match rate / consistency metrics |

### Outputs (`benchmark_output/`)

| File | Use |
|------|-----|
| `adaptive_benchmark_results.json` | Full scenario rows + summary |
| `adaptive_benchmark_summary.json` | Coverage, consistency, distinguishability, hot-update ms |
| `adaptive_benchmark_results.csv` | Spreadsheet analysis |
| `adaptive_benchmark_results.tex` | Chinese LaTeX tables |
| `adaptive_benchmark_results_en.tex` | English LaTeX tables |

See also [../benchmark_output/README.md](../benchmark_output/README.md).

## 4. Static vs adaptive fitness

Package API (no separate CLI): `reasoning.DefaultFitnessCases`, `AdaptivePick`, `Judge`, used by `static_vs_adaptive_test.go`.

Compares frozen static baselines (B1/B2) against adaptive coordinator picks under gold minimum-strength constraints.

## 5. Configuration for reproducibility

| Artefact | Path |
|----------|------|
| Rule base | `config/adaptive_rules.yaml` |
| Built-in golden rules | `reasoning.DefaultRuleSet()` |
| Ideal F bindings | `uc.DefaultIdealSpec()` |
| Catalog version | `reasoning.ConfigCatalogVersion` (`"1.0"`) |

Override production rules without rebuild:

```bash
set ADAPTIVE_RULES_PATH=D:\path\to\adaptive_rules.yaml   # Windows
export ADAPTIVE_RULES_PATH=/path/to/adaptive_rules.yaml  # Unix
```

After rule / IdealSpec edits:

```bash
go test ./pkg/uc -run TestHotPathIdealSpecConfigSync
```

## Suggested paper subsection mapping

| Claim | Evidence |
|-------|----------|
| Context awareness | Exp.1 / Exp.2 state-vector tables from adaptive_benchmark |
| Correct \(f_{\mathrm{id}},f_{\mathrm{enc}}\) | Coverage + consistency rates; E1 |
| Fail-closed integrity | E2 unit + CLI |
| UC-oriented composition | E3, E11, pillar snapshot |
| Hot reconfiguration | Exp.3 (`chaincode_redeploy=no`) |
| Closed-loop governance | Monitor tests + [CLOSED_LOOP.md](./CLOSED_LOOP.md) |
