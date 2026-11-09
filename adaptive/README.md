# Adaptive Privacy Engine (ACFP core)

Go module `privacy-protection/adaptive` — context-aware adaptive identity (IAPP) and data (DAPP) policy selection, plus UC-oriented verification and closed-loop governance.

Upstream modules import the coordinator:

- `identity-policy` → `EvaluateIdentityPolicy`
- `data-policy` → `EvaluateDataPolicy`

## Pipeline

\[
\mathcal{C}=(s,m,r,q,d,\ell,\mathit{cfg})
\;\xrightarrow{f_{\mathrm{id}},f_{\mathrm{enc}}}\;
\{\mu,\sigma\}
\]

1. **Context-Awareness** (`pkg/context`) — capture and normalize \(\mathcal{C}\)
2. **Logical Reasoning** (`pkg/reasoning`) — YAML rules + optional UC weights → IAPP/DAPP
3. **Protect / Encrypt slices** (`pkg/identity`, `pkg/crypto`) — UC real-world executables
4. **UC + monitor** (`pkg/uc`) — \(\pi/\mathcal{F}/\mathcal{S}\), audit, FeedbackGovernor

Rule base: [`config/adaptive_rules.yaml`](./config/adaptive_rules.yaml). Override with `ADAPTIVE_RULES_PATH` (no chaincode redeploy).

## Quick start

```bash
cd adaptive
go test ./...
go run ./cmd/uc_verify -out ./benchmark_output -trials 64
go run ./cmd/adaptive_benchmark -out ./benchmark_output
```

Requires **Go 1.21+**. Fabric is not required for these commands.

## Documentation

| Doc | Content |
|-----|---------|
| [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) | System architecture and data flow |
| [docs/MODULES.md](./docs/MODULES.md) | Package / file reference |
| [docs/UC_AND_VERIFICATION.md](./docs/UC_AND_VERIFICATION.md) | UC stack, E1–E11, audit modes |
| [docs/CLOSED_LOOP.md](./docs/CLOSED_LOOP.md) | Monitor, auditor, governor loop |
| [docs/EXPERIMENTS.md](./docs/EXPERIMENTS.md) | How to reproduce benchmarks |
| [benchmark_output/README.md](./benchmark_output/README.md) | Output file formats |

## Layout

```
adaptive/
├── config/adaptive_rules.yaml
├── cmd/uc_verify/
├── cmd/adaptive_benchmark/
├── pkg/context|reasoning|identity|crypto|uc/
├── benchmark_output/
└── docs/
```

## Minimal API example

```go
import (
    "privacy-protection/adaptive/pkg/context"
    "privacy-protection/adaptive/pkg/reasoning"
)

coord, err := reasoning.LoadCoordinatorFromEnv() // or NewDefaultCoordinator()
if err != nil { /* ... */ }

dec, err := coord.EvaluatePolicy(context.ContextInput{
    Phase: "REVIEW", Role: "AUTHOR", ReviewMode: "DOUBLE_BLIND",
    DataType: "MANUSCRIPT", SecurityLevel: 1,
    RegisteredRole: "AUTHOR", AuthenticatedPhase: "REVIEW",
})
// dec.IAPPStrategy, dec.DAPPStrategy, dec.RuleID, ...
```
