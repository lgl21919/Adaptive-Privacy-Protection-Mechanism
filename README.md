# ACFP — Adaptive Context-aware Privacy Protection

This repository contains the **user-identity security** and **data-protection** code from two research projects:

1. **Research on Blockchain-Intelligence-Driven Metaverse Modeling, Collaboration, and Decision-Making Technologies**
2. **Research on Key Technologies of Federated Large Models for Transportation Governance Based on Decentralized Autonomous Organizations (DAOs)**

The code covers **off-chain applications**, **on-chain chaincode pointers**, the **ACFP mechanism** (adaptive context-aware identity and data policies), **security verification cases**, and **functional / performance test cases**.

## Correspondence to the papers

ACFP implements a two-stage adaptive privacy pipeline used in consortium-chain academic-publishing and related DAO/governance workflows:

1. **Context-Awareness Module** — captures a workflow state vector \(\mathcal{C} = (s, m, r, d, l)\) (phase, role, review mode, data type, security level).
2. **Logical Reasoning Engine** — maps \(\mathcal{C}\) to identity and encryption strategies:

\[
\text{Policy} = f(s, m, r, d, l) \rightarrow \{\text{IAPP\_Strategy}, \text{DAPP\_Strategy}\}
\]

| Paper topic | What this repo provides |
|-------------|-------------------------|
| Identity security (IAPP / \(\Pi_{\mathrm{id}}\)) | Phase-aware real / pseudonymous / anonymous identities, anonymity and de-anonymisation experiments |
| Data security (DAPP / \(\Pi_{\mathrm{data}}\)) | ECDH, SSS, PRE, and MPC encryption selection, security experiments, Caliper benchmarks |
| Adaptive ACFP mechanism | Declarative YAML rule base, UC-style verification, adaptive vs. static comparison |
| Consortium-chain (Hyperledger Fabric) | Off-chain Go clients, chaincode deployment notes, on-chain policy storage |

The declarative rule base is `adaptive/config/adaptive_rules.yaml` (override with `ADAPTIVE_RULES_PATH`). Updating the YAML changes IAPP/DAPP behaviour **without redeploying chaincode**.

Further design notes: [adaptive/README.md](./adaptive/README.md), [adaptive/docs/ARCHITECTURE.md](./adaptive/docs/ARCHITECTURE.md), [adaptive/docs/UC_AND_VERIFICATION.md](./adaptive/docs/UC_AND_VERIFICATION.md), [adaptive/docs/EXPERIMENTS.md](./adaptive/docs/EXPERIMENTS.md).

## Repository layout

| Directory | Role | Typical entry points |
|-----------|------|----------------------|
| `adaptive/` | **ACFP mechanism**: context capture, logical reasoning, UC verification, identity/crypto scheme stubs, adaptive benchmarks | `pkg/context`, `pkg/reasoning`, `pkg/uc`, `cmd/uc_verify`, `cmd/adaptive_benchmark` |
| `identity-policy/` | **Identity policy (\(\Pi_{\mathrm{id}}\))**: off-chain identity manager, phase pseudonyms, Fabric clients, anonymity / de-anonymisation experiments — see [docs/ARCHITECTURE.md](./identity-policy/docs/ARCHITECTURE.md), [docs/EXPERIMENTS.md](./identity-policy/docs/EXPERIMENTS.md) | `cmd/identity_manager`, `cmd/paper_manager`, `cmd/anonymity_experiment`, `cmd/deanonymisation_sim` |
| `data-policy/` | **Data policy (\(\Pi_{\mathrm{data}}\))**: encryption managers (ECDH, SSS, PRE, MPC), security experiments, Caliper performance tests — see [docs/ARCHITECTURE.md](./data-policy/docs/ARCHITECTURE.md), [docs/EXPERIMENTS.md](./data-policy/docs/EXPERIMENTS.md) | `cmd/data_manager`, `cmd/paper_manager`, `cmd/rubric_export`, `caliper-workspace/` |

The three Go modules are wired by `go.work`:

```
./adaptive
./identity-policy
./data-policy
```

Exported import paths (for other services) are listed in [EXPORT_PACKAGES.md](./EXPORT_PACKAGES.md).

**On-chain chaincode.** Canonical Fabric chaincode lives at `../chaincode/privacy-protection/chaincode-go/` (chaincode ID `academicPublishing`). Local `identity-policy/chaincode/` and `data-policy/chaincode/` are README pointers only; do not add duplicate `.go` sources there.

## Environment

| Requirement | Version / notes |
|-------------|-----------------|
| Go | **1.21+** (`go.work` and all three `go.mod` files) |
| Hyperledger Fabric | Optional for unit tests and adaptive benchmarks; required for live chain clients and Caliper |
| Fabric Gateway / SDK | `fabric-gateway` v1.3.0; identity manager also uses `fabric-sdk-go` v1.0.0 |
| Node.js | Required only for Caliper (`data-policy/caliper-workspace`) |
| Hyperledger Caliper | Optional; bind SUT `fabric:fabric-gateway` |
| SQLite | Optional; identity/paper managers persist local registration and wallet mapping |

Set Fabric wallet / connection-profile paths in `identity-policy/config.yaml` and `data-policy/config.yaml` when talking to `fabric-samples/test-network`.

## Quick start

Clone this repository and work from the `ACFP` root.

```bash
git clone <this-repository-url> ACFP
cd ACFP
```

### 1. Adaptive mechanism (no Fabric required)

```bash
cd adaptive
go test ./...
go run ./cmd/uc_verify
go run ./cmd/adaptive_benchmark -out ./benchmark_output
```

Benchmark artefacts (JSON, CSV, LaTeX tables) are written under `adaptive/benchmark_output/`. See [adaptive/benchmark_output/README.md](./adaptive/benchmark_output/README.md).

### 2. Identity policy (off-chain CLIs)

```bash
cd identity-policy
go run ./cmd/identity_manager
go run ./cmd/paper_manager
go run ./cmd/anonymity_experiment
go run ./cmd/deanonymisation_sim
```

### 3. Data policy, security tests, and Caliper

```bash
cd data-policy
go run ./cmd/data_manager
go test ./internal/data_policy/...
```

Performance tests against a running Fabric network:

```bash
cd data-policy/caliper-workspace
# Requires Fabric test-network + deployed academicPublishing chaincode
./run.sh
```

Path checks and network YAML are documented in [data-policy/caliper-workspace/README.md](./data-policy/caliper-workspace/README.md).

## How to obtain the code and data

| Artefact | How to obtain |
|----------|----------------|
| **Source code** | This GitHub repository (three modules + configs + tests). No extra proprietary SDK is required beyond public Go / Fabric / Caliper dependencies resolved by `go mod`. |
| **Adaptive experiment data** | Generated locally: `cd adaptive && go run ./cmd/adaptive_benchmark -out ./benchmark_output`. Precomputed samples may already be present under `adaptive/benchmark_output/` (JSON, CSV, TeX). |
| **UC / security verification traces** | `go test ./pkg/uc/...` and `go run ./cmd/uc_verify` inside `adaptive/`; reports include `uc_verification_report.json` and related TeX tables. |
| **Identity anonymity results** | Run `identity-policy/cmd/anonymity_experiment` and `cmd/deanonymisation_sim`. |
| **Data-protection security / rubric outputs** | `go test ./internal/data_policy/...` and `go run ./cmd/rubric_export` in `data-policy/`; TeX under `data-policy/docs/rubric_output/`. |
| **Caliper performance reports** | Start Fabric test-network, deploy chaincode `academicPublishing`, then run `data-policy/caliper-workspace/run.sh`. |
| **On-chain chaincode** | If this folder is published alone, obtain `privacy-protection/chaincode-go` from the companion chaincode tree (`../chaincode/privacy-protection/`) or the corresponding GitHub path in the parent project. |

Third-party dependencies are fetched with `go mod tidy` in each module (or from the workspace root). Caliper and Fabric samples are **not** vendored; install them from the official Hyperledger distributions.

## Configuration

| File | Purpose |
|------|---------|
| `adaptive/config/adaptive_rules.yaml` | IAPP / DAPP rule base |
| `identity-policy` config YAML | Fabric CA / gateway / local DB for identity mapping |
| `data-policy` config YAML | Fabric gateway and encryption workflow settings |

`ADAPTIVE_RULES_PATH` overrides the adaptive rule file without a chaincode redeploy.

## License and citation

Please cite the two research projects listed above when using this code in academic work. If a formal license file is added later, follow that license for redistribution.
