# Data Policy Experiments and Quick Start

How to exercise Π_data code: unit security workflow, attack-surface rubric, crypto latency CLI, and Fabric Caliper benchmarks.

## Prerequisites

| Requirement | When needed |
|-------------|-------------|
| Go **1.21+** | All Go tests and CLIs |
| Sibling `../adaptive` module | Adaptive DAPP path / workspace build |
| Fabric test-network + chaincode `academicPublishing` | `paper_manager`, `encryption_chain`, Caliper |
| Node.js + Hyperledger Caliper | `caliper-workspace/` only |

From repo workspace (`ACFP/go.work`) or:

```bash
cd data-policy
go mod tidy
```

---

## 1. Security workflow unit tests

Fixed **8-step** high-security publishing profile (`security_experiment_workflow.go`):

| # | Phase | Data type | Level |
|---|-------|-----------|-------|
| 1 | SUBMISSION | MANUSCRIPT | 2 |
| 2 | SUBMISSION | MESSAGE | 2 |
| 3 | REVIEW | MANUSCRIPT | 2 |
| 4 | REVIEW | SUPPLEMENTARY_DATA | 2 |
| 5 | REVIEW | MESSAGE | 2 |
| 6 | REVIEW | FINAL_RECOMMENDATION | 3 |
| 7 | PUBLICATION | MANUSCRIPT | 2 |
| 8 | PUBLICATION | MESSAGE | 0 |

```bash
cd data-policy
go test ./internal/data_policy/ -run Security -count=1
go test ./internal/data_policy/ -count=1
```

These check that `GetEncryptionPolicyWithLevel` returns the expected algorithm class per step (and related rubric/sensitivity helpers).

Export the same steps for external timers:

```go
steps := data_policy.SecurityExperimentWorkflowSteps()
```

---

## 2. Attack-surface rubric export

Compares baselines **B1** (uniform ECDH), **B2** (phase-static), and **Adaptive** on qualitative attack vectors under the 8-step workflow (`attack_surface_rubric.go`):

| Vector ID | Meaning |
|-----------|---------|
| `single_point_key` | Single-point key compromise |
| `reviewer_collusion` | Compromised reviewer collusion |
| `insider_editor` | Insider editor targeting author identity |
| `pre_delegate` | Compromised PRE delegate (Adaptive-only surface) |

```bash
cd data-policy
go run ./cmd/rubric_export -out ./docs/rubric_output
```

| Output | Content |
|--------|---------|
| `docs/rubric_output/attack_surface_rubric.tex` | LaTeX tables (attack surface + legacy confidentiality weights) |
| `docs/rubric_output/attack_surface_rubric_summary.txt` | Mitigation totals / exposure index / ordering check |

Related tests: `attack_surface_rubric_test.go`, `rubric_sensitivity_test.go`.

---

## 3. Crypto performance CLI (`cmd/data_manager`)

Off-chain Enc/Dec microbenchmarks (no Fabric required):

```bash
cd data-policy
go run ./cmd/data_manager
```

Runs:

1. Registered phase×type×level combination smoke tests  
2. Default small-payload Enc+Dec latency  
3. **64 KB** manuscript Enc+Dec (paper table row)  
4. **8-step workflow** cumulative Enc+Dec (Adaptive vs static profiles as implemented in the CLI)  
5. Scale-out over participant count \(n\) (64 KB)  
6. Policy-retrieval microbenchmark  

Optional PRE demos / tests in the same package:

```bash
go test ./cmd/data_manager/ -count=1
# proxy_demo_main.go is a separate main; build with tags if present in tree
```

---

## 4. On-chain encryption workflow (optional Fabric)

Build-tagged chain demo (`cmd/data_manager/encryption_chain.go`, tag `encryption_chain`):

- Init local SQLite  
- Fabric Gateway client (User1 MSP paths)  
- Store data-protection policy / encrypted paper / query re-encryption material  

Requires a running test-network and deployed `academicPublishing` chaincode. Align org paths with your `fabric-samples` layout before running.

Paper manager CLI:

```bash
cd data-policy
go run ./cmd/paper_manager
```

Uses `config.yaml` / `config/config.yaml` for CCP and wallet settings.

---

## 5. Caliper performance tests

```bash
cd data-policy/caliper-workspace
# Ensure networks/networkConfig.yaml points at your Fabric orgs
./run.sh
# or: npx caliper bind --caliper-bind-sut fabric:fabric-gateway --caliper-bind-cwd .
```

Workload scenarios (see [../caliper-workspace/README.md](../caliper-workspace/README.md)):

| Scenario | Chain function focus |
|----------|----------------------|
| `storeDataProtectionPolicy` | Policy write |
| `storeEncryptedPaper` | Encrypted paper write |
| `getEncryptedPaper` | Paper read |
| `getDataProtectionPolicy` | Policy read |
| `getReEncryptionKey` | Re-key material |
| `mixedOperations` | Mixed read/write |

---

## Suggested paper evidence mapping

| Claim | Artefact / command |
|-------|--------------------|
| Adaptive DAPP selects stronger schemes on sensitive steps | Security workflow tests + adaptive YAML |
| Adaptive reduces attack-surface vs B1/B2 | `cmd/rubric_export` TeX / summary |
| Crypto latency acceptable at manuscript size | `cmd/data_manager` 64 KB + scale-\(n\) |
| On-chain store/query throughput | Caliper reports from `caliper-workspace` |

## Configuration checklist

| Knob | Effect |
|------|--------|
| `ADAPTIVE_RULES_PATH` | Changes DAPP decisions in exported `datapolicy` manager |
| `config.yaml` | Fabric endpoints for paper / chain demos |
| `caliper-workspace/networks/networkConfig.yaml` | Peer/identity paths for Caliper |

Architecture and package map: [ARCHITECTURE.md](./ARCHITECTURE.md).
