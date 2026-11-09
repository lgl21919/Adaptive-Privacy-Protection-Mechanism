#!/bin/bash

# Academic Publishing Caliper 性能测试运行脚本
# 基于 encryption_chain.go 工作流程

echo "=== Academic Publishing Caliper 性能测试 ==="
echo ""
npx caliper launch manager --caliper-workspace ./ --caliper-networkconfig networks/networkConfig.yaml --caliper-benchconfig benchmarks/myAPBenchmark.yaml --caliper-flow-only-test
