#!/bin/bash

echo "=== 学术出版系统部署脚本 ==="

# 1. 编译Go代码
echo "1. 编译Go代码..."
go mod init academic-publishing
go mod tidy
go build -o academic-publishing .

# 2. 编译链码
echo "2. 编译Fabric链码..."
cd chaincode
go mod init chaincode
go get github.com/hyperledger/fabric-contract-api-go
go build -o academic-publishing-chaincode .
cd ..

# 3. 运行测试
echo "3. 运行系统测试..."
./academic-publishing

echo "=== 部署完成 ==="

go get github.com/mattn/go-sqlite3