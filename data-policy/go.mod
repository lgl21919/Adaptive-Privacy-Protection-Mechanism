module github.com/tap-thesis/privacy-protection-data

go 1.21

require (
	github.com/hyperledger/fabric-gateway v1.3.0
	privacy-protection/adaptive v0.0.0
	golang.org/x/crypto v0.31.0
)

replace privacy-protection/adaptive => ../adaptive
