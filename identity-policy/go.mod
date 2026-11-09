module github.com/tap-thesis/privacy-protection-identity

go 1.21

require (
	github.com/hyperledger/fabric-gateway v1.3.0
	github.com/hyperledger/fabric-sdk-go v1.0.0
	github.com/pkg/errors v0.9.1
	privacy-protection/adaptive v0.0.0
	golang.org/x/crypto v0.31.0
	google.golang.org/grpc v1.54.0
)

replace (
	privacy-protection/adaptive => ../adaptive
	google.golang.org/grpc => google.golang.org/grpc v1.54.0
)
