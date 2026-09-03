module mcprogue

// The MCP go-sdk (v1.7.0) declares `go 1.25.0`, so this module must too.
// Locally you therefore need Go >= 1.25 (or GOTOOLCHAIN=auto to fetch it);
// the containers in deploy/ build on golang:1.25 for exactly this reason.
go 1.25.0

require (
	github.com/go-jose/go-jose/v4 v4.1.4
	github.com/modelcontextprotocol/go-sdk v1.7.0
	github.com/spiffe/go-spiffe/v2 v2.8.1
)

require (
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/google/jsonschema-go v0.4.3 // indirect
	github.com/segmentio/asm v1.1.3 // indirect
	github.com/segmentio/encoding v0.5.4 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	golang.org/x/net v0.48.0 // indirect
	golang.org/x/oauth2 v0.35.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.32.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
)
