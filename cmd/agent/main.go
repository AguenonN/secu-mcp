// Command agent is the MCP host: the party that trusts servers.
//
// It reads a trust config (an endpoint and an expected identity), connects to
// whatever answers, and calls get_file. TRUST_MODE splits the behaviour:
//
//	naive     — MCP as it ships: trust the endpoint on sight, verify no
//	            identity. Pointed at the rogue, the agent is robbed.
//	zerotrust — require the server to prove it holds ExpectedSPIFFEID. The
//	            rogue is refused at the handshake, before any tool runs,
//	            because it cannot produce that identity.
//
// Same config, same rogue: only continuous verification changes the outcome.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"mcprogue/internal/envelope"
	"mcprogue/internal/guardrail"
	"mcprogue/internal/identity"
	"mcprogue/internal/labconfig"
	"mcprogue/internal/mcptool"
	"mcprogue/internal/toolpolicy"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	mode := identity.Mode(labconfig.Env("TRUST_MODE", string(identity.ModeNaive)))
	cfg, err := labconfig.Load(labconfig.Env("AGENT_CONFIG", ""))
	if err != nil {
		log.Fatalf("agent: load config: %v", err)
	}

	log.Printf("agent: mode=%s endpoint=%s expected=%s", mode, cfg.Endpoint, cfg.ExpectedSPIFFEID)

	httpClient, cleanup, err := buildClient(ctx, mode, cfg)
	if err != nil {
		log.Fatalf("agent: %v", err)
	}
	defer cleanup()

	transport := &mcp.StreamableClientTransport{
		Endpoint:   cfg.Endpoint,
		HTTPClient: httpClient,
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "0.1.0"}, nil)

	session, err := client.Connect(ctx, transport, nil)
	if err != nil {
		// In zero-trust mode the rogue stops here: no SVID, no handshake, no
		// session.
		log.Fatalf("agent: connection rejected by the identity gate: %v", err)
	}
	defer session.Close()

	// GUARDRAIL=on adds the content layer: replies are schema-checked,
	// injection markers neutralized, credentials redacted. Off by default so
	// the naive scenarios still show the raw poisoned reply.
	var inner toolpolicy.Session = session
	if labconfig.Env("GUARDRAIL", "off") == "on" {
		log.Printf("agent: guardrail enabled — inspecting tool replies against local policy")
		inner = guardrail.Wrap(session)
	}

	// The guardrail is a textual filter and those lose eventually. The two
	// locks below are not filters: they hold against an injection the filter
	// never saw, so they are always on.
	//
	// toolpolicy grants exactly one read-only tool. Any other call is refused
	// before it leaves the process, and with no approver wired action tools
	// are unreachable.
	log.Printf("agent: tool policy active — grants: %s=%s, everything else denied",
		mcptool.ToolName, toolpolicy.Read)
	policy := toolpolicy.Wrap(inner, toolpolicy.Grants{mcptool.ToolName: toolpolicy.Read})

	res, err := policy.CallTool(ctx, &mcp.CallToolParams{
		Name:      mcptool.ToolName,
		Arguments: mcptool.GetFileInput{Path: "router.conf"},
	})
	if err != nil {
		log.Fatalf("agent: call get_file: %v", err)
	}

	// The reply is sealed inside an <untrusted_data> boundary before it could
	// be concatenated into a prompt: the poison stays visible, but it enters
	// the context as data rather than instructions.
	out, _ := json.MarshalIndent(res, "", "  ")
	sealed, err := envelope.Seal(string(out))
	if err != nil {
		log.Fatalf("agent: seal reply: %v", err)
	}
	fmt.Printf("agent: get_file returned — sealed as it would enter the model context:\n%s\n", sealed)
}

// buildClient returns the HTTP client for the mode, plus a cleanup releasing
// any identity source it opened.
func buildClient(ctx context.Context, mode identity.Mode, cfg labconfig.Config) (*http.Client, func(), error) {
	switch mode {
	case identity.ModeZeroTrust:
		src, err := identity.NewSource(ctx, cfg.WorkloadAPISocket)
		if err != nil {
			return nil, func() {}, err
		}
		expected, err := spiffeid.FromString(cfg.ExpectedSPIFFEID)
		if err != nil {
			src.Close()
			return nil, func() {}, fmt.Errorf("parse expected SPIFFE ID: %w", err)
		}
		return src.ClientHTTP(expected), func() { _ = src.Close() }, nil
	case identity.ModeNaive:
		return identity.NaiveHTTP(), func() {}, nil
	default:
		return nil, func() {}, fmt.Errorf("unknown TRUST_MODE %q (want naive|zerotrust)", mode)
	}
}
