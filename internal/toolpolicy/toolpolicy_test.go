package toolpolicy

import (
	"context"
	"errors"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// countingSession records whether the call ever reached the transport — the
// property under test is precisely that refused calls never do.
type countingSession struct {
	calls int
	res   *mcp.CallToolResult
}

func (c *countingSession) CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	c.calls++
	return c.res, nil
}

func call(t *testing.T, p *Policy, tool string) (*mcp.CallToolResult, error) {
	t.Helper()
	return p.CallTool(context.Background(), &mcp.CallToolParams{Name: tool})
}

// A granted read tool passes straight through.
func TestReadToolIsAllowed(t *testing.T) {
	inner := &countingSession{res: &mcp.CallToolResult{}}
	p := Wrap(inner, Grants{"get_file": Read}, WithLogf(t.Logf))

	if _, err := call(t, p, "get_file"); err != nil {
		t.Fatalf("granted read tool must pass, got: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("inner session should have been called once, got %d", inner.calls)
	}
}

// A tool outside the grant set is refused before the request leaves the
// agent — however the model was talked into asking for it.
func TestUngrantedToolIsDeniedBeforeTheWire(t *testing.T) {
	inner := &countingSession{}
	p := Wrap(inner, Grants{"get_file": Read}, WithLogf(t.Logf))

	for _, tool := range []string{"drop_table", "reboot_router", "exec"} {
		if _, err := call(t, p, tool); err == nil {
			t.Errorf("ungranted tool %q must be refused", tool)
		}
	}
	if inner.calls != 0 {
		t.Fatalf("refused calls must never reach the session, got %d calls", inner.calls)
	}
}

// An Action tool with no approver wired is unreachable: a headless agent is
// read-only by construction.
func TestActionToolWithoutApproverIsDenied(t *testing.T) {
	inner := &countingSession{}
	p := Wrap(inner, Grants{"reboot_router": Action}, WithLogf(t.Logf))

	if _, err := call(t, p, "reboot_router"); err == nil {
		t.Fatal("action tool without an approver must be refused")
	}
	if inner.calls != 0 {
		t.Fatalf("refused call must never reach the session, got %d calls", inner.calls)
	}
}

// The human-in-the-loop decides Action tools call by call: a refusal blocks,
// an approval lets exactly that call through.
func TestActionToolFollowsTheApprover(t *testing.T) {
	inner := &countingSession{res: &mcp.CallToolResult{}}
	verdict := errors.New("human said no")
	p := Wrap(inner, Grants{"reboot_router": Action},
		WithLogf(t.Logf),
		WithApprover(func(context.Context, *mcp.CallToolParams) error { return verdict }))

	if _, err := call(t, p, "reboot_router"); !errors.Is(err, verdict) {
		t.Fatalf("refusal must carry the approver's verdict, got: %v", err)
	}
	if inner.calls != 0 {
		t.Fatalf("refused call must never reach the session, got %d calls", inner.calls)
	}

	// The human approves the next one.
	p2 := Wrap(inner, Grants{"reboot_router": Action},
		WithLogf(t.Logf),
		WithApprover(func(context.Context, *mcp.CallToolParams) error { return nil }))
	if _, err := call(t, p2, "reboot_router"); err != nil {
		t.Fatalf("approved action must pass, got: %v", err)
	}
	if inner.calls != 1 {
		t.Fatalf("approved call should reach the session exactly once, got %d", inner.calls)
	}
}

// A grant with a capability the policy does not understand fails closed.
func TestUnknownCapabilityFailsClosed(t *testing.T) {
	inner := &countingSession{}
	p := Wrap(inner, Grants{"get_file": Capability("sudo")}, WithLogf(t.Logf))

	if _, err := call(t, p, "get_file"); err == nil {
		t.Fatal("unknown capability must be refused, not guessed at")
	}
	if inner.calls != 0 {
		t.Fatalf("refused call must never reach the session, got %d calls", inner.calls)
	}
}
