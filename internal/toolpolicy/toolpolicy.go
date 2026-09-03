// Package toolpolicy decides whether a tool call may leave the agent.
//
// The layers below it are fallible: identity proves who the server is, the
// guardrail inspects what it says, and a text filter eventually loses to an
// adaptive attacker. This one assumes the injection lands and limits what a
// fooled model can reach. A model argued into calling drop_table finds the
// agent does not hold the right to call it.
//
// The check runs in the client, before the request leaves the process, so the
// server's answer is irrelevant: the call is never made.
package toolpolicy

import (
	"context"
	"fmt"
	"log"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Session is the part of *mcp.ClientSession the policy needs. It matches
// guardrail.Session so the two middlewares chain in any order.
type Session interface {
	CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error)
}

// Capability classifies what a tool can do to the world.
type Capability string

const (
	// Read observes state and cannot mutate it.
	Read Capability = "read"
	// Action mutates state (write, delete, reboot, spend) and runs only
	// through a human-in-the-loop approval.
	Action Capability = "action"
)

// Grants maps tool name to capability. A tool absent from the map does not
// exist as far as this agent is concerned.
type Grants map[string]Capability

// Approver gates Action tools. Returning nil approves the call. There is no
// way to approve a class of actions: each call is presented individually.
type Approver func(ctx context.Context, params *mcp.CallToolParams) error

// Policy is the middleware. Build one with Wrap; the zero value is unusable.
type Policy struct {
	inner   Session
	grants  Grants
	approve Approver
	logf    func(format string, args ...any)
}

// Option customises a Policy.
type Option func(*Policy)

// WithLogf redirects the audit log (default log.Printf).
func WithLogf(f func(format string, args ...any)) Option {
	return func(p *Policy) { p.logf = f }
}

// WithApprover wires the human-in-the-loop. Without it, Action tools are
// unreachable: a headless agent is read-only by construction.
func WithApprover(a Approver) Option {
	return func(p *Policy) { p.approve = a }
}

// Wrap builds a Policy around inner. Use policy.CallTool wherever
// session.CallTool was used.
func Wrap(inner Session, grants Grants, opts ...Option) *Policy {
	p := &Policy{inner: inner, grants: grants, logf: log.Printf}
	for _, o := range opts {
		o(p)
	}
	return p
}

// CallTool enforces the grant set, then forwards to the wrapped session. A
// refused call does not reach the transport: the inner session is not
// invoked, so no arguments and no credentials leave the agent.
func (p *Policy) CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	capability, ok := p.grants[params.Name]
	if !ok {
		return nil, fmt.Errorf("toolpolicy: %q not in grant set", params.Name)
	}
	switch capability {
	case Read:
	case Action:
		if p.approve == nil {
			return nil, fmt.Errorf("toolpolicy: %q mutates state and no approver is wired", params.Name)
		}
		if err := p.approve(ctx, params); err != nil {
			return nil, fmt.Errorf("toolpolicy: %q refused by approver: %w", params.Name, err)
		}
		p.logf("toolpolicy: %q approved", params.Name)
	default:
		// An unrecognised grant is a misconfiguration; fail closed.
		return nil, fmt.Errorf("toolpolicy: %q has unknown capability %q", params.Name, capability)
	}
	return p.inner.CallTool(ctx, params)
}
