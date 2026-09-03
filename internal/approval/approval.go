// Package approval turns "human in the loop" from a name into a mechanism.
//
// APPROVED_ACTIONS, the static allowlist, is an approval decided at deploy
// time: honest as a per-target allowlist, misleading as HITL. This package
// defines the dynamic interface — one decision per call, made while the call
// waits — and three implementations:
//
//	Static   — the deploy-time allowlist, kept, under its true name;
//	Webhook  — the call pauses while an external system (Slack button, Jira,
//	           an internal API) answers approved or refused;
//	Token    — the caller carries proof: a short-lived JWT signed by an
//	           authenticated operator, bound to this exact call by digest.
//
// Every decision, approved or refused, lands in a hash-chained audit trail
// (see Audit) recording who approved what, when, under which ticket.
//
// The failure mode is always closed: no approver, no webhook answer, no
// token, an expired token, a token for a different call — all refuse.
package approval

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcprogue/internal/toolpolicy"
)

// Request is one action awaiting a decision.
type Request struct {
	// Tool is the tools/call name.
	Tool string
	// Arguments is the decoded argument object.
	Arguments map[string]any
	// Digest binds a decision to this exact call: sha256 over the tool name
	// and the canonical arguments. See Digest.
	Digest string
	// Token is the caller-supplied proof from _meta.approvalToken, empty when
	// none was sent. Only the Token approver reads it.
	Token string
}

// Decision records who let the call through.
type Decision struct {
	// Approver names the mechanism ("static-allowlist", "webhook", "token").
	Approver string
	// ApprovedBy identifies the human or system that decided.
	ApprovedBy string
	// TicketID references the change/incident record, when the mechanism
	// carries one.
	TicketID string
}

// Approver is the dynamic interface. Approve returns the decision, or an
// error meaning the call must not run. Implementations may block: the
// JSON-RPC request is already paused while this runs.
type Approver interface {
	Name() string
	Approve(ctx context.Context, req Request) (Decision, error)
}

// Digest computes the fingerprint a decision is bound to:
//
//	sha256( tool + "\n" + canonical_json(arguments) )   as lowercase hex
//
// canonical_json is encoding/json's output on the decoded argument object,
// which sorts keys at every level. An operator minting a token computes the
// same digest over the same JSON (cmd/mcp-approve does it).
func Digest(tool string, args map[string]any) string {
	if args == nil {
		args = map[string]any{}
	}
	b, err := json.Marshal(args)
	if err != nil {
		// A decoded JSON object always re-encodes; if it does not, produce a
		// digest nothing can be minted for rather than an empty one anything
		// could match.
		b = []byte(fmt.Sprintf("unencodable:%v", err))
	}
	sum := sha256.Sum256(append(append([]byte(tool), '\n'), b...))
	return hex.EncodeToString(sum[:])
}

// tokenKey carries _meta.approvalToken from the transport layer, which sees
// the raw JSON-RPC, to the Token approver, which does not.
type tokenKey struct{}

// WithToken attaches a caller-supplied approval token to the context.
func WithToken(ctx context.Context, token string) context.Context {
	if token == "" {
		return ctx
	}
	return context.WithValue(ctx, tokenKey{}, token)
}

// TokenFromContext retrieves the token WithToken attached, or "".
func TokenFromContext(ctx context.Context) string {
	s, _ := ctx.Value(tokenKey{}).(string)
	return s
}

// AnyOf approves a call if any configured mechanism approves it. That is what
// alternative approval channels mean: a valid operator token and a webhook
// approval are each sufficient, and requiring both would only teach people to
// script one of them. Refusals from every mechanism are joined so the caller
// learns everything it failed.
func AnyOf(approvers ...Approver) (Approver, error) {
	if len(approvers) == 0 {
		return nil, fmt.Errorf("approval: AnyOf with no approvers would refuse everything silently; pass nil instead")
	}
	if len(approvers) == 1 {
		return approvers[0], nil
	}
	return anyOf(approvers), nil
}

type anyOf []Approver

func (a anyOf) Name() string {
	names := make([]string, len(a))
	for i, ap := range a {
		names[i] = ap.Name()
	}
	b, _ := json.Marshal(names)
	return "any-of" + string(b)
}

func (a anyOf) Approve(ctx context.Context, req Request) (Decision, error) {
	var errs []error
	for _, ap := range a {
		dec, err := ap.Approve(ctx, req)
		if err == nil {
			return dec, nil
		}
		errs = append(errs, fmt.Errorf("%s: %w", ap.Name(), err))
	}
	return Decision{}, errors.Join(errs...)
}

// FromToolPolicy lifts a legacy toolpolicy.Approver — the static
// APPROVED_ACTIONS matcher — into the dynamic interface, under a name that no
// longer pretends a human was there.
func FromToolPolicy(name, approvedBy string, fn toolpolicy.Approver) Approver {
	return &staticApprover{name: name, by: approvedBy, fn: fn}
}

type staticApprover struct {
	name string
	by   string
	fn   toolpolicy.Approver
}

func (s *staticApprover) Name() string { return s.name }

func (s *staticApprover) Approve(ctx context.Context, req Request) (Decision, error) {
	if s.fn == nil {
		return Decision{}, fmt.Errorf("no static approval function wired")
	}
	err := s.fn(ctx, &mcp.CallToolParams{Name: req.Tool, Arguments: any(req.Arguments)})
	if err != nil {
		return Decision{}, err
	}
	return Decision{Approver: s.name, ApprovedBy: s.by}, nil
}

// ToToolPolicy adapts an Approver (plus the audit trail) back into the
// signature internal/toolpolicy consumes, so the proxy's lock 2 is untouched.
// audit may be nil; a is not: with no approver, wire nil into toolpolicy and
// let it refuse actions outright.
func ToToolPolicy(a Approver, audit *Audit, logf func(format string, args ...any)) toolpolicy.Approver {
	return func(ctx context.Context, params *mcp.CallToolParams) error {
		args, _ := params.Arguments.(map[string]any)
		req := Request{
			Tool:      params.Name,
			Arguments: args,
			Digest:    Digest(params.Name, args),
			Token:     TokenFromContext(ctx),
		}
		dec, err := a.Approve(ctx, req)
		entry := Entry{
			Tool:         req.Tool,
			ActionDigest: req.Digest,
			Approver:     a.Name(),
			Decision:     "approved",
			ApprovedBy:   dec.ApprovedBy,
			TicketID:     dec.TicketID,
		}
		if err != nil {
			entry.Decision = "refused"
			entry.Reason = err.Error()
		} else if dec.Approver != "" {
			entry.Approver = dec.Approver
		}
		if aerr := audit.Record(entry); aerr != nil && logf != nil {
			// The action itself is not blocked on audit I/O, but the operator
			// must know the trail has a hole.
			logf("approval: AUDIT WRITE FAILED for %s %s: %v", req.Tool, req.Digest, aerr)
		}
		return err
	}
}
