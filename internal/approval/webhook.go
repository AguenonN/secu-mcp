package approval

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// webhookMaxReply caps the decision body. A decision is a few fields; a
// megabyte of "decision" is an endpoint misbehaving.
const webhookMaxReply = 1 << 20

// WebhookRequest is what the approval endpoint receives. The endpoint owns
// the human side — a Slack interactive message, a Jira gate, ServiceNow — and
// answers only once a decision exists. The JSON-RPC call is paused for
// exactly that long.
type WebhookRequest struct {
	Tool         string         `json:"tool"`
	Arguments    map[string]any `json:"arguments"`
	ActionDigest string         `json:"action_digest"`
	RequestedAt  time.Time      `json:"requested_at"`
}

// WebhookResponse is what the endpoint answers with.
type WebhookResponse struct {
	Approved   bool   `json:"approved"`
	ApprovedBy string `json:"approved_by"`
	TicketID   string `json:"ticket_id"`
	Reason     string `json:"reason"`
}

// Webhook is the real-time human-in-the-loop approver. Everything that can go
// wrong — timeout, non-200, unreadable body, approved:false — refuses.
type Webhook struct {
	// URL receives one POST per pending action.
	URL string
	// Timeout bounds how long a call stays paused. Zero uses 120s: long
	// enough for a human to press a button, short enough that an unanswered
	// request does not pin the session forever.
	Timeout time.Duration
	// HTTP overrides the client; nil uses http.DefaultClient. The per-request
	// timeout comes from Timeout, not from the client.
	HTTP *http.Client
}

func (w *Webhook) Name() string { return "webhook" }

func (w *Webhook) Approve(ctx context.Context, req Request) (Decision, error) {
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 120 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	body, err := json.Marshal(WebhookRequest{
		Tool:         req.Tool,
		Arguments:    req.Arguments,
		ActionDigest: req.Digest,
		RequestedAt:  time.Now().UTC(),
	})
	if err != nil {
		return Decision{}, fmt.Errorf("encode approval request: %w", err)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
	if err != nil {
		return Decision{}, fmt.Errorf("build approval request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	client := w.HTTP
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(httpReq)
	if err != nil {
		return Decision{}, fmt.Errorf("approval endpoint unreachable (call refused): %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return Decision{}, fmt.Errorf("approval endpoint answered %d (call refused)", resp.StatusCode)
	}
	var dec WebhookResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, webhookMaxReply)).Decode(&dec); err != nil {
		return Decision{}, fmt.Errorf("unreadable approval decision (call refused): %w", err)
	}
	if !dec.Approved {
		reason := dec.Reason
		if reason == "" {
			reason = "no reason given"
		}
		return Decision{}, fmt.Errorf("refused by approval endpoint: %s", reason)
	}
	if dec.ApprovedBy == "" {
		// An approval nobody signed is not an approval; it is an endpoint
		// that rubber-stamps, and the audit trail would record a ghost.
		return Decision{}, fmt.Errorf("approval endpoint approved without approved_by (call refused)")
	}
	return Decision{Approver: "webhook", ApprovedBy: dec.ApprovedBy, TicketID: dec.TicketID}, nil
}
