// Package proxy interposes the locks in front of an MCP server not written to
// carry them: a third-party server, vendored or pulled from a registry, whose
// source is not ours to patch. The sidecar owns the network position, so the
// locks hold whatever the server does.
//
//	agent ──mTLS(SPIFFE)──▶ mcp-proxy ──plain HTTP──▶ upstream MCP server
//	                        │                          (127.0.0.1, no route
//	                        │                           from anywhere else)
//	                        ├─ 0. identity   the caller must PROVE its SVID
//	                        ├─ 2. execution  tools/call meets the grant set
//	                        │                and the human approval BEFORE a
//	                        │                packet is forwarded
//	                        └─ 3. data/code  replies are scrubbed and sealed
//	                                         into <untrusted_data id="nonce">
//
// Lock 1 (egress) is absent from this file because a process cannot apply it
// to itself. It lives in the deployment: the upstream binds loopback only, and
// the pod's NetworkPolicy gives it no egress. The proxy is worth what that
// placement is worth.
//
// # What is transformed, and what is not
//
// The proxy speaks JSON-RPC, not Go types. It decodes enough of each message
// to decide and forwards the original bytes, since an upstream may return
// fields this repository has never heard of (_meta, annotations, content types
// from a later spec revision). Only two shapes are rewritten:
//
//	result.content[]  — text blocks are scrubbed, then sealed: this is the
//	                    channel that becomes prompt text.
//	result.tools[]    — filtered to the grant set, so the agent is not told
//	                    about tools it could not call.
//
// result.structuredContent is scrubbed but not sealed. Sealing would destroy
// the typed channel that exists so a host need not re-read data as text; a
// host that stringifies it into a prompt seals it there, as cmd/agent-sre
// does.
//
// # Known scope
//
//   - The JSON-RPC surface is default-deny: tools/call meets grants and
//     approval, resources/read and resources/subscribe meet the URI
//     allowlist, prompts/get meets the prompt allowlist, and any method
//     outside the screened baseline (plus Config.AllowedMethods) is refused.
//     Server-initiated sampling and elicitation are blocked unless enabled.
//   - JSON-RPC batches are refused outright rather than screened element by
//     element. Batching was removed from MCP in 2025-06-18, and screening it
//     would mean a second, rarely exercised authorization path.
//   - The caller is authenticated, the upstream is not: on loopback inside one
//     pod there is no second party to impersonate. Fronting an upstream across
//     a network means giving it an identity and calling ClientHTTP here.
package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcprogue/internal/approval"
	"mcprogue/internal/toolpin"
	"mcprogue/internal/toolpolicy"
)

// Caps. An uncapped chokepoint is a memory bug waiting for the first
// oversized reply.
const (
	defaultMaxRequestBytes = 4 << 20  // 4 MiB of JSON-RPC request
	maxEventBytes          = 16 << 20 // one SSE event
	upstreamHeaderTimeout  = 30 * time.Second
)

// Config is the proxy's policy. Every zero value fails closed: an empty grant
// set refuses every tool, a nil approver refuses every action.
type Config struct {
	// Upstream is the MCP endpoint being fronted, e.g.
	// "http://127.0.0.1:8080/mcp". Every request goes to this exact URL: a
	// sidecar fronts one endpoint, and resolving the caller's path against it
	// would only invent ways to reach a second.
	Upstream string

	// Grants is the allowlist: tool name -> read|action. A tool absent from it
	// does not exist as far as callers are concerned.
	Grants toolpolicy.Grants

	// Approver gates action tools. Nil refuses every action.
	Approver toolpolicy.Approver

	// HideUngrantedTools filters tools/list down to Grants.
	HideUngrantedTools bool

	// HTTP talks to the upstream. Nil uses a streaming-safe default.
	HTTP *http.Client

	// MaxRequestBytes caps an inbound JSON-RPC body. Zero uses the default.
	MaxRequestBytes int64

	// AllowedMethods extends the screened baseline (see methods.go). Every
	// JSON-RPC method outside baseline+AllowedMethods is refused.
	AllowedMethods []string

	// ResourceURIs is the resources/read and resources/subscribe allowlist:
	// glob patterns where '*' matches anything. Empty refuses every resource.
	ResourceURIs []string

	// AllowedPrompts is the prompts/get allowlist by prompt name. Empty
	// refuses every prompt.
	AllowedPrompts []string

	// AllowServerSampling lets the upstream send sampling/createMessage to
	// the client. The zero value blocks it: a fronted server does not get to
	// order the LLM to run completions.
	AllowServerSampling bool

	// AllowServerElicitation likewise for elicitation/create.
	AllowServerElicitation bool

	// ToolLock, when non-nil, pins the upstream's tool schemas. A tool whose
	// name+description+inputSchema hash drifts from the lock is dropped from
	// tools/list and refused on tools/call (ERR_TOOL_SCHEMA_MUTATED).
	ToolLock *toolpin.Lock

	// Logf receives the audit trail. Nil uses log.Printf.
	Logf func(format string, args ...any)
}

// Proxy is an http.Handler. cmd/mcp-proxy puts it behind an mTLS listener
// whose peers must present an SVID.
type Proxy struct {
	cfg      Config
	upstream *url.URL
	http     *http.Client
	logf     func(format string, args ...any)
	methods  map[string]bool

	// quarantine holds tools disabled at run time because their advertised
	// schema mutated away from the pin. Quarantine outlives the tools/list
	// that detected it: the next tools/call is refused too.
	qmu        sync.Mutex
	quarantine map[string]string // tool name -> reason
}

// New validates the configuration and builds the handler.
func New(cfg Config) (*Proxy, error) {
	if strings.TrimSpace(cfg.Upstream) == "" {
		return nil, fmt.Errorf("proxy: no upstream URL: refusing to start a proxy in front of nothing")
	}
	u, err := url.Parse(cfg.Upstream)
	if err != nil {
		return nil, fmt.Errorf("proxy: parse upstream %q: %w", cfg.Upstream, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("proxy: upstream %q must be an absolute URL such as http://127.0.0.1:8080", cfg.Upstream)
	}
	return build(cfg, u)
}

// NewStdio validates a configuration for the stdio transport, where the
// upstream is a subprocess rather than a URL. Everything but the transport is
// the same proxy: same screen, same transform, same locks 2 and 3.
func NewStdio(cfg Config) (*Proxy, error) {
	if strings.TrimSpace(cfg.Upstream) != "" {
		return nil, fmt.Errorf("proxy: stdio mode fronts a subprocess; UPSTREAM_URL must be empty")
	}
	return build(cfg, nil)
}

func build(cfg Config, u *url.URL) (*Proxy, error) {
	if cfg.MaxRequestBytes <= 0 {
		cfg.MaxRequestBytes = defaultMaxRequestBytes
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	client := cfg.HTTP
	if client == nil {
		client = defaultUpstreamClient()
	}
	p := &Proxy{
		cfg:        cfg,
		upstream:   u,
		http:       client,
		logf:       logf,
		methods:    buildMethodSet(cfg.AllowedMethods),
		quarantine: map[string]string{},
	}
	if len(cfg.Grants) == 0 {
		logf("mcp-proxy: WARNING — the grant set is empty, every tools/call will be refused")
	}
	if cfg.Approver == nil {
		logf("mcp-proxy: no approver wired — action tools are unreachable (read-only by construction)")
	}
	if len(cfg.ResourceURIs) == 0 {
		logf("mcp-proxy: no resource URI allowlist — every resources/read will be refused")
	}
	if cfg.ToolLock != nil && cfg.ToolLock.TrustOnFirstUse() {
		logf("mcp-proxy: tool lock file absent — the FIRST tools/list will be pinned as-is; make sure this start is from a trusted state")
	}
	return p, nil
}

// defaultUpstreamClient is built for streaming: no overall timeout, since an
// SSE stream stays open for the session, but a header timeout so a dead
// upstream does not pin a caller. Compression is off so events reach the
// caller as produced rather than in buffer-sized bursts.
func defaultUpstreamClient() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
			ResponseHeaderTimeout: upstreamHeaderTimeout,
			DisableCompression:    true,
			MaxIdleConnsPerHost:   8,
		},
	}
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		p.servePost(w, r)
	case http.MethodGet, http.MethodDelete, http.MethodOptions, http.MethodHead:
		// Neither carries a tools/call, but a GET stream can carry tool
		// results, so it goes through the same rewriting pipe.
		p.forward(w, r, nil)
	default:
		http.Error(w, "mcp-proxy: method not allowed", http.StatusMethodNotAllowed)
	}
}

// servePost is where lock 2 sits. Nothing reaches the upstream except through
// authorize.
func (p *Proxy) servePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, p.cfg.MaxRequestBytes+1))
	if err != nil {
		http.Error(w, "mcp-proxy: read request body", http.StatusBadRequest)
		return
	}
	if int64(len(body)) > p.cfg.MaxRequestBytes {
		p.logf("mcp-proxy: REFUSED oversized request (> %d bytes)", p.cfg.MaxRequestBytes)
		http.Error(w, "mcp-proxy: request too large", http.StatusRequestEntityTooLarge)
		return
	}
	if refused := p.screen(r.Context(), body); refused != nil {
		writeRPCError(w, refused.id, codeRefused, refused.message)
		return
	}
	p.forward(w, r, body)
}

// refusal is a decision not to forward, carrying what to tell the caller.
type refusal struct {
	id      json.RawMessage
	message string
}

// screen decides whether the body may be forwarded. The engine is
// default-deny: a method outside the screened baseline is refused, and the
// screened ones each meet their own allowlist before a packet leaves.
func (p *Proxy) screen(ctx context.Context, body []byte) *refusal {
	kind, req := classify(body)
	switch kind {
	case bodyBatch:
		// A batch can mix a ping with a tools/call, and screening it means
		// splitting and re-joining responses. MCP no longer defines the
		// shape, so refuse it.
		return &refusal{id: nil, message: "mcp-proxy: JSON-RPC batches are not forwarded; " +
			"send one request per message (batching was removed from MCP in 2025-06-18)"}
	case bodyBad:
		// A body the proxy cannot read is a body whose policy it cannot
		// enforce.
		return &refusal{id: nil, message: "mcp-proxy: unreadable JSON-RPC message refused"}
	}

	if req.Method == "" {
		// A response (result/error) to a server-initiated request. It carries
		// no method to authorize; the requests themselves are gated on the
		// way out (blockedServerMethod).
		return nil
	}
	if !p.methods[req.Method] {
		p.logf("mcp-proxy: method %q REFUSED (ERR_METHOD_NOT_ALLOWED), upstream not contacted", req.Method)
		return &refusal{id: req.ID, message: fmt.Sprintf(
			"mcp-proxy: ERR_METHOD_NOT_ALLOWED: %q is not in the proxy's method policy", req.Method)}
	}

	switch req.Method {
	case "tools/call":
		name, args, token, err := callParams(req.Params)
		if err != nil {
			return &refusal{id: req.ID, message: "mcp-proxy: " + err.Error()}
		}
		if reason := p.quarantined(name); reason != "" {
			p.logf("mcp-proxy: tools/call %q REFUSED, tool is quarantined: %s", name, reason)
			return &refusal{id: req.ID, message: "mcp-proxy: " + reason}
		}
		ctx = approval.WithToken(ctx, token)
		if err := p.authorize(ctx, name, args); err != nil {
			p.logf("mcp-proxy: tools/call %q REFUSED, upstream not contacted: %v", name, err)
			return &refusal{id: req.ID, message: err.Error()}
		}
		p.logf("mcp-proxy: tools/call %q authorized, forwarding upstream", name)
	case "resources/read", "resources/subscribe":
		uri, err := paramField(req.Params, "uri")
		if err != nil {
			return &refusal{id: req.ID, message: "mcp-proxy: " + req.Method + ": " + err.Error()}
		}
		if !p.uriAllowed(uri) {
			p.logf("mcp-proxy: %s %q REFUSED (outside the resource allowlist), upstream not contacted", req.Method, uri)
			return &refusal{id: req.ID, message: fmt.Sprintf(
				"mcp-proxy: resource %q is not in the URI allowlist", uri)}
		}
		p.logf("mcp-proxy: %s %q authorized, forwarding upstream", req.Method, uri)
	case "prompts/get":
		name, err := paramField(req.Params, "name")
		if err != nil {
			return &refusal{id: req.ID, message: "mcp-proxy: prompts/get: " + err.Error()}
		}
		if !p.promptAllowed(name) {
			p.logf("mcp-proxy: prompts/get %q REFUSED (outside the prompt allowlist), upstream not contacted", name)
			return &refusal{id: req.ID, message: fmt.Sprintf(
				"mcp-proxy: prompt %q is not in the prompt allowlist", name)}
		}
		p.logf("mcp-proxy: prompts/get %q authorized, forwarding upstream", name)
	}
	return nil
}

func (p *Proxy) promptAllowed(name string) bool {
	for _, allowed := range p.cfg.AllowedPrompts {
		if allowed == name {
			return true
		}
	}
	return false
}

// quarantined reports why a tool is disabled, or "".
func (p *Proxy) quarantined(name string) string {
	p.qmu.Lock()
	defer p.qmu.Unlock()
	return p.quarantine[name]
}

func (p *Proxy) setQuarantine(name, reason string) {
	p.qmu.Lock()
	defer p.qmu.Unlock()
	p.quarantine[name] = reason
}

// gate is the sentinel session the policy forwards to. The proxy carries raw
// bytes rather than decoded results, so the inner session has nothing to do;
// routing the decision through toolpolicy.Policy keeps the refusal logic
// identical to the one cmd/agent-sre runs, and reached records that the policy
// opened the door.
type gate struct{ reached bool }

func (g *gate) CallTool(context.Context, *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	g.reached = true
	return &mcp.CallToolResult{}, nil
}

// authorize runs one call through lock 2. An error means the request must not
// leave this process.
func (p *Proxy) authorize(ctx context.Context, name string, args map[string]any) error {
	g := &gate{}
	policy := toolpolicy.Wrap(g, p.cfg.Grants,
		toolpolicy.WithApprover(p.cfg.Approver),
		toolpolicy.WithLogf(p.logf))

	if _, err := policy.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args}); err != nil {
		return err
	}
	if !g.reached {
		// Unreachable today. It guards the invariant this component exists
		// for: the upstream is reached only through the policy. A refactor
		// that breaks it should fail closed.
		return fmt.Errorf("mcp-proxy: no decision for %q", name)
	}
	return nil
}

// forward relays the request upstream and rewrites what comes back. body is
// nil for methods with no payload.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request, body []byte) {
	out := *p.upstream
	out.RawQuery = r.URL.RawQuery

	var payload io.Reader
	if body != nil {
		payload = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(r.Context(), r.Method, out.String(), payload)
	if err != nil {
		p.fail(w, "build upstream request", err)
		return
	}
	copyHeaders(req.Header, r.Header)
	req.Header.Del("Host")
	if body != nil {
		req.ContentLength = int64(len(body))
	}

	resp, err := p.http.Do(req)
	if err != nil {
		p.fail(w, "upstream unreachable", err)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	// The body is rewritten, so the upstream's declared length is wrong.
	w.Header().Del("Content-Length")

	switch mediaType(resp.Header.Get("Content-Type")) {
	case "text/event-stream":
		w.WriteHeader(resp.StatusCode)
		p.pipeSSE(w, resp.Body)
	case "application/json":
		raw, err := io.ReadAll(resp.Body)
		if err != nil {
			p.fail(w, "read upstream reply", err)
			return
		}
		if method, blocked := p.suppressedServerCall(raw); blocked {
			p.logf("mcp-proxy: SUPPRESSED server-initiated %q from upstream (blocked by policy)", method)
			w.WriteHeader(http.StatusAccepted)
			return
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(p.transform(raw))
	default:
		// Not a protocol message: pass it through rather than guess.
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	}
}

// fail reports an upstream-side problem; the detail goes to the audit log
// rather than to the caller.
func (p *Proxy) fail(w http.ResponseWriter, what string, err error) {
	p.logf("mcp-proxy: %s: %v", what, err)
	http.Error(w, "mcp-proxy: "+what, http.StatusBadGateway)
}

// pipeSSE copies a server-sent event stream, rewriting the JSON-RPC payload of
// each event. Events are forwarded and flushed one at a time: buffering here
// would turn a live feed into a batch job.
func (p *Proxy) pipeSSE(w http.ResponseWriter, body io.Reader) {
	rc := http.NewResponseController(w)
	sc := bufio.NewScanner(body)
	sc.Buffer(make([]byte, 0, 64<<10), maxEventBytes)

	var block []string
	emit := func() {
		if len(block) == 0 {
			return
		}
		_, _ = io.WriteString(w, p.rewriteEvent(block))
		_ = rc.Flush()
		block = block[:0]
	}
	for sc.Scan() {
		line := strings.TrimSuffix(sc.Text(), "\r")
		if line == "" {
			emit()
			continue
		}
		block = append(block, line)
	}
	emit()
	if err := sc.Err(); err != nil {
		p.logf("mcp-proxy: upstream stream ended: %v", err)
	}
}

// rewriteEvent transforms the data field of one SSE event. Other fields are
// preserved verbatim; id: in particular is the upstream's resumption token.
func (p *Proxy) rewriteEvent(lines []string) string {
	var data []string
	var out strings.Builder
	dataAt := -1
	for _, l := range lines {
		if v, ok := cutField(l, "data"); ok {
			if dataAt < 0 {
				dataAt = out.Len()
			}
			data = append(data, v)
			continue
		}
		out.WriteString(l)
		out.WriteByte('\n')
	}
	if dataAt < 0 {
		out.WriteByte('\n')
		return out.String()
	}
	joined := []byte(strings.Join(data, "\n"))
	if method, blocked := p.suppressedServerCall(joined); blocked {
		// The event is replaced by an SSE comment: the stream stays valid,
		// the client never sees the request, and the upstream's pending id
		// simply never gets an answer.
		p.logf("mcp-proxy: SUPPRESSED server-initiated %q from upstream stream (blocked by policy)", method)
		return ": mcp-proxy suppressed a server-initiated " + method + "\n\n"
	}
	payload := p.transform(joined)
	// JSON carries no literal newline, so re-joining the data lines into one
	// loses nothing.
	out.WriteString("data: ")
	out.Write(payload)
	out.WriteString("\n\n")
	return out.String()
}

// hopByHop headers govern one connection and must not be relayed.
var hopByHop = map[string]bool{
	"connection":          true,
	"proxy-connection":    true,
	"keep-alive":          true,
	"proxy-authenticate":  true,
	"proxy-authorization": true,
	"te":                  true,
	"trailer":             true,
	"transfer-encoding":   true,
	"upgrade":             true,
}

func copyHeaders(dst, src http.Header) {
	skip := map[string]bool{}
	for _, v := range src.Values("Connection") {
		for _, name := range strings.Split(v, ",") {
			if name = strings.ToLower(strings.TrimSpace(name)); name != "" {
				skip[name] = true
			}
		}
	}
	for k, vs := range src {
		lk := strings.ToLower(k)
		if hopByHop[lk] || skip[lk] {
			continue
		}
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}

// mediaType strips parameters from a Content-Type ("application/json; charset=utf-8").
func mediaType(v string) string {
	if i := strings.IndexByte(v, ';'); i >= 0 {
		v = v[:i]
	}
	return strings.ToLower(strings.TrimSpace(v))
}

// cutField splits an SSE "name: value" line. Per the grammar, one leading
// space after the colon belongs to the delimiter, not the value.
func cutField(line, name string) (string, bool) {
	if !strings.HasPrefix(line, name) {
		return "", false
	}
	rest := line[len(name):]
	if rest == "" {
		return "", true
	}
	if !strings.HasPrefix(rest, ":") {
		return "", false
	}
	return strings.TrimPrefix(rest[1:], " "), true
}
