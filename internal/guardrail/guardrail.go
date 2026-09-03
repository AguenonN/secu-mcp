// Package guardrail inspects what a server says, after identity has settled
// who said it. mTLS answers "are you the server I expect?", not "is this
// reply safe to hand to the model?": a poisoned file on a legitimate server
// passes the handshake untouched.
//
// Guard wraps session.CallTool and applies three checks, in order:
//
//  1. schema    — the reply must decode strictly into the tool's declared
//     output type, and the payload must match the expected configuration
//     grammar line by line. Anything else is rejected outright (fail
//     closed): the model never sees a payload the policy cannot parse.
//  2. markers   — lines carrying prompt-injection markers (instructions
//     addressed to the assistant, role tags, chat-template delimiters,
//     URLs in a file that has no business containing one) are neutralized
//     in place before the reply reaches the application context.
//  3. redaction — values of sensitive directives (community strings,
//     passwords, keys) are masked before any downstream processing, so
//     the model cannot leak what it never received.
//
// Rejection is an error; neutralization and redaction are logged. A
// guardrail that silently rewrites data is its own debugging problem.
package guardrail

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"regexp"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcprogue/internal/mcptool"
)

// Session is the part of *mcp.ClientSession the guard needs. Anything with a
// CallTool of this shape can be wrapped, including another Guard.
type Session interface {
	CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error)
}

// Finding records one action the guard took on a reply. Line is 1-based
// within the payload, 0 when the finding is not tied to a line.
type Finding struct {
	Layer  string // "schema" | "marker" | "redaction"
	Line   int
	Detail string
}

// Guard is the client-side inspection middleware. Build one with Wrap; the
// zero value is unusable.
type Guard struct {
	inner   Session
	schema  *Schema
	logf    func(format string, args ...any)
	observe func(Finding)
}

// Option customises a Guard.
type Option func(*Guard)

// WithLogf redirects the guard's audit log (default log.Printf).
func WithLogf(f func(format string, args ...any)) Option {
	return func(g *Guard) { g.logf = f }
}

// WithSchema replaces the payload grammar (default RouterConf).
func WithSchema(s *Schema) Option {
	return func(g *Guard) { g.schema = s }
}

// WithObserver registers a callback invoked for every finding, in addition
// to the log.
func WithObserver(f func(Finding)) Option {
	return func(g *Guard) { g.observe = f }
}

// Wrap builds a Guard around inner. Use guard.CallTool wherever
// session.CallTool was used.
func Wrap(inner Session, opts ...Option) *Guard {
	g := &Guard{inner: inner, schema: RouterConf(), logf: log.Printf}
	for _, o := range opts {
		o(g)
	}
	return g
}

// CallTool forwards the call, then inspects the reply before releasing it. A
// reply failing strict validation is withheld and surfaced as an error; one
// carrying suspicious or sensitive fragments comes back neutralized.
func (g *Guard) CallTool(ctx context.Context, params *mcp.CallToolParams) (*mcp.CallToolResult, error) {
	res, err := g.inner.CallTool(ctx, params)
	if err != nil || res == nil {
		return res, err
	}

	// Tool errors stay visible so the model can self-correct, but an error
	// string carries an injection as well as a file does.
	if res.IsError {
		g.scrubTextBlocks(res)
		return res, nil
	}

	out, err := decodeStrict(res)
	if err != nil {
		return nil, fmt.Errorf("guardrail: reply rejected: %w", err)
	}
	if err := g.schema.Validate(out.Content); err != nil {
		return nil, fmt.Errorf("guardrail: payload rejected by schema: %w", err)
	}

	clean, findings := neutralizeMarkers(out.Content)
	clean, redactions := redactSecrets(clean)
	for _, f := range append(findings, redactions...) {
		g.report(f)
	}

	// Rebuild from the sanitized payload so the structured value and its text
	// mirror cannot disagree. The raw reply is dropped, not patched.
	sanitized := mcptool.GetFileOutput{Content: clean}
	data, err := json.Marshal(sanitized)
	if err != nil {
		return nil, fmt.Errorf("guardrail: re-encode sanitized reply: %w", err)
	}
	return &mcp.CallToolResult{
		Content:           []mcp.Content{&mcp.TextContent{Text: string(data)}},
		StructuredContent: sanitized,
	}, nil
}

func (g *Guard) report(f Finding) {
	g.logf("guardrail: %s line %d: %s", f.Layer, f.Line, f.Detail)
	if g.observe != nil {
		g.observe(f)
	}
}

// scrubTextBlocks applies the marker pass to error results, which are passed
// through rather than re-validated.
func (g *Guard) scrubTextBlocks(res *mcp.CallToolResult) {
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			clean, findings := neutralizeMarkers(tc.Text)
			tc.Text = clean
			for _, f := range findings {
				g.report(f)
			}
		}
	}
}

// decodeStrict extracts the tool's declared output type, decoding with
// unknown fields forbidden. A reply that does not commit to the schema is
// refused rather than read charitably.
func decodeStrict(res *mcp.CallToolResult) (mcptool.GetFileOutput, error) {
	var out mcptool.GetFileOutput
	if res.StructuredContent == nil {
		return out, fmt.Errorf("no structured content (tool %q declares an output schema)", mcptool.ToolName)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		return out, fmt.Errorf("re-encode structured content: %w", err)
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return out, fmt.Errorf("structured content does not match %T: %w", out, err)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Layer 1 — strict syntactic validation
// ---------------------------------------------------------------------------

// Schema is a line grammar for a configuration payload. It is an allowlist:
// what the grammar does not recognise is rejected, never passed through.
type Schema struct {
	// MaxBytes caps the payload size before any parsing happens.
	MaxBytes int
	// Lines are the allowed line shapes. A line is valid iff at least one
	// matches it in full.
	Lines []*regexp.Regexp
}

// RouterConf is the grammar of the lab's router.conf. Comments are legal, and
// the poison payload is made of well-formed comment lines: schema validation
// alone cannot stop the injection, which is what the marker layer is for.
func RouterConf() *Schema {
	return &Schema{
		MaxBytes: 256 << 10,
		Lines: []*regexp.Regexp{
			regexp.MustCompile(`^$`),                                   // blank
			regexp.MustCompile(`^#.*$`),                                // comment
			regexp.MustCompile(`^hostname [A-Za-z0-9._-]+$`),           //
			regexp.MustCompile(`^domain [A-Za-z0-9._-]+$`),             //
			regexp.MustCompile(`^interface [A-Za-z0-9._/-]+$`),         //
			regexp.MustCompile(`^  description .+$`),                   //
			regexp.MustCompile(`^  ip \d{1,3}(\.\d{1,3}){3}/\d{1,2}$`), //
			regexp.MustCompile(`^ntp \d{1,3}(\.\d{1,3}){3}$`),          //
			regexp.MustCompile(`^(snmp-community|password|secret|psk|tacacs-key) [!-~]+$`),
		},
	}
}

// Validate returns the first violation. Offending lines are quoted with %q so
// control characters cannot leak raw into logs or terminals.
func (s *Schema) Validate(payload string) error {
	if payload == "" {
		return fmt.Errorf("empty payload")
	}
	if len(payload) > s.MaxBytes {
		return fmt.Errorf("payload is %d bytes, policy caps it at %d", len(payload), s.MaxBytes)
	}
	directives := 0
	for i, line := range strings.Split(payload, "\n") {
		if bad, ok := firstNonGraphic(line); ok {
			return fmt.Errorf("line %d contains non-printable or format character %q", i+1, bad)
		}
		if !s.lineOK(line) {
			return fmt.Errorf("line %d does not match any allowed directive: %q", i+1, truncate(line, 80))
		}
		if line != "" && !strings.HasPrefix(strings.TrimSpace(line), "#") {
			directives++
		}
	}
	if directives == 0 {
		return fmt.Errorf("payload holds no configuration directives, only comments/blanks")
	}
	return nil
}

func (s *Schema) lineOK(line string) bool {
	for _, re := range s.Lines {
		if re.MatchString(line) {
			return true
		}
	}
	return false
}

// firstNonGraphic reports the first rune that is neither graphic nor a plain
// space, barring ANSI escapes, carriage returns, zero-width and bidi-override
// characters from the payload, comments included.
func firstNonGraphic(line string) (rune, bool) {
	for _, r := range line {
		if r != ' ' && !unicode.IsGraphic(r) {
			return r, true
		}
	}
	return 0, false
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

// ---------------------------------------------------------------------------
// Layer 2 — control-marker neutralization
// ---------------------------------------------------------------------------

// markers are the shapes of an in-band instruction: legal where it sits, but
// addressed to the model rather than to the parser. A matching line is
// replaced whole; a partial edit leaves the sentence reconstructable.
var markers = []struct {
	name string
	re   *regexp.Regexp
}{
	{"assistant-directed instruction", regexp.MustCompile(`(?i)\b(note|instruction|message|reminder)s?\s+(for|to)\s+the\s+(assistant|ai|model|agent|llm)\b`)},
	{"override instruction", regexp.MustCompile(`(?i)\bignore\s+(all\s+)?(previous|prior|above|earlier)\s+(instructions?|rules?|context)\b`)},
	{"role tag", regexp.MustCompile(`(?i)^\s*#?\s*(system|assistant|user|tool)\s*:`)},
	{"chat-template delimiter", regexp.MustCompile(`<\|[a-zA-Z_]+\|>|\[/?INST\]|<<\s*/?SYS\s*>>`)},
	{"embedded URL (egress vector)", regexp.MustCompile(`(?i)\b[a-z][a-z0-9+.-]*://\S+`)},
	{"exfiltration directive", regexp.MustCompile(`(?i)\b(send|post|upload|forward|exfiltrate)\b.{0,40}\b(credential|secret|password|key|token|contents)`)},
}

// neutralizeMarkers replaces each offending line with an inert comment naming
// the marker. Replacing rather than deleting keeps line numbers stable and
// leaves the trace in the payload.
func neutralizeMarkers(payload string) (string, []Finding) {
	var findings []Finding
	lines := strings.Split(payload, "\n")
	for i, line := range lines {
		for _, m := range markers {
			if m.re.MatchString(line) {
				lines[i] = fmt.Sprintf("# [guardrail] line neutralized (control marker: %s)", m.name)
				findings = append(findings, Finding{Layer: "marker", Line: i + 1, Detail: m.name})
				break
			}
		}
	}
	return strings.Join(lines, "\n"), findings
}

// ---------------------------------------------------------------------------
// Layer 3 — egress control / redaction
// ---------------------------------------------------------------------------

// secretDirective matches directives whose value is a credential. The name is
// kept, so downstream still learns a community string exists; the value is
// masked before the payload leaves the guard.
var secretDirective = regexp.MustCompile(`^(\s*)(snmp-community|password|secret|psk|tacacs-key|wpa-passphrase|community|api-key|token)(\s+)\S.*$`)

// redactSecrets masks credential values line by line.
func redactSecrets(payload string) (string, []Finding) {
	var findings []Finding
	lines := strings.Split(payload, "\n")
	for i, line := range lines {
		if m := secretDirective.FindStringSubmatch(line); m != nil {
			lines[i] = m[1] + m[2] + m[3] + "[REDACTED]"
			findings = append(findings, Finding{Layer: "redaction", Line: i + 1, Detail: m[2] + " value masked"})
		}
	}
	return strings.Join(lines, "\n"), findings
}
