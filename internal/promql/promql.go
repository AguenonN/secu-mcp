// Package promql caps the cost of every expression the bridge forwards to
// Prometheus. The query is written by a model that can be talked into things,
// which makes two risks concrete:
//
//   - Cost. One expression can load every series in the TSDB
//     ({__name__=~".+"}) or walk a month of samples ([30d]), and Prometheus
//     will try. That is a production outage from inside the read path, with
//     no write permission anywhere.
//   - Transport injection. The expression travels as a query parameter, so
//     control characters and newlines are refused rather than encoded.
//
// Not ReDoS. Prometheus matches label regexes with RE2: linear time, no
// catastrophic backtracking, so (a+)+ is not an exponential-blowup vector
// here. Nested quantifiers are still refused, on cost grounds and so the
// guard does not depend on the backend staying RE2 — but the real risks are
// cardinality and window size.
//
// This is a syntactic allowlist over the shapes the SRE agent needs, not a
// PromQL parser. Using prometheus/promql/parser would give a correct AST at
// the price of pulling in prometheus/prometheus. It is stricter than PromQL:
// a rejected query costs the agent a round trip, an accepted expensive one
// costs the on-call team their monitoring.
package promql

import (
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
)

// Policy caps what an expression may ask for. Use Default; the zero value is
// unusable.
type Policy struct {
	// MaxLen caps the raw expression length.
	MaxLen int
	// MaxWindow caps any range selector or lookback, e.g. [5m].
	MaxWindow time.Duration
	// MaxSelectors caps how many series selectors one expression may join.
	MaxSelectors int
	// MaxRegexMatchers caps how many regex label matchers may appear.
	MaxRegexMatchers int
}

// Default leaves room for incident work — rates, quantiles, joins over a few
// selectors — and none for sweeping the TSDB.
func Default() Policy {
	return Policy{
		MaxLen:           1024,
		MaxWindow:        6 * time.Hour,
		MaxSelectors:     8,
		MaxRegexMatchers: 6,
	}
}

// Rejection carries why an expression was refused. It goes back to the agent
// verbatim: the model needs a precise reason to rewrite, and the policy holds
// nothing secret.
type Rejection struct {
	Reason string
	Detail string
}

func (r *Rejection) Error() string {
	if r.Detail == "" {
		return "promql: " + r.Reason
	}
	return fmt.Sprintf("promql: %s (%s)", r.Reason, r.Detail)
}

func reject(reason, detail string) error { return &Rejection{Reason: reason, Detail: detail} }

var (
	// windowRe finds range selectors and offsets: [5m], [1h:30s], offset 1d.
	windowRe = regexp.MustCompile(`\[\s*(\d+)(ms|s|m|h|d|w|y)\s*(?::\s*\d+(?:ms|s|m|h|d|w|y)\s*)?\]`)
	// matcherRe finds label matchers: name<op>"value" with op in = != =~ !~.
	matcherRe = regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)\s*(=~|!~|=|!=)\s*"((?:[^"\\]|\\.)*)"`)
	// selectorRe counts series selectors: a metric name or a `{` group.
	selectorRe = regexp.MustCompile(`\{`)
	// metricNameRe finds bare metric names (identifiers not followed by `(`).
	metricNameRe = regexp.MustCompile(`\b([a-zA-Z_:][a-zA-Z0-9_:]*)\b\s*(\()?`)
	// nestedQuantRe spots (…+)+ / (…*)* shapes inside a regex matcher.
	nestedQuantRe = regexp.MustCompile(`\([^()]*[+*]\s*\)\s*[+*{]`)
	// catchAllRe is a regex matcher that matches everything.
	catchAllRe = regexp.MustCompile(`^\.[*+]$|^\(\?[a-z]*\)\.[*+]$|^$`)
)

// PromQL keywords and functions that are identifiers but not metric names.
var reservedWords = map[string]bool{
	"by": true, "without": true, "on": true, "ignoring": true,
	"group_left": true, "group_right": true, "offset": true, "bool": true,
	"and": true, "or": true, "unless": true, "inf": true, "nan": true,
	"start": true, "end": true, "atan2": true,
}

// Validate checks expr against the policy and returns nil if the bridge may
// forward it to Prometheus. Every refusal is a *Rejection.
func (p Policy) Validate(expr string) error {
	trimmed := strings.TrimSpace(expr)
	if trimmed == "" {
		return reject("empty query", "")
	}
	if len(trimmed) > p.MaxLen {
		return reject("query too long", fmt.Sprintf("%d bytes, policy caps at %d", len(trimmed), p.MaxLen))
	}
	if err := checkCharset(trimmed); err != nil {
		return err
	}
	if err := checkBalanced(trimmed); err != nil {
		return err
	}
	if err := p.checkWindows(trimmed); err != nil {
		return err
	}
	if n := len(selectorRe.FindAllString(trimmed, -1)); n > p.MaxSelectors {
		return reject("too many series selectors",
			fmt.Sprintf("%d, policy caps at %d", n, p.MaxSelectors))
	}
	return p.checkMatchers(trimmed)
}

// checkCharset bars non-printables. Control characters, newlines and
// zero-width or bidi runes are smuggling channels into the query parameter and
// into whatever log or prompt displays the query later.
func checkCharset(expr string) error {
	for i, r := range expr {
		if r == ' ' || r == '\t' {
			continue
		}
		if !unicode.IsGraphic(r) {
			return reject("query contains a non-printable character",
				fmt.Sprintf("offset %d: %q", i, r))
		}
		if r > unicode.MaxASCII {
			return reject("query contains a non-ASCII character",
				fmt.Sprintf("offset %d: %q — PromQL identifiers are ASCII", i, r))
		}
	}
	return nil
}

// checkBalanced rejects unbalanced brackets and quotes. An unbalanced quote is
// the shape of an expression breaking out of its own string context.
func checkBalanced(expr string) error {
	var stack []rune
	inString := false
	var quote rune
	for i, r := range expr {
		if inString {
			switch {
			case r == '\\':
				// Escapes are consumed by the matcher regex later; here we
				// only need to not treat the next quote as a terminator.
			case r == quote:
				inString = false
			}
			continue
		}
		switch r {
		case '"', '\'', '`':
			inString, quote = true, r
		case '(', '[', '{':
			stack = append(stack, r)
		case ')', ']', '}':
			want := map[rune]rune{')': '(', ']': '[', '}': '{'}[r]
			if len(stack) == 0 || stack[len(stack)-1] != want {
				return reject("unbalanced brackets", fmt.Sprintf("unexpected %q at offset %d", r, i))
			}
			stack = stack[:len(stack)-1]
		}
	}
	if inString {
		return reject("unterminated string literal", "")
	}
	if len(stack) != 0 {
		return reject("unbalanced brackets", fmt.Sprintf("%d unclosed", len(stack)))
	}
	return nil
}

// checkWindows caps every range selector. One [30d] on a busy metric pushes
// Prometheus into swap.
func (p Policy) checkWindows(expr string) error {
	for _, m := range windowRe.FindAllStringSubmatch(expr, -1) {
		d, err := parseDuration(m[1] + m[2])
		if err != nil {
			return reject("unparsable range selector", m[0])
		}
		if d > p.MaxWindow {
			return reject("lookback window too large",
				fmt.Sprintf("%s, policy caps at %s", m[0], p.MaxWindow))
		}
	}
	// `offset 30d` moves the evaluation point far back into cold blocks.
	if idx := strings.Index(expr, "offset"); idx >= 0 {
		rest := expr[idx+len("offset"):]
		f := strings.Fields(strings.TrimSpace(rest))
		if len(f) > 0 {
			if d, err := parseDuration(strings.TrimSuffix(f[0], ")")); err == nil && d > p.MaxWindow {
				return reject("offset too large",
					fmt.Sprintf("%s, policy caps at %s", f[0], p.MaxWindow))
			}
		}
	}
	return nil
}

// checkMatchers is the cardinality guard. Regex matchers must additionally
// compile and not be catch-alls.
func (p Policy) checkMatchers(expr string) error {
	matchers := matcherRe.FindAllStringSubmatch(expr, -1)
	regexCount := 0
	nameConstrained := false

	for _, m := range matchers {
		label, op, value := m[1], m[2], m[3]

		if label == "__name__" && (op == "=~" || op == "!~") {
			// A regex on the metric name asks for every series at once.
			return reject("regex matcher on __name__ is not allowed",
				"name the metric explicitly")
		}
		if op == "=" || op == "!=" {
			if label == "__name__" {
				nameConstrained = true
			}
			continue
		}

		regexCount++
		if regexCount > p.MaxRegexMatchers {
			return reject("too many regex matchers",
				fmt.Sprintf("%d, policy caps at %d", regexCount, p.MaxRegexMatchers))
		}
		if catchAllRe.MatchString(value) {
			return reject("catch-all regex matcher",
				fmt.Sprintf(`%s%s"%s" selects every series — constrain it`, label, op, value))
		}
		// Prometheus anchors label regexes, so compile the anchored form:
		// what we validate is what the server will run.
		if _, err := regexp.Compile("^(?:" + value + ")$"); err != nil {
			return reject("invalid regex in label matcher", err.Error())
		}
		if nestedQuantRe.MatchString(value) {
			// RE2 stays linear on these, so this is a cost guard rather than
			// a ReDoS guard — see the package comment.
			return reject("nested quantifier in label matcher",
				fmt.Sprintf(`%q — rewrite without (x+)+ shapes`, value))
		}
		if strings.Count(value, ".*")+strings.Count(value, ".+") > 2 {
			return reject("overly permissive regex",
				fmt.Sprintf(`%q holds too many wildcards`, value))
		}
	}

	// A selector must be anchored on something: either a metric name written
	// literally in the expression, or an explicit __name__ equality. A bare
	// `{job=~"..."}` with no metric name sweeps every metric of that job.
	if !nameConstrained && !hasLiteralMetricName(expr) {
		return reject("query selects no explicit metric",
			"name a metric rather than selecting on labels alone")
	}
	return nil
}

// hasLiteralMetricName reports whether the expression mentions at least one
// identifier used as a metric name — an identifier not immediately followed by
// an opening parenthesis, which would make it a function call.
//
// Label matchers are stripped before the search, so neither a label NAME nor a
// label VALUE can pass for a metric name. Without that, `{job="checkout-api"}`
// would look anchored on the metric `job` and `{job=~"http_requests_total"}`
// on a metric quoted inside a string — both of them whole-database sweeps
// wearing a disguise.
func hasLiteralMetricName(expr string) bool {
	for _, m := range metricNameRe.FindAllStringSubmatch(stripSelectors(expr), -1) {
		if m[2] == "(" || reservedWords[m[1]] {
			continue
		}
		return true
	}
	return false
}

// stripSelectors removes every {...} label-matcher block and every string
// literal, leaving only the expression's skeleton: function calls, operators
// and bare metric names.
func stripSelectors(expr string) string {
	var out strings.Builder
	depth := 0
	inString := false
	var quote rune
	escaped := false

	for _, r := range expr {
		switch {
		case inString:
			if escaped {
				escaped = false
			} else if r == '\\' {
				escaped = true
			} else if r == quote {
				inString = false
			}
		case r == '"' || r == '\'' || r == '`':
			inString, quote = true, r
		case r == '{':
			depth++
		case r == '}':
			if depth > 0 {
				depth--
			}
		case depth == 0:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// parseDuration understands PromQL durations, including the d/w/y units Go's
// time.ParseDuration does not.
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty duration")
	}
	units := []struct {
		suffix string
		mul    time.Duration
	}{
		{"ms", time.Millisecond},
		{"s", time.Second},
		{"m", time.Minute},
		{"h", time.Hour},
		{"d", 24 * time.Hour},
		{"w", 7 * 24 * time.Hour},
		{"y", 365 * 24 * time.Hour},
	}
	for _, u := range units {
		if !strings.HasSuffix(s, u.suffix) {
			continue
		}
		// "ms" must win over "s"; the table is ordered accordingly.
		num := strings.TrimSuffix(s, u.suffix)
		var n int64
		if _, err := fmt.Sscanf(num, "%d", &n); err != nil {
			return 0, fmt.Errorf("parse %q: %w", s, err)
		}
		if num != fmt.Sprintf("%d", n) {
			return 0, fmt.Errorf("parse %q: trailing characters", s)
		}
		return time.Duration(n) * u.mul, nil
	}
	return 0, fmt.Errorf("unknown duration unit in %q", s)
}

// ParseWindow validates a user-supplied lookback ("15m") against the policy
// and returns it. Empty falls back to def.
func (p Policy) ParseWindow(s string, def time.Duration) (time.Duration, error) {
	if strings.TrimSpace(s) == "" {
		return def, nil
	}
	d, err := parseDuration(s)
	if err != nil {
		return 0, reject("invalid duration", err.Error())
	}
	if d <= 0 {
		return 0, reject("duration must be positive", s)
	}
	if d > p.MaxWindow {
		return 0, reject("duration too large",
			fmt.Sprintf("%s, policy caps at %s", s, p.MaxWindow))
	}
	return d, nil
}
