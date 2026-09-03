package promql

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// The queries an SRE agent legitimately needs must pass. A cost policy that
// blocks real incident work gets turned off, and then protects nothing.
func TestLegitimateQueriesPass(t *testing.T) {
	p := Default()
	for _, q := range []string{
		`sum(rate(http_requests_total{status=~"5.."}[5m]))`,
		`sum(rate(http_requests_total{job="checkout-api",status=~"5.."}[5m])) / sum(rate(http_requests_total{job="checkout-api"}[5m]))`,
		`histogram_quantile(0.99, sum(rate(http_request_duration_seconds_bucket[5m])) by (le))`,
		`node_memory_MemAvailable_bytes / node_memory_MemTotal_bytes`,
		`up{job="checkout-api"} == 0`,
		`topk(5, sum by (route) (rate(http_requests_total{status=~"5.."}[15m])))`,
		`increase(http_requests_total{status="500"}[1h])`,
		`avg_over_time(checkout_api_broken[30m])`,
	} {
		if err := p.Validate(q); err != nil {
			t.Errorf("legitimate query refused:\n  %s\n  %v", q, err)
		}
	}
}

// The refusals that matter: expressions that would hurt Prometheus, and
// expressions carrying characters that have no business in PromQL.
func TestExpensiveOrHostileQueriesAreRefused(t *testing.T) {
	p := Default()
	for name, q := range map[string]string{
		"catch-all on __name__":   `{__name__=~".+"}`,
		"regex on __name__":       `count({__name__=~"http_.*"})`,
		"catch-all label matcher": `http_requests_total{job=~".*"}`,
		"empty regex matcher":     `http_requests_total{job=~""}`,
		"month-long window":       `rate(http_requests_total[30d])`,
		"huge offset":             `http_requests_total offset 90d`,
		"no metric named":         `{job="checkout-api"}`,
		"labels-only selector":    `sum({job=~"check.+"})`,
		"newline injected":        "http_requests_total\n&admin=1",
		"control character":       "http_requests_total{job=\"a\x00b\"}",
		"unicode homoglyph":       `http_requests_totaｌ`,
		"unbalanced parens":       `sum(rate(http_requests_total[5m])`,
		"unterminated string":     `http_requests_total{job="checkout`,
		"invalid regex":           `http_requests_total{job=~"(unclosed"}`,
		"wildcard soup":           `http_requests_total{route=~".*a.*b.*c.*"}`,
		"nested quantifier":       `http_requests_total{route=~"(a+)+b"}`,
		"empty":                   ``,
	} {
		err := p.Validate(q)
		if err == nil {
			t.Errorf("%s: must be refused: %s", name, q)
			continue
		}
		var r *Rejection
		if !errors.As(err, &r) {
			t.Errorf("%s: refusal should be a *Rejection, got %T", name, err)
		}
	}
}

// An over-long query is refused before anything else looks at it.
func TestLengthCap(t *testing.T) {
	p := Default()
	q := `http_requests_total{route="` + strings.Repeat("a", p.MaxLen) + `"}`
	if err := p.Validate(q); err == nil {
		t.Fatal("over-long query must be refused")
	}
}

// A label VALUE that happens to look like a metric name must not satisfy the
// "name an explicit metric" requirement — that would reopen the whole-TSDB
// selector through a quoted string.
func TestMetricNameCannotComeFromALabelValue(t *testing.T) {
	if err := Default().Validate(`{job=~"http_requests_total"}`); err == nil {
		t.Fatal("a metric name inside a label value must not count as naming a metric")
	}
}

func TestParseWindow(t *testing.T) {
	p := Default()
	def := 15 * time.Minute

	if got, err := p.ParseWindow("", def); err != nil || got != def {
		t.Fatalf("empty window should fall back to the default, got %v %v", got, err)
	}
	if got, err := p.ParseWindow("1h", def); err != nil || got != time.Hour {
		t.Fatalf("1h should parse, got %v %v", got, err)
	}
	if _, err := p.ParseWindow("7d", def); err == nil {
		t.Fatal("7d exceeds the cap and must be refused")
	}
	for _, bad := range []string{"0m", "-5m", "5", "5 minutes", "5mm"} {
		if _, err := p.ParseWindow(bad, def); err == nil {
			t.Errorf("%q must be refused", bad)
		}
	}
}

// PromQL durations use units Go's time.ParseDuration does not know.
func TestParseDurationUnits(t *testing.T) {
	cases := map[string]time.Duration{
		"500ms": 500 * time.Millisecond,
		"30s":   30 * time.Second,
		"5m":    5 * time.Minute,
		"2h":    2 * time.Hour,
		"1d":    24 * time.Hour,
		"1w":    7 * 24 * time.Hour,
	}
	for in, want := range cases {
		got, err := parseDuration(in)
		if err != nil || got != want {
			t.Errorf("parseDuration(%q) = %v, %v; want %v", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "5", "m", "5x", "1.5h", "5m30s"} {
		if _, err := parseDuration(bad); err == nil {
			t.Errorf("parseDuration(%q) should fail", bad)
		}
	}
}
