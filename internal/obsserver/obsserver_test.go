package obsserver

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcprogue/internal/obsclient"
	"mcprogue/internal/obstool"
)

// backends spins up stand-ins for Prometheus, Alertmanager and Grafana, and
// records what the bridge actually sent them — the point of several tests
// below is precisely that a call never arrives.
type backends struct {
	promCalls    int
	grafanaCalls int
	lastAnnotate map[string]any
	lastQuery    string
}

func newBackends(t *testing.T, alerts string) (*backends, Backends) {
	t.Helper()
	b := &backends{}

	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.promCalls++
		_ = r.ParseForm()
		b.lastQuery = r.FormValue("query")
		now := time.Now().Unix()
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[
		  {"metric":{"job":"checkout-api","instance":"93.184.216.34:8080"},
		   "values":[[%d,"0.1"],[%d,"4.2"],[%d,"3.7"]]}]}}`, now-120, now-60, now)
	}))
	t.Cleanup(prom.Close)

	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, alerts)
	}))
	t.Cleanup(am.Close)

	grafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.grafanaCalls++
		b.lastAnnotate = map[string]any{}
		_ = json.NewDecoder(r.Body).Decode(&b.lastAnnotate)
		fmt.Fprint(w, `{"id":42,"message":"Annotation added"}`)
	}))
	t.Cleanup(grafana.Close)

	return b, Backends{
		Prom:    obsclient.Prometheus{BaseURL: prom.URL, HTTP: prom.Client()},
		Alerts:  obsclient.Alertmanager{BaseURL: am.URL, HTTP: am.Client()},
		Grafana: obsclient.Grafana{BaseURL: grafana.URL, Token: "glsa_test", HTTP: grafana.Client()},
	}
}

const oneFiringAlert = `[{
  "labels":{"alertname":"HighErrorRate","severity":"critical","job":"checkout-api"},
  "annotations":{"summary":"5xx rate above 5% on checkout-api",
                 "description":"failing for customer_id=CUST8891023, ops@example.com paged"},
  "startsAt":"2026-08-29T10:00:00Z",
  "status":{"state":"active"}}]`

func newBridge(t *testing.T, alerts string, mutate func(*Config)) (*Bridge, *mcp.ClientSession, *backends) {
	t.Helper()
	rec, be := newBackends(t, alerts)

	cfg := Config{
		Backends:             be,
		AllowedDashboards:    []string{"api-gateway"},
		AnnotationsPerMinute: 6,
		Logf:                 t.Logf,
	}
	if mutate != nil {
		mutate(&cfg)
	}
	bridge, srv := New(cfg)

	// A real in-memory MCP session, so the tools are exercised through the
	// protocol rather than as bare Go functions.
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(context.Background(), st, nil); err != nil {
		t.Fatalf("connect server: %v", err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil)
	session, err := client.Connect(context.Background(), ct, nil)
	if err != nil {
		t.Fatalf("connect client: %v", err)
	}
	t.Cleanup(func() { session.Close() })
	return bridge, session, rec
}

func callTool(t *testing.T, s *mcp.ClientSession, name string, args any, into any) error {
	t.Helper()
	res, err := s.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		return err
	}
	if res.IsError {
		var sb strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				sb.WriteString(tc.Text)
			}
		}
		return fmt.Errorf("%s", sb.String())
	}
	if into != nil {
		raw, err := json.Marshal(res.StructuredContent)
		if err != nil {
			return err
		}
		return json.Unmarshal(raw, into)
	}
	return nil
}

// The three tools must be advertised under exactly the names the agent grants.
func TestToolsAdvertised(t *testing.T) {
	_, session, _ := newBridge(t, oneFiringAlert, nil)
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatalf("list tools: %v", err)
	}
	got := map[string]bool{}
	for _, tool := range res.Tools {
		got[tool.Name] = true
	}
	for _, want := range []string{obstool.QueryMetricsTool, obstool.ActiveAlertsTool, obstool.AnnotateTool} {
		if !got[want] {
			t.Errorf("tool %q not advertised (got %v)", want, got)
		}
	}
}

// A legitimate query reaches Prometheus and comes back summarised, with the
// public IP in the labels masked on the way out.
func TestQueryMetricsSummarisesAndScrubs(t *testing.T) {
	_, session, rec := newBridge(t, oneFiringAlert, nil)

	var out obstool.QueryMetricsOutput
	if err := callTool(t, session, obstool.QueryMetricsTool, obstool.QueryMetricsInput{
		Query: `sum(rate(http_requests_total{status=~"5.."}[5m]))`, Duration: "15m",
	}, &out); err != nil {
		t.Fatalf("legitimate query must succeed: %v", err)
	}
	if rec.promCalls != 1 {
		t.Fatalf("expected exactly one Prometheus call, got %d", rec.promCalls)
	}
	if len(out.Series) != 1 {
		t.Fatalf("expected one series, got %d", len(out.Series))
	}
	s := out.Series[0]
	if s.Max != 4.2 || s.Last != 3.7 {
		t.Errorf("series not reduced correctly: %+v", s)
	}
	if s.Labels["job"] != "checkout-api" {
		t.Errorf("benign label altered: %q", s.Labels["job"])
	}
	if strings.Contains(s.Labels["instance"], "93.184.216.34") {
		t.Errorf("public IP reached the model: %q", s.Labels["instance"])
	}
	if out.Redactions == 0 {
		t.Error("redaction count should report the masked value")
	}
	if !strings.Contains(out.Summary, "peak") {
		t.Errorf("summary should describe the peak, got %q", out.Summary)
	}
}

// An expensive query is refused by the bridge and never reaches Prometheus.
// That is the property that matters: the backend is protected, not merely
// warned about.
func TestExpensiveQueryNeverReachesPrometheus(t *testing.T) {
	_, session, rec := newBridge(t, oneFiringAlert, nil)

	for _, q := range []string{`{__name__=~".+"}`, `rate(http_requests_total[30d])`} {
		err := callTool(t, session, obstool.QueryMetricsTool,
			obstool.QueryMetricsInput{Query: q, Duration: "15m"}, nil)
		if err == nil {
			t.Errorf("query must be refused: %s", q)
		}
	}
	if rec.promCalls != 0 {
		t.Fatalf("refused queries must not reach Prometheus, got %d calls", rec.promCalls)
	}
}

// Alert text is free-form and routinely quotes the failing request. It gets
// the same scrubbing as metric labels.
func TestActiveAlertsAreScrubbed(t *testing.T) {
	_, session, _ := newBridge(t, oneFiringAlert, nil)

	var out obstool.ActiveAlertsOutput
	if err := callTool(t, session, obstool.ActiveAlertsTool, obstool.ActiveAlertsInput{}, &out); err != nil {
		t.Fatalf("get_active_alerts: %v", err)
	}
	if out.Count != 1 || out.Alerts[0].Name != "HighErrorRate" {
		t.Fatalf("expected the firing alert, got %+v", out)
	}
	desc := out.Alerts[0].Description
	if strings.Contains(desc, "CUST8891023") || strings.Contains(desc, "ops@example.com") {
		t.Errorf("customer data reached the model: %q", desc)
	}
	if out.Redactions < 2 {
		t.Errorf("expected both values reported as redacted, got %d", out.Redactions)
	}
	if !strings.Contains(out.Summary, "critical") {
		t.Errorf("summary should name the severity, got %q", out.Summary)
	}
}

// The severity filter is honoured.
func TestActiveAlertsSeverityFilter(t *testing.T) {
	_, session, _ := newBridge(t, oneFiringAlert, nil)
	var out obstool.ActiveAlertsOutput
	if err := callTool(t, session, obstool.ActiveAlertsTool,
		obstool.ActiveAlertsInput{Severity: "warning"}, &out); err != nil {
		t.Fatalf("get_active_alerts: %v", err)
	}
	if out.Count != 0 {
		t.Fatalf("critical alert must not match a warning filter, got %+v", out.Alerts)
	}
}

// An approved write lands on Grafana, carrying a provenance prefix the caller
// cannot remove and a scrubbed body.
func TestAnnotateWritesWithProvenance(t *testing.T) {
	_, session, rec := newBridge(t, oneFiringAlert, nil)

	var out obstool.AnnotateOutput
	if err := callTool(t, session, obstool.AnnotateTool, obstool.AnnotateInput{
		DashboardUID: "api-gateway",
		Text:         "5xx spike after v2.1.0\nkey: glsa_AbCdEf0123456789xyz",
		Tags:         []string{"incident", "ai-analysis", "bad tag!", strings.Repeat("x", 80)},
	}, &out); err != nil {
		t.Fatalf("approved annotation must succeed: %v", err)
	}
	if out.ID != 42 || out.Status != "created" {
		t.Errorf("unexpected result: %+v", out)
	}
	if !strings.HasPrefix(out.Text, annotationPrefix) {
		t.Errorf("annotation must carry its provenance prefix, got %q", out.Text)
	}
	if strings.Contains(out.Text, "glsa_") {
		t.Errorf("credential written to the dashboard: %q", out.Text)
	}
	if strings.ContainsAny(out.Text, "\n\r") {
		t.Errorf("annotation must be a single line, got %q", out.Text)
	}

	tags, _ := rec.lastAnnotate["tags"].([]any)
	var seen []string
	for _, tg := range tags {
		seen = append(seen, fmt.Sprint(tg))
	}
	joined := strings.Join(seen, ",")
	if !strings.Contains(joined, "mcp-agent") {
		t.Errorf("provenance tag missing: %v", seen)
	}
	if strings.Contains(joined, "bad tag!") || strings.Contains(joined, strings.Repeat("x", 80)) {
		t.Errorf("malformed tags must be dropped: %v", seen)
	}
}

// A dashboard outside the allowlist is refused and Grafana is never called —
// even though the caller got this far, which means human approval had already
// been given for SOME annotation. Approval is not a blank cheque.
func TestAnnotateOutsideAllowlistNeverReachesGrafana(t *testing.T) {
	_, session, rec := newBridge(t, oneFiringAlert, nil)

	err := callTool(t, session, obstool.AnnotateTool, obstool.AnnotateInput{
		DashboardUID: "exec-board", Text: "all systems nominal",
	}, nil)
	if err == nil {
		t.Fatal("annotation outside the allowlist must be refused")
	}
	if !strings.Contains(err.Error(), "allowlist") {
		t.Errorf("refusal should name the allowlist, got: %v", err)
	}
	if rec.grafanaCalls != 0 {
		t.Fatalf("refused write must not reach Grafana, got %d calls", rec.grafanaCalls)
	}
}

// With no allowlist configured the bridge writes nowhere: a half-configured
// deployment is inert, not unrestricted.
func TestEmptyAllowlistFailsClosed(t *testing.T) {
	_, session, rec := newBridge(t, oneFiringAlert, func(c *Config) { c.AllowedDashboards = nil })

	if err := callTool(t, session, obstool.AnnotateTool, obstool.AnnotateInput{
		DashboardUID: "api-gateway", Text: "x",
	}, nil); err == nil {
		t.Fatal("with no allowlist, every annotation must be refused")
	}
	if rec.grafanaCalls != 0 {
		t.Fatalf("no write should have reached Grafana, got %d", rec.grafanaCalls)
	}
}

// The rate limiter caps a runaway loop. Human approval gates the first write;
// this gates the hundredth.
func TestAnnotationRateLimit(t *testing.T) {
	_, session, rec := newBridge(t, oneFiringAlert, func(c *Config) { c.AnnotationsPerMinute = 2 })

	for i := 0; i < 2; i++ {
		if err := callTool(t, session, obstool.AnnotateTool, obstool.AnnotateInput{
			DashboardUID: "api-gateway", Text: fmt.Sprintf("note %d", i),
		}, nil); err != nil {
			t.Fatalf("write %d should be allowed: %v", i, err)
		}
	}
	err := callTool(t, session, obstool.AnnotateTool, obstool.AnnotateInput{
		DashboardUID: "api-gateway", Text: "note 3",
	}, nil)
	if err == nil {
		t.Fatal("third write must be rate limited")
	}
	if !strings.Contains(err.Error(), "rate limit") {
		t.Errorf("refusal should name the rate limit, got: %v", err)
	}
	if rec.grafanaCalls != 2 {
		t.Fatalf("exactly two writes should have reached Grafana, got %d", rec.grafanaCalls)
	}
}

// An empty annotation is refused rather than written as a blank marker.
func TestEmptyAnnotationRefused(t *testing.T) {
	_, session, rec := newBridge(t, oneFiringAlert, nil)
	if err := callTool(t, session, obstool.AnnotateTool, obstool.AnnotateInput{
		DashboardUID: "api-gateway", Text: "   \n\t ",
	}, nil); err == nil {
		t.Fatal("empty annotation must be refused")
	}
	if rec.grafanaCalls != 0 {
		t.Fatalf("no write should have reached Grafana, got %d", rec.grafanaCalls)
	}
}
