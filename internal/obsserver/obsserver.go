// Package obsserver builds the observability MCP bridge: three tools over
// Prometheus, Alertmanager and Grafana. Construction lives here rather than in
// cmd/ so the binary and the tests exercise the same handlers.
//
// The bridge is the trust boundary. Above it is an agent driven by a model
// that can be argued with; below it are production backends and a Grafana
// credential that writes to the dashboards an on-call team depends on. Each
// rule here exists because the caller cannot enforce it on itself:
//
//	reads  — the PromQL cost policy (internal/promql) refuses queries that
//	         would take Prometheus down, and everything leaving the bridge
//	         goes through internal/scrub.
//	writes — annotate_dashboard is confined three ways: a dashboard allowlist,
//	         a provenance prefix no caller can remove, and a rate limit on how
//	         much an approved-but-runaway agent can write.
//
// None of this assumes the agent is hostile, only that something it read can
// make it so.
package obsserver

import (
	"context"
	"fmt"
	"log"
	"math"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcprogue/internal/obsclient"
	"mcprogue/internal/obstool"
	"mcprogue/internal/promql"
	"mcprogue/internal/scrub"
)

// Caps on what one reply may carry. An unbounded reply is an unbounded
// prompt, and ten thousand series make the model's reasoning worse.
const (
	maxSeries       = 20
	maxSamples      = 30
	maxAlerts       = 50
	maxAnnotationCh = 500
	maxTags         = 8
)

// annotationPrefix marks every annotation this bridge writes. Added
// server-side and not suppressible by the caller: whoever reads the dashboard
// must be able to tell a machine wrote it.
const annotationPrefix = "[SRE-Agent]"

// Backends are the three services the bridge fronts.
type Backends struct {
	Prom    obsclient.Prometheus
	Alerts  obsclient.Alertmanager
	Grafana obsclient.Grafana
}

// Config is the bridge's policy.
type Config struct {
	Backends Backends
	// Policy caps PromQL cost. Zero value uses promql.Default().
	Policy promql.Policy
	// AllowedDashboards holds the Grafana dashboard UIDs the bridge may
	// annotate. Empty means none: a misconfigured deployment is inert.
	AllowedDashboards []string
	// AnnotationsPerMinute caps the write rate. Zero disables writes.
	AnnotationsPerMinute int
	// DefaultWindow is the lookback used when the caller names none.
	DefaultWindow time.Duration
	// Logf receives the audit trail. Nil uses log.Printf.
	Logf func(format string, args ...any)
}

// Bridge holds the built server and its mutable rate-limiter state.
type Bridge struct {
	cfg     Config
	allowed map[string]bool
	logf    func(format string, args ...any)

	mu     sync.Mutex
	writes []time.Time
}

// New builds the bridge and its MCP server.
func New(cfg Config) (*Bridge, *mcp.Server) {
	if cfg.Policy.MaxLen == 0 {
		cfg.Policy = promql.Default()
	}
	if cfg.DefaultWindow == 0 {
		cfg.DefaultWindow = 15 * time.Minute
	}
	logf := cfg.Logf
	if logf == nil {
		logf = log.Printf
	}
	b := &Bridge{cfg: cfg, allowed: map[string]bool{}, logf: logf}
	for _, uid := range cfg.AllowedDashboards {
		if uid = strings.TrimSpace(uid); uid != "" {
			b.allowed[uid] = true
		}
	}

	s := mcp.NewServer(&mcp.Implementation{Name: "mcp-obs-bridge", Version: "1.0.0"}, nil)
	mcp.AddTool(s, &mcp.Tool{
		Name:        obstool.QueryMetricsTool,
		Description: obstool.QueryMetricsDesc,
	}, b.queryMetrics)
	mcp.AddTool(s, &mcp.Tool{
		Name:        obstool.ActiveAlertsTool,
		Description: obstool.ActiveAlertsDesc,
	}, b.activeAlerts)
	mcp.AddTool(s, &mcp.Tool{
		Name:        obstool.AnnotateTool,
		Description: obstool.AnnotateDesc,
	}, b.annotate)
	return b, s
}

// ---------------------------------------------------------------------------
// query_metrics — read
// ---------------------------------------------------------------------------

func (b *Bridge) queryMetrics(ctx context.Context, _ *mcp.CallToolRequest, in obstool.QueryMetricsInput) (*mcp.CallToolResult, obstool.QueryMetricsOutput, error) {
	// An expression that would hurt Prometheus never reaches Prometheus. The
	// rejection text goes back so the model can rewrite the query.
	if err := b.cfg.Policy.Validate(in.Query); err != nil {
		b.logf("obs-bridge: query_metrics REFUSED: %v", err)
		return nil, obstool.QueryMetricsOutput{}, err
	}
	window, err := b.cfg.Policy.ParseWindow(in.Duration, b.cfg.DefaultWindow)
	if err != nil {
		b.logf("obs-bridge: query_metrics REFUSED: %v", err)
		return nil, obstool.QueryMetricsOutput{}, err
	}

	raw, err := b.cfg.Backends.Prom.QueryRange(ctx, in.Query, window)
	if err != nil {
		return nil, obstool.QueryMetricsOutput{}, err
	}

	out := obstool.QueryMetricsOutput{Query: in.Query, Window: window.String()}
	if len(raw) > maxSeries {
		raw, out.Truncated = raw[:maxSeries], true
	}

	var findings []scrub.Finding
	for _, s := range raw {
		labels, f := scrub.Labels(s.Labels)
		findings = append(findings, f...)
		series := obstool.Series{Labels: labels}
		series.Min, series.Max, series.Avg, series.Last = reduce(s.Samples)
		samples, truncated := thin(s.Samples, maxSamples)
		out.Truncated = out.Truncated || truncated
		for _, p := range samples {
			series.Samples = append(series.Samples, obstool.Point{
				Timestamp: p.At.Format(time.RFC3339),
				Value:     round(p.Value),
			})
		}
		out.Series = append(out.Series, series)
	}

	out.Redactions = len(findings)
	out.Summary = summarizeSeries(out.Series, window)
	if out.Redactions > 0 {
		b.logf("obs-bridge: query_metrics masked %d sensitive value(s): %s",
			out.Redactions, scrub.Summarize(findings))
	}
	b.logf("obs-bridge: query_metrics ok — %d series over %s", len(out.Series), window)
	return nil, out, nil
}

// reduce computes the shape of a series so the model can judge it without
// every point.
func reduce(samples []obsclient.RangeSample) (min, max, avg, last float64) {
	if len(samples) == 0 {
		return 0, 0, 0, 0
	}
	min, max = math.Inf(1), math.Inf(-1)
	sum := 0.0
	for _, s := range samples {
		if s.Value < min {
			min = s.Value
		}
		if s.Value > max {
			max = s.Value
		}
		sum += s.Value
	}
	return round(min), round(max), round(sum / float64(len(samples))), round(samples[len(samples)-1].Value)
}

// thin downsamples evenly, always keeping the last point: during an incident
// the most recent value is the one that matters.
func thin(samples []obsclient.RangeSample, limit int) ([]obsclient.RangeSample, bool) {
	if len(samples) <= limit {
		return samples, false
	}
	stride := float64(len(samples)-1) / float64(limit-1)
	out := make([]obsclient.RangeSample, 0, limit)
	for i := 0; i < limit; i++ {
		out = append(out, samples[int(math.Round(float64(i)*stride))])
	}
	return out, true
}

func round(f float64) float64 {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return 0
	}
	return math.Round(f*1000) / 1000
}

func summarizeSeries(series []obstool.Series, window time.Duration) string {
	if len(series) == 0 {
		return fmt.Sprintf("no series matched over the last %s", window)
	}
	worst := series[0]
	for _, s := range series[1:] {
		if s.Max > worst.Max {
			worst = s
		}
	}
	return fmt.Sprintf("%d series over %s; highest peak %.3f (last %.3f) on %s",
		len(series), window, worst.Max, worst.Last, labelString(worst.Labels))
}

func labelString(l map[string]string) string {
	if len(l) == 0 {
		return "{}"
	}
	keys := make([]string, 0, len(l))
	for k := range l {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%s=%q", k, l[k]))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

// ---------------------------------------------------------------------------
// get_active_alerts — read
// ---------------------------------------------------------------------------

func (b *Bridge) activeAlerts(ctx context.Context, _ *mcp.CallToolRequest, in obstool.ActiveAlertsInput) (*mcp.CallToolResult, obstool.ActiveAlertsOutput, error) {
	alerts, err := b.cfg.Backends.Alerts.ActiveAlerts(ctx)
	if err != nil {
		return nil, obstool.ActiveAlertsOutput{}, err
	}

	want := strings.ToLower(strings.TrimSpace(in.Severity))
	var out obstool.ActiveAlertsOutput
	var findings []scrub.Finding
	now := time.Now()

	for _, a := range alerts {
		if want != "" && !strings.EqualFold(a.Labels["severity"], want) {
			continue
		}
		if len(out.Alerts) >= maxAlerts {
			break
		}
		// Annotations are free text written by the rule author and routinely
		// quote failing requests, so they get the same scrubbing as labels.
		summary, f1 := scrub.String(a.Annotations["summary"], "alert.summary")
		desc, f2 := scrub.String(a.Annotations["description"], "alert.description")
		labels, f3 := scrub.Labels(a.Labels)
		findings = append(findings, f1...)
		findings = append(findings, f2...)
		findings = append(findings, f3...)

		age := ""
		if !a.StartsAt.IsZero() {
			age = now.Sub(a.StartsAt).Round(time.Second).String()
		}
		out.Alerts = append(out.Alerts, obstool.Alert{
			Name:        labels["alertname"],
			Severity:    labels["severity"],
			Summary:     summary,
			Description: desc,
			StartsAt:    a.StartsAt.UTC().Format(time.RFC3339),
			Age:         age,
			Labels:      labels,
		})
	}

	out.Count = len(out.Alerts)
	out.Redactions = len(findings)
	out.Summary = summarizeAlerts(out.Alerts)
	if out.Redactions > 0 {
		b.logf("obs-bridge: get_active_alerts masked %d sensitive value(s): %s",
			out.Redactions, scrub.Summarize(findings))
	}
	b.logf("obs-bridge: get_active_alerts ok — %d firing", out.Count)
	return nil, out, nil
}

func summarizeAlerts(alerts []obstool.Alert) string {
	if len(alerts) == 0 {
		return "no alerts firing"
	}
	bySeverity := map[string]int{}
	for _, a := range alerts {
		s := a.Severity
		if s == "" {
			s = "unspecified"
		}
		bySeverity[s]++
	}
	keys := make([]string, 0, len(bySeverity))
	for k := range bySeverity {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%d %s", bySeverity[k], k))
	}
	return fmt.Sprintf("%d alert(s) firing: %s — oldest is %s (%s)",
		len(alerts), strings.Join(parts, ", "), alerts[0].Name, alerts[0].Age)
}

// ---------------------------------------------------------------------------
// annotate_dashboard — action
// ---------------------------------------------------------------------------

// tagRe is the allowed shape of a Grafana tag. Anything else is dropped
// rather than sanitised: a tag is a short label, not a payload.
var tagRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9:_.\-]{0,31}$`)

func (b *Bridge) annotate(ctx context.Context, _ *mcp.CallToolRequest, in obstool.AnnotateInput) (*mcp.CallToolResult, obstool.AnnotateOutput, error) {
	uid := strings.TrimSpace(in.DashboardUID)
	if !b.allowed[uid] {
		// The human approved writing an annotation, not writing anywhere.
		err := fmt.Errorf("annotate_dashboard: dashboard %q is not on this bridge's allowlist %v",
			uid, sortedKeys(b.allowed))
		b.logf("obs-bridge: %v", err)
		return nil, obstool.AnnotateOutput{}, err
	}
	if err := b.admitWrite(); err != nil {
		b.logf("obs-bridge: %v", err)
		return nil, obstool.AnnotateOutput{}, err
	}

	text, findings := scrub.String(collapse(in.Text), "annotation.text")
	if text == "" {
		return nil, obstool.AnnotateOutput{}, fmt.Errorf("annotate_dashboard: empty annotation text")
	}
	if len(text) > maxAnnotationCh {
		text = text[:maxAnnotationCh] + "…"
	}
	// Provenance is added server-side, after scrubbing, so no caller can spoof
	// or strip it.
	text = annotationPrefix + " " + text

	tags := []string{"mcp-agent"}
	for _, t := range in.Tags {
		t = strings.TrimSpace(t)
		if len(tags) >= maxTags {
			break
		}
		if tagRe.MatchString(t) && t != "mcp-agent" {
			tags = append(tags, t)
		}
	}

	id, err := b.cfg.Backends.Grafana.Annotate(ctx, obsclient.Annotation{
		DashboardUID: uid,
		Text:         text,
		Tags:         tags,
		At:           time.Now(),
	})
	if err != nil {
		return nil, obstool.AnnotateOutput{}, err
	}

	if len(findings) > 0 {
		b.logf("obs-bridge: annotate_dashboard masked %d value(s) before writing: %s",
			len(findings), scrub.Summarize(findings))
	}
	b.logf("obs-bridge: annotate_dashboard WROTE annotation %d on dashboard %q", id, uid)
	return nil, obstool.AnnotateOutput{Status: "created", ID: id, Text: text}, nil
}

// admitWrite enforces the rate limit. Human approval gates the first write;
// this gates the hundredth, the one a runaway loop produces.
func (b *Bridge) admitWrite() error {
	if b.cfg.AnnotationsPerMinute <= 0 {
		return fmt.Errorf("annotate_dashboard: writes are disabled on this bridge")
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	cutoff := time.Now().Add(-time.Minute)
	kept := b.writes[:0]
	for _, t := range b.writes {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	b.writes = kept
	if len(b.writes) >= b.cfg.AnnotationsPerMinute {
		return fmt.Errorf("annotate_dashboard: rate limit reached (%d annotations/minute)",
			b.cfg.AnnotationsPerMinute)
	}
	b.writes = append(b.writes, time.Now())
	return nil
}

// collapse flattens whitespace and strips control characters. An annotation
// is one line read at a glance during an incident; newlines and escape
// sequences in it are noise at best.
func collapse(s string) string {
	var b strings.Builder
	lastSpace := true
	for _, r := range s {
		switch {
		case r == '\n' || r == '\r' || r == '\t' || r == ' ':
			if !lastSpace {
				b.WriteRune(' ')
				lastSpace = true
			}
		case r < 0x20 || r == 0x7f:
			// drop control characters outright
		default:
			b.WriteRune(r)
			lastSpace = false
		}
	}
	return strings.TrimSpace(b.String())
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
