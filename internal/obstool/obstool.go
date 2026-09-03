// Package obstool holds the tool contracts of the observability bridge, split
// across the read/action line internal/toolpolicy enforces on the client:
//
//	query_metrics      (read)   — run a PromQL query against Prometheus
//	get_active_alerts  (read)   — list firing alerts from Alertmanager
//	annotate_dashboard (action) — write an annotation onto a Grafana dashboard
//
// The two reads touch sensitive data: metric labels and alert text leak
// hostnames, IPs and customer identifiers. The write lands on the dashboards
// an on-call engineer watches during an incident. One server, both halves of
// the risk.
package obstool

// Tool names, as advertised to the agent.
const (
	QueryMetricsTool = "query_metrics"
	ActiveAlertsTool = "get_active_alerts"
	AnnotateTool     = "annotate_dashboard"
)

// Tool descriptions. These reach the model, so they state the security
// contract: an agent told a tool is validated wastes fewer turns finding out.
const (
	QueryMetricsDesc = "Run a PromQL query over a recent time window and return a summarised time series. " +
		"Queries are validated against a cost policy: catch-all matchers and long lookback windows are refused."
	ActiveAlertsDesc = "List the alerts currently firing in Alertmanager, with their severity, summary and age."
	AnnotateDesc     = "Post an annotation onto a Grafana dashboard to mark an incident event on the team's graphs. " +
		"This writes to production dashboards and requires human approval."
)

// QueryMetricsInput is the argument schema for query_metrics.
type QueryMetricsInput struct {
	// Query is the PromQL expression, e.g.
	// sum(rate(http_requests_total{status=~"5.."}[5m])).
	Query string `json:"query" jsonschema:"PromQL expression to evaluate"`
	// Duration is the lookback window, e.g. "15m". Capped by policy.
	Duration string `json:"duration" jsonschema:"lookback window such as 15m or 1h"`
}

// Point is one sample of a series.
type Point struct {
	Timestamp string  `json:"timestamp"`
	Value     float64 `json:"value"`
}

// Series is one labelled time series, already reduced to something a model can
// reason about without drowning in raw samples.
type Series struct {
	Labels  map[string]string `json:"labels"`
	Min     float64           `json:"min"`
	Max     float64           `json:"max"`
	Avg     float64           `json:"avg"`
	Last    float64           `json:"last"`
	Samples []Point           `json:"samples"`
}

// QueryMetricsOutput is the result schema for query_metrics.
type QueryMetricsOutput struct {
	Query string `json:"query"`
	// Window is the resolved lookback actually evaluated (after capping).
	Window string   `json:"window"`
	Series []Series `json:"series"`
	// Summary is a one-line, model-friendly reduction of the whole result.
	Summary string `json:"summary"`
	// Truncated reports that the result hit a policy cap (series or samples).
	Truncated bool `json:"truncated"`
	// Redactions counts values masked by the scrubber before the reply left
	// the bridge. Non-zero means sensitive data was present in the labels.
	Redactions int `json:"redactions"`
}

// ActiveAlertsInput is the argument schema for get_active_alerts.
type ActiveAlertsInput struct {
	// Severity optionally filters on the severity label ("critical",
	// "warning"). Empty returns every firing alert.
	Severity string `json:"severity" jsonschema:"optional severity filter such as critical"`
}

// Alert is one firing alert, flattened for the model.
type Alert struct {
	Name        string            `json:"name"`
	Severity    string            `json:"severity"`
	Summary     string            `json:"summary"`
	Description string            `json:"description"`
	StartsAt    string            `json:"starts_at"`
	Age         string            `json:"age"`
	Labels      map[string]string `json:"labels"`
}

// ActiveAlertsOutput is the result schema for get_active_alerts.
type ActiveAlertsOutput struct {
	Alerts     []Alert `json:"alerts"`
	Count      int     `json:"count"`
	Summary    string  `json:"summary"`
	Redactions int     `json:"redactions"`
}

// AnnotateInput is the argument schema for annotate_dashboard.
type AnnotateInput struct {
	// DashboardUID is the Grafana dashboard to mark, e.g. "api-gateway".
	DashboardUID string `json:"dashboard_uid" jsonschema:"UID of the target Grafana dashboard"`
	// Text is the incident note to display on the graph.
	Text string `json:"text" jsonschema:"incident analysis message to display"`
	// Tags label the annotation, e.g. ["incident","ai-analysis"].
	Tags []string `json:"tags" jsonschema:"tags for the annotation"`
}

// AnnotateOutput is the result schema for annotate_dashboard.
type AnnotateOutput struct {
	Status string `json:"status"`
	ID     int64  `json:"id"`
	// Text is the annotation as written, after the bridge prefixed its
	// provenance marker and scrubbed the message: what landed on the
	// dashboard, not what was asked for.
	Text string `json:"text"`
}
