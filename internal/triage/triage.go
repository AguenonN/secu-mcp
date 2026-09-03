// Package triage turns firing alerts and a metric series into the incident
// note the agent proposes to write.
//
// It is deterministic. A model writes a better sentence, but the sentence is
// not the security-relevant part: the note is derived from data the bridge
// already validated and scrubbed, and its shape is predictable enough to be
// reviewed in the seconds an on-call engineer will give it. Wiring in an LLM
// rewrites this text; it does not change which tools get called.
package triage

import (
	"fmt"
	"strings"
	"time"

	"mcprogue/internal/obstool"
)

// Note composes the annotation text for the given incident. query is the
// PromQL the agent ran, metrics its (already summarised) result.
func Note(alert obstool.Alert, query string, metrics obstool.QueryMetricsOutput) string {
	var b strings.Builder

	name := alert.Name
	if name == "" {
		name = "unnamed alert"
	}
	fmt.Fprintf(&b, "%s", name)
	if alert.Severity != "" {
		fmt.Fprintf(&b, " (%s)", alert.Severity)
	}
	if alert.Age != "" {
		fmt.Fprintf(&b, " firing for %s", alert.Age)
	}
	if svc := serviceOf(alert); svc != "" {
		fmt.Fprintf(&b, " on %s", svc)
	}
	b.WriteString(". ")

	if s := strings.TrimSpace(alert.Summary); s != "" {
		fmt.Fprintf(&b, "%s. ", strings.TrimSuffix(s, "."))
	}

	if len(metrics.Series) > 0 {
		worst := metrics.Series[0]
		for _, s := range metrics.Series[1:] {
			if s.Max > worst.Max {
				worst = s
			}
		}
		fmt.Fprintf(&b, "Observed %s: peak %.3f, now %.3f over %s.",
			shortQuery(query), worst.Max, worst.Last, metrics.Window)
	} else {
		fmt.Fprintf(&b, "No series matched %s over %s.", shortQuery(query), metrics.Window)
	}
	if metrics.Redactions > 0 {
		fmt.Fprintf(&b, " (%d value(s) redacted by the bridge.)", metrics.Redactions)
	}
	return b.String()
}

// Tags are the annotation tags for an incident note.
func Tags(alert obstool.Alert) []string {
	tags := []string{"incident", "ai-analysis"}
	if alert.Severity != "" {
		tags = append(tags, "severity:"+alert.Severity)
	}
	if svc := serviceOf(alert); svc != "" {
		tags = append(tags, "service:"+svc)
	}
	return tags
}

// Query proposes the PromQL to run for an alert. It prefers the query the
// rule author attached to the alert, and otherwise falls back to the generic
// error-rate expression for the alert's service.
//
// The fallback is built from a fixed template with only the service name
// interpolated, and that name is checked against a conservative shape before
// use: the alert's labels are external data, and this is the one place where
// external data would otherwise become executable query text.
func Query(alert obstool.Alert) string {
	if q := strings.TrimSpace(alert.Labels["promql"]); q != "" {
		return q
	}
	svc := serviceOf(alert)
	if !safeLabelValue(svc) {
		svc = ""
	}
	if svc == "" {
		return `sum(rate(http_requests_total{status=~"5.."}[5m]))`
	}
	return fmt.Sprintf(`sum(rate(http_requests_total{job="%s",status=~"5.."}[5m]))`, svc)
}

// safeLabelValue reports whether v can be interpolated into a PromQL label
// matcher without changing the expression's structure: letters, digits and
// the few separators real job names use. Anything else — quotes, braces,
// spaces — is refused rather than escaped.
func safeLabelValue(v string) bool {
	if v == "" || len(v) > 64 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return false
		}
	}
	return true
}

func serviceOf(a obstool.Alert) string {
	for _, k := range []string{"service", "job", "app", "instance"} {
		if v := strings.TrimSpace(a.Labels[k]); v != "" {
			return v
		}
	}
	return ""
}

func shortQuery(q string) string {
	q = strings.Join(strings.Fields(q), " ")
	if len(q) > 60 {
		return q[:60] + "…"
	}
	return q
}

// Pick chooses the alert to work on: highest severity first, then oldest.
func Pick(alerts []obstool.Alert) (obstool.Alert, bool) {
	rank := map[string]int{"critical": 3, "warning": 2, "info": 1}
	best, found := obstool.Alert{}, false
	for _, a := range alerts {
		if !found {
			best, found = a, true
			continue
		}
		if rank[strings.ToLower(a.Severity)] > rank[strings.ToLower(best.Severity)] {
			best = a
			continue
		}
		if rank[strings.ToLower(a.Severity)] == rank[strings.ToLower(best.Severity)] &&
			startedBefore(a, best) {
			best = a
		}
	}
	return best, found
}

func startedBefore(a, b obstool.Alert) bool {
	ta, err1 := time.Parse(time.RFC3339, a.StartsAt)
	tb, err2 := time.Parse(time.RFC3339, b.StartsAt)
	if err1 != nil || err2 != nil {
		return false
	}
	return ta.Before(tb)
}
