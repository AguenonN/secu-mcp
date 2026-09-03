package triage

import (
	"strings"
	"testing"

	"mcprogue/internal/obstool"
	"mcprogue/internal/promql"
)

func alert(labels map[string]string) obstool.Alert {
	return obstool.Alert{
		Name: "HighErrorRate", Severity: "critical", Age: "4m30s",
		Summary: "5xx rate above 5% on checkout-api", Labels: labels,
	}
}

// The query the agent derives from an alert must itself satisfy the bridge's
// cost policy — otherwise the agent proposes work the bridge will refuse.
func TestDerivedQueryPassesTheCostPolicy(t *testing.T) {
	p := promql.Default()
	for name, labels := range map[string]map[string]string{
		"with job":    {"job": "checkout-api"},
		"no labels":   {},
		"service tag": {"service": "payments-api"},
	} {
		q := Query(alert(labels))
		if err := p.Validate(q); err != nil {
			t.Errorf("%s: derived query %q rejected by the policy: %v", name, q, err)
		}
	}
}

// Alert labels are external data. A job name carrying quotes or braces must
// not be interpolated into the expression: that is PromQL injection, and the
// label is attacker-influenced whenever the alert rule quotes a request.
func TestHostileLabelCannotRewriteTheQuery(t *testing.T) {
	p := promql.Default()
	for _, hostile := range []string{
		`checkout"} or {__name__=~".+`,
		`a"}[30d]) or (rate(x{y="`,
		`x", status=~".*`,
		"multi word name",
	} {
		q := Query(alert(map[string]string{"job": hostile}))
		if strings.Contains(q, hostile) {
			t.Errorf("hostile label was interpolated into the query:\n  label: %s\n  query: %s", hostile, q)
		}
		if err := p.Validate(q); err != nil {
			t.Errorf("query built from a hostile label must still be valid, got %v for %q", err, q)
		}
	}
}

// A rule author can attach the exact query to run; it is used as-is, and the
// bridge validates it like any other.
func TestRuleSuppliedQueryIsPreferred(t *testing.T) {
	q := Query(alert(map[string]string{"job": "checkout-api", "promql": `up{job="checkout-api"} == 0`}))
	if q != `up{job="checkout-api"} == 0` {
		t.Fatalf("the rule's own query should win, got %q", q)
	}
}

// The note must name the alert and quote the observed numbers — that is what
// makes it worth putting on a dashboard.
func TestNoteDescribesTheIncident(t *testing.T) {
	metrics := obstool.QueryMetricsOutput{
		Window: "15m",
		Series: []obstool.Series{{Labels: map[string]string{"job": "checkout-api"}, Max: 4.2, Last: 3.7}},
	}
	note := Note(alert(map[string]string{"job": "checkout-api"}), "sum(rate(x[5m]))", metrics)
	for _, want := range []string{"HighErrorRate", "critical", "4m30s", "checkout-api", "4.200", "3.700"} {
		if !strings.Contains(note, want) {
			t.Errorf("note should mention %q, got:\n%s", want, note)
		}
	}
	if strings.Contains(note, "\n") {
		t.Errorf("note must be a single line, got:\n%q", note)
	}
	// The note is read at a glance on a graph during an incident; stray
	// double spaces and orphaned punctuation make it look machine-broken.
	for _, ugly := range []string{"  ", " .", " ,"} {
		if strings.Contains(note, ugly) {
			t.Errorf("note contains %q:\n%s", ugly, note)
		}
	}
}

// An empty result set must not produce a note that implies numbers were seen.
func TestNoteWithNoSeries(t *testing.T) {
	note := Note(alert(nil), "sum(rate(x[5m]))", obstool.QueryMetricsOutput{Window: "15m"})
	if !strings.Contains(note, "No series matched") {
		t.Fatalf("note should say no data was found, got:\n%s", note)
	}
}

// Triage works the most severe alert first, then the oldest.
func TestPickPrefersSeverityThenAge(t *testing.T) {
	alerts := []obstool.Alert{
		{Name: "DiskWarn", Severity: "warning", StartsAt: "2026-08-29T09:00:00Z"},
		{Name: "ApiDown", Severity: "critical", StartsAt: "2026-08-29T10:00:00Z"},
		{Name: "DbDown", Severity: "critical", StartsAt: "2026-08-29T09:30:00Z"},
	}
	got, ok := Pick(alerts)
	if !ok || got.Name != "DbDown" {
		t.Fatalf("expected the oldest critical alert, got %+v", got)
	}
	if _, ok := Pick(nil); ok {
		t.Fatal("no alerts should report nothing picked")
	}
}

// Tags carry the incident context without ever carrying free text.
func TestTagsAreStructured(t *testing.T) {
	tags := Tags(alert(map[string]string{"job": "checkout-api"}))
	joined := strings.Join(tags, ",")
	for _, want := range []string{"incident", "ai-analysis", "severity:critical", "service:checkout-api"} {
		if !strings.Contains(joined, want) {
			t.Errorf("expected tag %q in %v", want, tags)
		}
	}
}
