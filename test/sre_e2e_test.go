// This file extends the end-to-end coverage to the observability bridge that
// fronts Prometheus, Alertmanager and Grafana.
//
// The claim is narrower than the lab's. There, the rogue fails because it holds
// no identity. Here every workload holds a valid SVID — that is what a working
// SPIRE deployment means — and the bridge still refuses all but one, because it
// carries a credential that writes to production dashboards. Attestation is
// necessary and not sufficient: the question is not "are you one of ours?" but
// "are you the one workload allowed to ask me this?".
//
// Three scenarios, over real mTLS handshakes and real MCP calls:
//
//	agent-sre  → bridge : authorized, reads telemetry, writes its annotation
//	other pod  → bridge : attested by the same SPIRE, refused at the handshake
//	no identity→ bridge : refused, as in the lab
package e2e

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
	"github.com/spiffe/go-spiffe/v2/spiffeid"

	"mcprogue/internal/identity"
	"mcprogue/internal/obsclient"
	"mcprogue/internal/obsserver"
	"mcprogue/internal/obstool"
	"mcprogue/internal/testca"
	"mcprogue/internal/toolpolicy"
)

const (
	bridgeID   = "spiffe://mcp.lab/obs-bridge"
	sreAgentID = "spiffe://mcp.lab/agent-sre"
	otherPodID = "spiffe://mcp.lab/some-other-workload"
)

// fakeBackends stands up Prometheus, Alertmanager and Grafana, and reports
// whether Grafana was ever written to.
type fakeBackends struct {
	grafanaWrites int
}

func (f *fakeBackends) start(t *testing.T) obsserver.Backends {
	t.Helper()

	prom := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		now := time.Now().Unix()
		fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[
		  {"metric":{"job":"checkout-api"},"values":[[%d,"0.2"],[%d,"5.1"]]}]}}`, now-60, now)
	}))
	t.Cleanup(prom.Close)

	am := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, `[{"labels":{"alertname":"HighErrorRate","severity":"critical","job":"checkout-api"},
		  "annotations":{"summary":"5xx rate above 5%"},
		  "startsAt":"2026-08-29T10:00:00Z","status":{"state":"active"}}]`)
	}))
	t.Cleanup(am.Close)

	grafana := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		f.grafanaWrites++
		fmt.Fprint(w, `{"id":7,"message":"Annotation added"}`)
	}))
	t.Cleanup(grafana.Close)

	return obsserver.Backends{
		Prom:    obsclient.Prometheus{BaseURL: prom.URL, HTTP: prom.Client()},
		Alerts:  obsclient.Alertmanager{BaseURL: am.URL, HTTP: am.Client()},
		Grafana: obsclient.Grafana{BaseURL: grafana.URL, Token: "glsa_secret", HTTP: grafana.Client()},
	}
}

// sreFixtures mints the CA and the three workload identities. Note that ALL of
// them are attested: unlike the rogue in the lab, the "other workload" here is
// a legitimate member of the trust domain.
func sreFixtures(t *testing.T) (bridgeSrc, sreSrc, otherSrc *identity.Source) {
	t.Helper()
	ca, err := testca.New(trustDomain)
	if err != nil {
		t.Fatalf("new CA: %v", err)
	}
	mint := func(id string) *identity.Source {
		svid, err := ca.Issue(id)
		if err != nil {
			t.Fatalf("issue %s: %v", id, err)
		}
		return identity.New(svid, ca.Bundle())
	}
	return mint(bridgeID), mint(sreAgentID), mint(otherPodID)
}

// serveBridge stands the bridge up behind real mTLS, authorizing only the SRE
// agent, and returns its URL.
func serveBridge(t *testing.T, bridgeSrc *identity.Source, be obsserver.Backends) string {
	t.Helper()
	_, srv := obsserver.New(obsserver.Config{
		Backends:             be,
		AllowedDashboards:    []string{"api-gateway"},
		AnnotationsPerMinute: 6,
		Logf:                 t.Logf,
	})
	authorizer, err := identity.OnlyIDs(sreAgentID)
	if err != nil {
		t.Fatalf("authorizer: %v", err)
	}
	return serveMTLS(t, srv, bridgeSrc.ServerTLS(authorizer))
}

// connectSRE opens an MCP session to the bridge as the given workload.
func connectSRE(t *testing.T, endpoint string, src *identity.Source) (*mcp.ClientSession, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), handshakeGrace)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "agent-sre", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: src.ClientHTTP(spiffeid.RequireFromString(bridgeID)),
	}, nil)
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { session.Close() })
	return session, nil
}

func decode(t *testing.T, res *mcp.CallToolResult, into any) {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal reply: %v", err)
	}
	if err := json.Unmarshal(raw, into); err != nil {
		t.Fatalf("decode reply into %T: %v", into, err)
	}
}

// Scenario A — the authorized on-call agent completes a full incident pass:
// it reads the alert, reads the metric, and writes its annotation through the
// human-approved action.
func TestSRE_AuthorizedAgent_CompletesIncidentPass(t *testing.T) {
	be := &fakeBackends{}
	bridgeSrc, sreSrc, _ := sreFixtures(t)
	endpoint := serveBridge(t, bridgeSrc, be.start(t))

	session, err := connectSRE(t, endpoint, sreSrc)
	if err != nil {
		t.Fatalf("the authorized agent must be able to connect: %v", err)
	}

	// The agent runs behind its own execution policy, exactly as in
	// cmd/agent-sre: two reads granted, the write gated on human approval.
	approved := false
	policy := toolpolicy.Wrap(session, toolpolicy.Grants{
		obstool.ActiveAlertsTool: toolpolicy.Read,
		obstool.QueryMetricsTool: toolpolicy.Read,
		obstool.AnnotateTool:     toolpolicy.Action,
	}, toolpolicy.WithLogf(t.Logf),
		toolpolicy.WithApprover(func(context.Context, *mcp.CallToolParams) error {
			approved = true
			return nil
		}))

	ctx := context.Background()

	res, err := policy.CallTool(ctx, &mcp.CallToolParams{
		Name: obstool.ActiveAlertsTool, Arguments: obstool.ActiveAlertsInput{},
	})
	if err != nil {
		t.Fatalf("get_active_alerts: %v", err)
	}
	var alerts obstool.ActiveAlertsOutput
	decode(t, res, &alerts)
	if alerts.Count != 1 || alerts.Alerts[0].Name != "HighErrorRate" {
		t.Fatalf("expected the firing alert, got %+v", alerts)
	}

	res, err = policy.CallTool(ctx, &mcp.CallToolParams{
		Name: obstool.QueryMetricsTool,
		Arguments: obstool.QueryMetricsInput{
			Query:    `sum(rate(http_requests_total{job="checkout-api",status=~"5.."}[5m]))`,
			Duration: "15m",
		},
	})
	if err != nil {
		t.Fatalf("query_metrics: %v", err)
	}
	var metrics obstool.QueryMetricsOutput
	decode(t, res, &metrics)
	if len(metrics.Series) != 1 || metrics.Series[0].Max != 5.1 {
		t.Fatalf("expected the summarised series, got %+v", metrics)
	}

	res, err = policy.CallTool(ctx, &mcp.CallToolParams{
		Name: obstool.AnnotateTool,
		Arguments: obstool.AnnotateInput{
			DashboardUID: "api-gateway",
			Text:         "5xx spike on checkout-api after v2.1.0",
			Tags:         []string{"incident"},
		},
	})
	if err != nil {
		t.Fatalf("annotate_dashboard: %v", err)
	}
	var wrote obstool.AnnotateOutput
	decode(t, res, &wrote)
	if wrote.ID != 7 || !approved {
		t.Fatalf("expected an approved write, got %+v (approved=%v)", wrote, approved)
	}
	if be.grafanaWrites != 1 {
		t.Fatalf("expected exactly one Grafana write, got %d", be.grafanaWrites)
	}
	if !strings.HasPrefix(wrote.Text, "[SRE-Agent]") {
		t.Errorf("the annotation must be marked as machine-written: %q", wrote.Text)
	}
}

// Scenario B — the property the lab could not show. A DIFFERENT pod, attested
// by the same SPIRE and holding a perfectly valid SVID, is refused at the
// handshake: it is not the workload this bridge serves. A container compromised
// elsewhere in the cluster cannot touch the on-call dashboards.
func TestSRE_AttestedButUnauthorizedWorkload_IsRejected(t *testing.T) {
	be := &fakeBackends{}
	bridgeSrc, _, otherSrc := sreFixtures(t)
	endpoint := serveBridge(t, bridgeSrc, be.start(t))

	session, err := connectSRE(t, endpoint, otherSrc)
	if err == nil {
		// If the handshake somehow succeeded, the tool call must still fail;
		// either way nothing may reach Grafana.
		_, callErr := session.CallTool(context.Background(), &mcp.CallToolParams{
			Name:      obstool.AnnotateTool,
			Arguments: obstool.AnnotateInput{DashboardUID: "api-gateway", Text: "x"},
		})
		t.Fatalf("SECURITY FAILURE: an unauthorized workload connected to the bridge (call err: %v)", callErr)
	}
	t.Logf("attested-but-unauthorized workload correctly refused: %v", err)

	if be.grafanaWrites != 0 {
		t.Fatalf("SECURITY FAILURE: %d write(s) reached Grafana", be.grafanaWrites)
	}
}

// Scenario C — a workload with no identity at all, as in the lab: refused
// before any tool runs.
func TestSRE_UnattestedWorkload_IsRejected(t *testing.T) {
	be := &fakeBackends{}
	bridgeSrc, _, _ := sreFixtures(t)
	endpoint := serveBridge(t, bridgeSrc, be.start(t))

	ctx, cancel := context.WithTimeout(context.Background(), handshakeGrace)
	defer cancel()

	client := mcp.NewClient(&mcp.Implementation{Name: "nobody", Version: "0"}, nil)
	if _, err := client.Connect(ctx, &mcp.StreamableClientTransport{
		Endpoint:   endpoint,
		HTTPClient: identity.NaiveHTTP(), // no client certificate at all
	}, nil); err == nil {
		t.Fatal("SECURITY FAILURE: a workload with no SVID reached the bridge")
	}
	if be.grafanaWrites != 0 {
		t.Fatalf("SECURITY FAILURE: %d write(s) reached Grafana", be.grafanaWrites)
	}
}
