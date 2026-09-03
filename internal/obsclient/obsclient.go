// Package obsclient talks to the observability backends the bridge fronts:
// Prometheus (metrics), Alertmanager (firing alerts) and Grafana
// (annotations).
//
// The bridge is the only workload holding the Grafana credential, which is
// why it is a separate workload at all: the agent gets a tool, never a token.
// Everything here runs on the server side of the mTLS gate, so by the time
// these functions run SPIRE has already proven which workload asked.
package obsclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// maxBody caps how much is read from a backend, so an expensive query or a
// misbehaving backend cannot take the bridge down with it.
const maxBody = 8 << 20

// Prometheus queries a Prometheus server.
type Prometheus struct {
	BaseURL string
	HTTP    *http.Client
}

// Alertmanager queries an Alertmanager.
type Alertmanager struct {
	BaseURL string
	HTTP    *http.Client
}

// Grafana writes annotations. Token is the credential the agent never sees.
type Grafana struct {
	BaseURL string
	Token   string
	HTTP    *http.Client
}

// DefaultHTTP is the client used against every backend: short timeouts,
// because an incident-time tool call that hangs is worse than one that fails.
func DefaultHTTP() *http.Client {
	return &http.Client{
		Timeout: 20 * time.Second,
		Transport: &http.Transport{
			MaxIdleConnsPerHost:   4,
			ResponseHeaderTimeout: 15 * time.Second,
		},
	}
}

// ---------------------------------------------------------------------------
// Prometheus
// ---------------------------------------------------------------------------

// RangeSample is one raw sample returned by a range query.
type RangeSample struct {
	At    time.Time
	Value float64
}

// RangeSeries is one labelled series returned by a range query.
type RangeSeries struct {
	Labels  map[string]string
	Samples []RangeSample
}

type promRangeResponse struct {
	Status string `json:"status"`
	Error  string `json:"error"`
	Data   struct {
		ResultType string `json:"resultType"`
		Result     []struct {
			Metric map[string]string `json:"metric"`
			Values [][2]json.RawMessage
		} `json:"result"`
	} `json:"data"`
}

// QueryRange runs a PromQL range query ending now, covering the given window.
// The caller has already validated the expression against the cost policy;
// this function does transport, not judgement.
func (p Prometheus) QueryRange(ctx context.Context, expr string, window time.Duration) ([]RangeSeries, error) {
	end := time.Now()
	start := end.Add(-window)
	step := window / 60
	if step < 15*time.Second {
		step = 15 * time.Second
	}

	form := url.Values{
		"query": {expr},
		"start": {strconv.FormatInt(start.Unix(), 10)},
		"end":   {strconv.FormatInt(end.Unix(), 10)},
		"step":  {strconv.Itoa(int(step.Seconds())) + "s"},
	}
	// POST, so the expression travels in a body rather than in a URL that
	// would be echoed into every access log along the way.
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(p.BaseURL, "/")+"/api/v1/query_range",
		strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("build prometheus request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	body, err := do(p.HTTP, req, "prometheus")
	if err != nil {
		return nil, err
	}

	var pr promRangeResponse
	if err := json.Unmarshal(body, &pr); err != nil {
		return nil, fmt.Errorf("decode prometheus reply: %w", err)
	}
	if pr.Status != "success" {
		return nil, fmt.Errorf("prometheus rejected the query: %s", pr.Error)
	}

	out := make([]RangeSeries, 0, len(pr.Data.Result))
	for _, r := range pr.Data.Result {
		s := RangeSeries{Labels: r.Metric}
		for _, v := range r.Values {
			at, val, err := decodeSample(v)
			if err != nil {
				continue // one unusable sample must not void the series
			}
			s.Samples = append(s.Samples, RangeSample{At: at, Value: val})
		}
		out = append(out, s)
	}
	return out, nil
}

// decodeSample turns Prometheus' [<unix seconds>, "<value>"] pair into typed
// values. The timestamp is a JSON number, the value a JSON string — a shape
// that trips generic decoders, hence the explicit handling.
func decodeSample(v [2]json.RawMessage) (time.Time, float64, error) {
	var ts float64
	if err := json.Unmarshal(v[0], &ts); err != nil {
		return time.Time{}, 0, err
	}
	var raw string
	if err := json.Unmarshal(v[1], &raw); err != nil {
		return time.Time{}, 0, err
	}
	f, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return time.Time{}, 0, err
	}
	return time.Unix(int64(ts), 0).UTC(), f, nil
}

// ---------------------------------------------------------------------------
// Alertmanager
// ---------------------------------------------------------------------------

// FiringAlert is one alert in state firing.
type FiringAlert struct {
	Labels      map[string]string
	Annotations map[string]string
	StartsAt    time.Time
}

type amAlert struct {
	Labels      map[string]string `json:"labels"`
	Annotations map[string]string `json:"annotations"`
	StartsAt    time.Time         `json:"startsAt"`
	Status      struct {
		State string `json:"state"`
	} `json:"status"`
}

// ActiveAlerts lists alerts currently firing. Silenced and inhibited alerts
// are excluded: an alert someone has deliberately silenced is not an incident
// the agent should reopen.
func (a Alertmanager) ActiveAlerts(ctx context.Context) ([]FiringAlert, error) {
	u := strings.TrimRight(a.BaseURL, "/") +
		"/api/v2/alerts?active=true&silenced=false&inhibited=false&unprocessed=false"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, fmt.Errorf("build alertmanager request: %w", err)
	}

	body, err := do(a.HTTP, req, "alertmanager")
	if err != nil {
		return nil, err
	}

	var alerts []amAlert
	if err := json.Unmarshal(body, &alerts); err != nil {
		return nil, fmt.Errorf("decode alertmanager reply: %w", err)
	}

	out := make([]FiringAlert, 0, len(alerts))
	for _, al := range alerts {
		if al.Status.State != "" && al.Status.State != "active" {
			continue
		}
		out = append(out, FiringAlert{
			Labels:      al.Labels,
			Annotations: al.Annotations,
			StartsAt:    al.StartsAt,
		})
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// Grafana
// ---------------------------------------------------------------------------

// Annotation is what gets written onto a dashboard.
type Annotation struct {
	DashboardUID string
	Text         string
	Tags         []string
	At           time.Time
}

// Annotate posts an annotation and returns the id Grafana assigned. This is
// the only write in the whole bridge, and the only call that carries the
// credential.
func (g Grafana) Annotate(ctx context.Context, a Annotation) (int64, error) {
	at := a.At
	if at.IsZero() {
		at = time.Now()
	}
	payload := map[string]any{
		"text": a.Text,
		"tags": a.Tags,
		"time": at.UnixMilli(),
	}
	// Grafana rejects an empty dashboardUID, so an organisation-wide
	// annotation is expressed by simply omitting the field.
	if a.DashboardUID != "" {
		payload["dashboardUID"] = a.DashboardUID
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return 0, fmt.Errorf("encode annotation: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		strings.TrimRight(g.BaseURL, "/")+"/api/annotations", bytes.NewReader(body))
	if err != nil {
		return 0, fmt.Errorf("build grafana request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if g.Token != "" {
		req.Header.Set("Authorization", "Bearer "+g.Token)
	}

	respBody, err := do(g.HTTP, req, "grafana")
	if err != nil {
		return 0, err
	}
	var res struct {
		ID      int64  `json:"id"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return 0, fmt.Errorf("decode grafana reply: %w", err)
	}
	return res.ID, nil
}

// ---------------------------------------------------------------------------

// do executes the request and returns the body, capping the read and turning
// any non-2xx into an error that names the backend but NOT the response body:
// a backend error page can quote the request, credential headers included, and
// that text would otherwise flow straight back to the model.
func do(c *http.Client, req *http.Request, backend string) ([]byte, error) {
	if c == nil {
		c = DefaultHTTP()
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%s unreachable: %w", backend, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("read %s reply: %w", backend, err)
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s refused the call: HTTP %d", backend, resp.StatusCode)
	}
	return body, nil
}
