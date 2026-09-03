// Command checkout-api is the service the SRE agent investigates: a small
// HTTP API that exposes Prometheus metrics and can be made to fail on demand.
//
// It exists so the incident is real: Prometheus scrapes a rising 5xx rate, the
// recording rule fires, Alertmanager lists it, the agent finds it. Nothing is
// stubbed between the failure and the annotation.
//
//	GET  /            — serve a request (500s at the configured failure rate)
//	GET  /metrics     — Prometheus text exposition
//	POST /break       — start failing (this is the "deployment v2.1.0")
//	POST /heal        — stop failing
//
// break/heal are reachable only from inside the cluster: the service is not
// exposed, and the namespace runs default-deny NetworkPolicies.
package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"mcprogue/internal/labconfig"
)

// counters holds the metric state. The exposition format is a dozen lines, so
// the image stays free of a client library it would use once.
type counters struct {
	mu       sync.Mutex
	byStatus map[string]uint64
	latency  float64 // running sum of seconds, for a rate-able counter
	requests uint64
}

func newCounters() *counters {
	return &counters{byStatus: map[string]uint64{"200": 0, "500": 0}}
}

func (c *counters) record(status string, seconds float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.byStatus[status]++
	c.latency += seconds
	c.requests++
}

func (c *counters) render(job, route string) string {
	c.mu.Lock()
	defer c.mu.Unlock()

	out := "# HELP http_requests_total Total HTTP requests by status.\n" +
		"# TYPE http_requests_total counter\n"
	for _, status := range []string{"200", "500"} {
		out += fmt.Sprintf("http_requests_total{job=%q,route=%q,status=%q} %d\n",
			job, route, status, c.byStatus[status])
	}
	out += "# HELP http_request_duration_seconds_sum Cumulative request latency.\n" +
		"# TYPE http_request_duration_seconds_sum counter\n" +
		fmt.Sprintf("http_request_duration_seconds_sum{job=%q,route=%q} %.6f\n", job, route, c.latency) +
		"# HELP http_request_duration_seconds_count Requests observed for latency.\n" +
		"# TYPE http_request_duration_seconds_count counter\n" +
		fmt.Sprintf("http_request_duration_seconds_count{job=%q,route=%q} %d\n", job, route, c.requests) +
		"# HELP checkout_api_broken Whether the service is in its failing state.\n" +
		"# TYPE checkout_api_broken gauge\n"
	return out
}

func main() {
	addr := labconfig.Env("LISTEN_ADDR", ":8080")
	job := labconfig.Env("JOB_NAME", "checkout-api")
	route := labconfig.Env("ROUTE", "/checkout")

	c := newCounters()
	var broken atomic.Bool
	if labconfig.Env("START_BROKEN", "false") == "true" {
		broken.Store(true)
	}

	// Self-traffic: the lab has no real users, so the service generates its
	// own load. Without it every rate() would be zero and there would be
	// nothing for the agent to look at.
	go func() {
		for range time.Tick(200 * time.Millisecond) {
			status := "200"
			latency := 0.02 + rand.Float64()*0.03
			if broken.Load() && rand.Float64() < 0.35 {
				status, latency = "500", 0.4+rand.Float64()*0.6
			}
			c.record(status, latency)
		}
	}()

	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		body := c.render(job, route)
		state := 0
		if broken.Load() {
			state = 1
		}
		fmt.Fprintf(w, "%scheckout_api_broken{job=%q} %d\n", body, job, state)
	})
	mux.HandleFunc("/break", func(w http.ResponseWriter, _ *http.Request) {
		broken.Store(true)
		log.Printf("checkout-api: BROKEN — serving 500s (simulating deployment v2.1.0)")
		fmt.Fprintln(w, "broken")
	})
	mux.HandleFunc("/heal", func(w http.ResponseWriter, _ *http.Request) {
		broken.Store(false)
		log.Printf("checkout-api: healed")
		fmt.Fprintln(w, "healed")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		start := time.Now()
		if broken.Load() && rand.Float64() < 0.35 {
			c.record("500", time.Since(start).Seconds())
			http.Error(w, "upstream payment provider timed out", http.StatusInternalServerError)
			return
		}
		c.record("200", time.Since(start).Seconds())
		fmt.Fprintln(w, "ok")
	})

	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Printf("checkout-api: listening on %s (job=%s route=%s broken=%v)", addr, job, route, broken.Load())
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("checkout-api: %v", err)
	}
}
