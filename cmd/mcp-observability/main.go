// Command mcp-observability is the observability MCP bridge, the production
// counterpart to the lab's network-config server.
//
// It fronts Prometheus, Alertmanager and Grafana behind three MCP tools and is
// the only workload holding the Grafana write credential: the agent gets a
// tool, never a token, so one talked into exfiltrating the API key has nothing
// to exfiltrate.
//
// Two identity decisions, both stricter than the lab's:
//
//	who may call — the listener authorizes exactly the SPIFFE IDs in
//	               AUTHORIZED_CLIENT_IDS, not anyone attested by our SPIRE. A
//	               compromised pod elsewhere holds a valid SVID and still
//	               cannot open this socket.
//	who we are   — the bridge serves its own SVID, so the agent can tell it
//	               from something that answered on the same Service name.
//
// Configuration is by environment and fails closed when unset.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcprogue/internal/identity"
	"mcprogue/internal/labconfig"
	"mcprogue/internal/obsclient"
	"mcprogue/internal/obsserver"
	"mcprogue/internal/promql"
)

func main() {
	ctx := context.Background()

	addr := labconfig.Env("LISTEN_ADDR", ":8443")
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")
	clientIDs := splitList(labconfig.Env("AUTHORIZED_CLIENT_IDS", ""))

	cfg := obsserver.Config{
		Backends: obsserver.Backends{
			Prom: obsclient.Prometheus{
				BaseURL: labconfig.Env("PROMETHEUS_URL", "http://prometheus.monitoring.svc.cluster.local:9090"),
				HTTP:    obsclient.DefaultHTTP(),
			},
			Alerts: obsclient.Alertmanager{
				BaseURL: labconfig.Env("ALERTMANAGER_URL", "http://alertmanager.monitoring.svc.cluster.local:9093"),
				HTTP:    obsclient.DefaultHTTP(),
			},
			Grafana: obsclient.Grafana{
				BaseURL: labconfig.Env("GRAFANA_URL", "http://grafana.monitoring.svc.cluster.local:3000"),
				Token:   os.Getenv("GRAFANA_API_KEY"),
				HTTP:    obsclient.DefaultHTTP(),
			},
		},
		Policy:               promql.Default(),
		AllowedDashboards:    splitList(labconfig.Env("ALLOWED_DASHBOARDS", "")),
		AnnotationsPerMinute: envInt("ANNOTATIONS_PER_MINUTE", 6),
		DefaultWindow:        15 * time.Minute,
	}

	if len(cfg.AllowedDashboards) == 0 {
		log.Printf("obs-bridge: WARNING — ALLOWED_DASHBOARDS is empty, every annotation will be refused")
	}
	if os.Getenv("GRAFANA_API_KEY") == "" {
		log.Printf("obs-bridge: WARNING — no GRAFANA_API_KEY, annotations will fail at the Grafana call")
	}

	_, srv := obsserver.New(cfg)
	handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return srv }, nil)

	src, err := identity.NewSource(ctx, socket)
	if err != nil {
		log.Fatalf("obs-bridge: no workload identity (is the SPIRE agent up and this workload registered?): %v", err)
	}
	defer src.Close()

	// Only the on-call agent may call this bridge, not any attested workload.
	authorizer, err := identity.OnlyIDs(clientIDs...)
	if err != nil {
		log.Fatalf("obs-bridge: %v", err)
	}

	httpSrv := &http.Server{
		Addr:              addr,
		Handler:           handler,
		TLSConfig:         src.ServerTLS(authorizer),
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("obs-bridge: serving %s, %s, %s over mTLS on %s",
		"query_metrics", "get_active_alerts", "annotate_dashboard", addr)
	log.Printf("obs-bridge: authorized callers: %s", strings.Join(clientIDs, ", "))
	log.Printf("obs-bridge: annotation allowlist: %v (max %d/min)",
		cfg.AllowedDashboards, cfg.AnnotationsPerMinute)

	if err := httpSrv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("obs-bridge: %v", err)
	}
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func envInt(key string, def int) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 0 {
		log.Printf("obs-bridge: %s=%q is not a non-negative integer, using %d", key, v, def)
		return def
	}
	return n
}
