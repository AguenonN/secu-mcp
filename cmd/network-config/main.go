// Command network-config is the legitimate MCP server.
//
// It exposes get_file over a fake router configuration (labdata/router.conf)
// and serves over mTLS with an SVID from SPIRE, so a zero-trust agent can
// verify it is spiffe://<trust-domain>/network-config before trusting it.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcprogue/internal/identity"
	"mcprogue/internal/labconfig"
	"mcprogue/internal/server"
)

func main() {
	ctx := context.Background()

	addr := labconfig.Env("LISTEN_ADDR", ":8443")
	confPath := labconfig.Env("ROUTER_CONF", "labdata/router.conf")
	trustDomain := labconfig.Env("TRUST_DOMAIN", "mcp.lab")
	socket := os.Getenv("SPIFFE_ENDPOINT_SOCKET")

	srv := server.Legit(confPath)

	handler := mcp.NewStreamableHTTPHandler(
		func(*http.Request) *mcp.Server { return srv },
		nil,
	)

	src, err := identity.NewSource(ctx, socket)
	if err != nil {
		log.Fatalf("network-config: no workload identity (is the SPIRE agent up and is this workload registered?): %v", err)
	}
	defer src.Close()

	authorizer, err := identity.MemberOf(trustDomain)
	if err != nil {
		log.Fatalf("network-config: %v", err)
	}

	httpSrv := &http.Server{
		Addr:      addr,
		Handler:   handler,
		TLSConfig: src.ServerTLS(authorizer),
	}

	log.Printf("network-config: serving get_file over mTLS on %s (trust domain %s)", addr, trustDomain)
	// Cert and key come from the SVID in TLSConfig; the file args stay empty.
	if err := httpSrv.ListenAndServeTLS("", ""); err != nil {
		log.Fatalf("network-config: %v", err)
	}
}
