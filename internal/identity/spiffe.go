// Package identity is the gate the lab turns on.
//
// In MCP as it stands, an agent trusts a server on the strength of one config
// entry written once and never re-checked at run time. Workload identity
// supplies the missing verification, and the proof is inverted: nothing is
// blocked for being malicious, everything is rejected that is not shown to be
// legitimate. The rogue is refused because it cannot produce an SVID, not
// because it was recognised.
//
// Scope: identity answers "who are you?", which is binary and provable. It
// says nothing about "what are you doing?" — an authenticated server can still
// misbehave, and poisoned content rides in through a legitimate one. That half
// is contained by the other locks, not proven away.
package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/http"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// Mode selects how much the agent verifies the server it is about to trust.
type Mode string

const (
	// ModeNaive reproduces MCP as it ships: the configured endpoint is trusted
	// on sight and never re-verified. Point it at the rogue and the rogue wins.
	ModeNaive Mode = "naive"

	// ModeZeroTrust requires the server to prove it holds the expected SPIFFE
	// identity, before any tool is called.
	ModeZeroTrust Mode = "zerotrust"
)

// Source provides a workload's own SVID and the trust bundle it verifies peers
// against. It is defined over the go-spiffe Source interfaces rather than a
// concrete Workload API client, so the same gate code runs against a live SPIRE
// agent (NewSource) and against an in-memory CA in tests (New).
type Source struct {
	svid   x509svid.Source
	bundle x509bundle.Source
	closer func() error
}

// New builds a Source from any SVID and bundle sources.
func New(svid x509svid.Source, bundle x509bundle.Source) *Source {
	return &Source{svid: svid, bundle: bundle, closer: func() error { return nil }}
}

// NewSource connects to the Workload API. socket is a URI such as
// "unix:///tmp/spire-agent/public/api.sock"; empty uses SPIFFE_ENDPOINT_SOCKET.
//
// A workload not registered in SPIRE gets no SVID, so this is where a rogue
// first fails: it has nothing to serve.
func NewSource(ctx context.Context, socket string) (*Source, error) {
	var opts []workloadapi.X509SourceOption
	if socket != "" {
		opts = append(opts, workloadapi.WithClientOptions(workloadapi.WithAddr(socket)))
	}
	s, err := workloadapi.NewX509Source(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("obtain workload identity from SPIRE: %w", err)
	}
	// *workloadapi.X509Source implements both Source interfaces.
	return &Source{svid: s, bundle: s, closer: s.Close}, nil
}

// Close releases any underlying Workload API stream.
func (s *Source) Close() error { return s.closer() }

// ClientHTTP builds the *http.Client the agent uses in zero-trust mode. The
// handshake completes only if the server presents a valid SVID whose SPIFFE ID
// equals expected, so a server without one fails before any tool call.
func (s *Source) ClientHTTP(expected spiffeid.ID) *http.Client {
	cfg := tlsconfig.MTLSClientConfig(s.svid, s.bundle, tlsconfig.AuthorizeID(expected))
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg}}
}

// ServerTLS builds the tls.Config a server presents: its own SVID, plus the
// authorizer deciding which callers it accepts.
func (s *Source) ServerTLS(authorizer tlsconfig.Authorizer) *tls.Config {
	return tlsconfig.MTLSServerConfig(s.svid, s.bundle, authorizer)
}

// MemberOf authorizes any peer whose SVID belongs to the given trust domain,
// e.g. "mcp.lab".
func MemberOf(trustDomain string) (tlsconfig.Authorizer, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, fmt.Errorf("parse trust domain %q: %w", trustDomain, err)
	}
	return tlsconfig.AuthorizeMemberOf(td), nil
}

// OnlyIDs authorizes exactly the listed SPIFFE IDs and nobody else.
//
// Use this rather than MemberOf wherever the server holds a credential worth
// stealing. MemberOf answers "are you attested by our SPIRE?", which every
// workload in the cluster satisfies, including a compromised one. A server
// that can write to production dashboards needs the narrower answer: "are you
// the one workload allowed to ask me for that?". Least privilege applies to
// callers, not only to permissions.
func OnlyIDs(ids ...string) (tlsconfig.Authorizer, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("no authorized SPIFFE ID given: refusing to start a server nobody may call")
	}
	parsed := make([]spiffeid.ID, 0, len(ids))
	for _, raw := range ids {
		id, err := spiffeid.FromString(raw)
		if err != nil {
			return nil, fmt.Errorf("parse authorized SPIFFE ID %q: %w", raw, err)
		}
		parsed = append(parsed, id)
	}
	return tlsconfig.AuthorizeOneOf(parsed...), nil
}

// NaiveHTTP returns the client an unmodified MCP agent effectively uses: it
// accepts whatever certificate the endpoint presents and verifies no identity.
// This is trust written once and never re-checked, in code.
func NaiveHTTP() *http.Client {
	return &http.Client{
		Transport: &http.Transport{
			// Intentionally insecure: a naive agent knows only that something
			// answered, not which server.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // lab: models the vulnerable baseline
		},
	}
}

// SelfSignedTLS gives the rogue a throwaway certificate so it can speak HTTPS
// like the real server. Anyone can mint one of these; what cannot be minted is
// an SVID the local authority attested. Identity is the unforgeable part, not
// encryption.
func SelfSignedTLS() (*tls.Config, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "totally-network-config-trust-me"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		DNSNames:     []string{"localhost", "rogue", "network-config"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	}, nil
}
