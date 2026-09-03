package identity

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"

	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// Verifier abstracts lock 0 away from SPIRE. The lock is "the caller proved
// who it is before the first byte of MCP"; who runs the proof varies by
// deployment:
//
//	SPIFFEVerifier — this process terminates mTLS against a SPIRE-issued
//	                 SVID. The original design; requires a SPIRE agent.
//	MeshVerifier   — an Istio/Envoy sidecar already terminated SPIFFE mTLS
//	                 and asserted the peer in X-Forwarded-Client-Cert. The
//	                 proxy verifies the assertion instead of re-running the
//	                 handshake, and the mesh's AuthorizationPolicy is the
//	                 first line, not a rival.
//	LocalVerifier  — there is no network: stdio to a subprocess, or an
//	                 explicit opt-out. Lock 0 is out of scope by transport,
//	                 which the verifier says out loud rather than simulating.
//
// ServerTLS returning nil means the listener is plain: the transport layer in
// front of this process owns the handshake.
type Verifier interface {
	// Name identifies the mode in logs.
	Name() string
	// ServerTLS is the listener's TLS configuration, nil for a plain
	// listener whose transport (mesh sidecar, OS pipe) owns identity.
	ServerTLS() *tls.Config
	// Peer authenticates one accepted request and returns the caller's
	// identity for the audit trail. An error refuses the request.
	Peer(r *http.Request) (string, error)
	// Close releases any underlying credential source.
	Close() error
}

// ---------------------------------------------------------------------------
// SPIFFE: the proxy holds the handshake.
// ---------------------------------------------------------------------------

// SPIFFEVerifier terminates mTLS with this workload's SVID and admits only
// the authorized peer IDs.
type SPIFFEVerifier struct {
	src        *Source
	authorizer tlsconfig.Authorizer
}

// NewSPIFFEVerifier builds the classic gate: src supplies the SVID and trust
// bundle, ids is the exact caller allowlist (OnlyIDs semantics).
func NewSPIFFEVerifier(src *Source, ids ...string) (*SPIFFEVerifier, error) {
	authorizer, err := OnlyIDs(ids...)
	if err != nil {
		return nil, err
	}
	return &SPIFFEVerifier{src: src, authorizer: authorizer}, nil
}

func (v *SPIFFEVerifier) Name() string { return "spiffe" }

func (v *SPIFFEVerifier) ServerTLS() *tls.Config {
	return v.src.ServerTLS(v.authorizer)
}

// Peer reads the identity the handshake already proved; authorization
// happened in the TLS layer, this is for the audit line.
func (v *SPIFFEVerifier) Peer(r *http.Request) (string, error) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// Unreachable behind our own MTLSServerConfig; guards a refactor
		// that swaps the listener out from under the verifier.
		return "", fmt.Errorf("no client certificate on a connection the SPIFFE verifier expected to have authenticated")
	}
	id, err := x509svid.IDFromCert(r.TLS.PeerCertificates[0])
	if err != nil {
		return "", fmt.Errorf("peer certificate carries no SPIFFE ID: %w", err)
	}
	return id.String(), nil
}

func (v *SPIFFEVerifier) Close() error { return v.src.Close() }

// ---------------------------------------------------------------------------
// Mesh: Envoy holds the handshake, the proxy verifies its assertion.
// ---------------------------------------------------------------------------

// MeshVerifier trusts the service mesh's mTLS and reads the peer SPIFFE ID
// from X-Forwarded-Client-Cert (XFCC). It only makes sense when both are
// true, and neither is checkable from here:
//
//   - the listener is reachable ONLY through the local sidecar (mesh
//     AuthorizationPolicy + no direct pod port), so nobody can inject the
//     header from outside;
//   - the mesh is configured to set XFCC from the verified client cert
//     (Istio: forwardClientCertDetails SANITIZE_SET, its gateway default).
//
// Given those, XFCC is Envoy's signed-in-transport assertion of the caller,
// and this verifier enforces the same exact-ID allowlist OnlyIDs would.
type MeshVerifier struct {
	allowed map[string]bool
}

// NewMeshVerifier builds the XFCC gate. Like OnlyIDs, an empty allowlist is
// a configuration error rather than "allow the mesh's word for anyone".
func NewMeshVerifier(ids ...string) (*MeshVerifier, error) {
	if len(ids) == 0 {
		return nil, fmt.Errorf("mesh identity mode with no authorized SPIFFE ID: refusing to start a server nobody may call")
	}
	allowed := make(map[string]bool, len(ids))
	for _, id := range ids {
		id = strings.TrimSpace(id)
		if !strings.HasPrefix(id, "spiffe://") {
			return nil, fmt.Errorf("authorized ID %q is not a SPIFFE ID", id)
		}
		allowed[id] = true
	}
	return &MeshVerifier{allowed: allowed}, nil
}

func (v *MeshVerifier) Name() string           { return "mesh" }
func (v *MeshVerifier) ServerTLS() *tls.Config { return nil }
func (v *MeshVerifier) Close() error           { return nil }

func (v *MeshVerifier) Peer(r *http.Request) (string, error) {
	xfcc := r.Header.Get("X-Forwarded-Client-Cert")
	if xfcc == "" {
		return "", fmt.Errorf("no X-Forwarded-Client-Cert header: either the mesh sidecar is not in front of this listener, or it is not configured to forward client certificate details")
	}
	id, err := PeerFromXFCC(xfcc)
	if err != nil {
		return "", err
	}
	if !v.allowed[id] {
		return "", fmt.Errorf("mesh-asserted peer %q is not an authorized caller", id)
	}
	return id, nil
}

// PeerFromXFCC extracts the URI SAN of the immediate peer from an Envoy
// X-Forwarded-Client-Cert header. Each hop appends one comma-separated
// element of semicolon-separated key=value pairs, values possibly quoted; the
// last element is the hop closest to this listener, and its URI is the
// SPIFFE ID Envoy verified.
func PeerFromXFCC(header string) (string, error) {
	elements := splitUnquoted(header, ',')
	last := elements[len(elements)-1]
	for _, pair := range splitUnquoted(last, ';') {
		k, val, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		if !strings.EqualFold(strings.TrimSpace(k), "URI") {
			continue
		}
		val = strings.Trim(strings.TrimSpace(val), `"`)
		if !strings.HasPrefix(val, "spiffe://") {
			return "", fmt.Errorf("XFCC URI %q is not a SPIFFE ID", val)
		}
		return val, nil
	}
	return "", fmt.Errorf("XFCC element carries no URI SAN: the mesh verified a certificate without a SPIFFE identity")
}

// splitUnquoted splits on sep outside double quotes, so a quoted Subject
// containing commas or semicolons does not shear the element.
func splitUnquoted(s string, sep byte) []string {
	var out []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			quoted = !quoted
		case sep:
			if !quoted {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	return append(out, s[start:])
}

// ---------------------------------------------------------------------------
// Local: no network, no lock 0.
// ---------------------------------------------------------------------------

// LocalVerifier is the honest absence of network identity: a stdio subprocess
// has no peer to authenticate, the OS process boundary is the identity. It
// exists so a caller cannot end up in this state by accident — constructing
// one is an explicit decision, and every audit line carries the marker.
type LocalVerifier struct{}

func (LocalVerifier) Name() string                       { return "local" }
func (LocalVerifier) ServerTLS() *tls.Config             { return nil }
func (LocalVerifier) Peer(*http.Request) (string, error) { return "local-process", nil }
func (LocalVerifier) Close() error                       { return nil }
