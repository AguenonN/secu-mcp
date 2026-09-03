// Package testca mints in-memory SPIFFE identities for tests. An SVID is an
// X.509 certificate whose URI SAN is a spiffe:// ID, signed by a trusted CA,
// which is what this package produces: it drives the real identity gate — the
// same tlsconfig authorizers SPIRE feeds in production — without SPIRE.
package testca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/spiffe/go-spiffe/v2/bundle/x509bundle"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/svid/x509svid"
)

// CA is a throwaway certificate authority scoped to one trust domain.
type CA struct {
	td     spiffeid.TrustDomain
	cert   *x509.Certificate
	key    crypto.Signer
	bundle *x509bundle.Bundle
}

// New creates a CA for the given trust domain (e.g. "mcp.lab").
func New(trustDomain string) (*CA, error) {
	td, err := spiffeid.TrustDomainFromString(trustDomain)
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: trustDomain + " test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &CA{
		td:     td,
		cert:   cert,
		key:    key,
		bundle: x509bundle.FromX509Authorities(td, []*x509.Certificate{cert}),
	}, nil
}

// Bundle returns the trust bundle (the CA certificate) peers verify against.
// *x509bundle.Bundle implements x509bundle.Source.
func (c *CA) Bundle() *x509bundle.Bundle { return c.bundle }

// Issue mints an SVID for the given SPIFFE ID (e.g.
// "spiffe://mcp.lab/network-config"), signed by this CA. *x509svid.SVID
// implements x509svid.Source.
func (c *CA) Issue(spiffeID string) (*x509svid.SVID, error) {
	id, err := spiffeid.FromString(spiffeID)
	if err != nil {
		return nil, err
	}
	if !id.MemberOf(c.td) {
		return nil, fmt.Errorf("id %s is not in trust domain %s", id, c.td)
	}
	uri, err := url.Parse(id.String())
	if err != nil {
		return nil, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 62))
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: id.String()},
		URIs:         []*url.URL{uri},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, c.cert, &key.PublicKey, c.key)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &x509svid.SVID{
		ID:           id,
		Certificates: []*x509.Certificate{leaf},
		PrivateKey:   key,
	}, nil
}
