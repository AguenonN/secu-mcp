// Package labconfig models the agent's trust configuration: the MCP server
// entry, written once and thereafter believed without question. Whoever
// controls Endpoint controls who the agent talks to.
package labconfig

import (
	"encoding/json"
	"os"
)

// Config is what the agent knows about the server before it connects.
type Config struct {
	// Endpoint is where the agent believes the server lives. In naive mode
	// this string is the whole basis of trust.
	Endpoint string `json:"endpoint"`

	// ExpectedSPIFFEID is the identity the server must prove at run time.
	// Ignored in naive mode, enforced in zero-trust mode.
	ExpectedSPIFFEID string `json:"expected_spiffe_id"`

	// WorkloadAPISocket is the SPIRE agent socket the SVID and trust bundle
	// come from. Empty falls back to SPIFFE_ENDPOINT_SOCKET.
	WorkloadAPISocket string `json:"workload_api_socket"`
}

// Load reads config from an optional JSON file, with env defaults so the lab
// runs without one.
func Load(path string) (Config, error) {
	c := Config{
		Endpoint:          Env("MCP_ENDPOINT", "https://localhost:8443"),
		ExpectedSPIFFEID:  Env("MCP_EXPECTED_ID", "spiffe://mcp.lab/network-config"),
		WorkloadAPISocket: os.Getenv("SPIFFE_ENDPOINT_SOCKET"),
	}
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(data, &c); err != nil {
		return c, err
	}
	return c, nil
}

// Env returns the value of key, or def when unset/empty.
func Env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
