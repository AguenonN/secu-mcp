package proxy

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
)

// The stdio transport: mcp-proxy as a CLI wrapper around a local MCP server
// subprocess, the shape Claude Desktop, IDEs and local CLIs use.
//
//	host (stdin/stdout) ──▶ mcp-proxy ──▶ upstream subprocess (pipes)
//
// There is no network layer here, so lock 0 has no handshake to run: the OS
// process boundary is the identity, and the threat model shifts to the
// integrity of the binary being spawned — a registry-pulled server swapped
// underneath the config is this transport's rogue. VerifyBinarySHA256 is that
// check. Locks 2 and 3 are the same code as the HTTP path: same screen, same
// transform.
//
// Framing per the MCP stdio spec: one JSON-RPC message per line, no embedded
// newlines.

// VerifyBinarySHA256 resolves command on PATH and checks its content hash
// against wantHex ("sha256:..." prefix accepted). It returns the resolved
// path so the caller execs exactly what was measured.
func VerifyBinarySHA256(command, wantHex string) (string, error) {
	path, err := exec.LookPath(command)
	if err != nil {
		return "", fmt.Errorf("mcp-proxy: resolve upstream binary %q: %w", command, err)
	}
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("mcp-proxy: open upstream binary: %w", err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("mcp-proxy: hash upstream binary: %w", err)
	}
	got := hex.EncodeToString(h.Sum(nil))
	want := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(wantHex), "sha256:"))
	if got != want {
		return "", fmt.Errorf("mcp-proxy: ERR_UPSTREAM_BINARY_MUTATED: %s hashes to sha256:%s, expected sha256:%s — refusing to spawn", path, got, want)
	}
	return path, nil
}

// ServeStdio spawns argv as the upstream MCP server and bridges the host's
// stdio to it through the locks. wantSHA256, when non-empty, pins the binary;
// empty is allowed but logged, because a wrapper that refuses to run anything
// unhashed is a wrapper nobody adopts — the log line is where the operator
// learns what to pin.
//
// It returns when the host closes stdin, the subprocess exits, or ctx ends.
func (p *Proxy) ServeStdio(ctx context.Context, argv []string, wantSHA256 string) error {
	if len(argv) == 0 {
		return fmt.Errorf("mcp-proxy: stdio mode needs an upstream command to spawn")
	}
	path := argv[0]
	if wantSHA256 != "" {
		var err error
		if path, err = VerifyBinarySHA256(argv[0], wantSHA256); err != nil {
			return err
		}
		p.logf("mcp-proxy: upstream binary %s matches its pinned hash", path)
	} else {
		p.logf("mcp-proxy: WARNING — UPSTREAM_SHA256 not set; the upstream binary is spawned unverified (supply-chain lock disarmed)")
	}

	cmd := exec.CommandContext(ctx, path, argv[1:]...)
	cmd.Stderr = os.Stderr // the server's own diagnostics stay visible
	childIn, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("mcp-proxy: pipe to upstream: %w", err)
	}
	childOut, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("mcp-proxy: pipe from upstream: %w", err)
	}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("mcp-proxy: spawn upstream: %w", err)
	}
	p.logf("mcp-proxy: stdio upstream started: %s (pid %d)", path, cmd.Process.Pid)

	bridgeErr := p.BridgeStdio(ctx, os.Stdin, os.Stdout, childIn, childOut)
	waitErr := cmd.Wait()
	if bridgeErr != nil {
		return bridgeErr
	}
	return waitErr
}

// BridgeStdio is the transport-free core, split out so tests can drive it
// with in-memory pipes. hostIn/hostOut face the MCP host; childIn/childOut
// face the upstream server.
func (p *Proxy) BridgeStdio(ctx context.Context, hostIn io.Reader, hostOut io.Writer, childIn io.WriteCloser, childOut io.Reader) error {
	var outMu sync.Mutex // hostOut: refusals and transformed replies interleave
	var inMu sync.Mutex  // childIn: forwarded requests and policy error replies interleave

	// Two writes rather than append(line, '\n'): line may alias a scanner's
	// internal buffer, and appending into its spare capacity would corrupt
	// the next buffered token.
	writeHost := func(line []byte) {
		outMu.Lock()
		defer outMu.Unlock()
		_, _ = hostOut.Write(line)
		_, _ = io.WriteString(hostOut, "\n")
	}
	writeChild := func(line []byte) {
		inMu.Lock()
		defer inMu.Unlock()
		_, _ = childIn.Write(line)
		_, _ = io.WriteString(childIn, "\n")
	}

	// Upstream → host.
	done := make(chan error, 1)
	go func() {
		sc := bufio.NewScanner(childOut)
		sc.Buffer(make([]byte, 0, 64<<10), maxEventBytes)
		for sc.Scan() {
			line := sc.Bytes()
			if len(strings.TrimSpace(string(line))) == 0 {
				continue
			}
			if method, blocked := p.suppressedServerCall(line); blocked {
				p.logf("mcp-proxy: SUPPRESSED server-initiated %q from stdio upstream (blocked by policy)", method)
				// stdio is bidirectional, so unlike the SSE path the upstream
				// gets a proper refusal instead of a silent timeout.
				if reply := serverCallRefusal(line, method); reply != nil {
					writeChild(reply)
				}
				continue
			}
			writeHost(p.transform(line))
		}
		done <- sc.Err()
	}()

	// Host → upstream.
	sc := bufio.NewScanner(hostIn)
	sc.Buffer(make([]byte, 0, 64<<10), int(p.cfg.MaxRequestBytes)+1)
	for sc.Scan() {
		line := sc.Bytes()
		if len(strings.TrimSpace(string(line))) == 0 {
			continue
		}
		if int64(len(line)) > p.cfg.MaxRequestBytes {
			p.logf("mcp-proxy: REFUSED oversized stdio message (> %d bytes)", p.cfg.MaxRequestBytes)
			writeHost(rpcErrorLine(nil, codeRefused, "mcp-proxy: request too large"))
			continue
		}
		if refused := p.screen(ctx, line); refused != nil {
			writeHost(rpcErrorLine(refused.id, codeRefused, refused.message))
			continue
		}
		writeChild(line)
	}
	// Host hung up: closing the child's stdin is the shutdown signal every
	// stdio MCP server understands.
	_ = childIn.Close()
	if err := sc.Err(); err != nil {
		return fmt.Errorf("mcp-proxy: read host stdin: %w", err)
	}
	return <-done
}

// serverCallRefusal builds the JSON-RPC error answering a blocked
// server-initiated request. A blocked notification (no id) gets no reply.
func serverCallRefusal(raw []byte, method string) []byte {
	var msg struct {
		ID json.RawMessage `json:"id"`
	}
	if json.Unmarshal(raw, &msg) != nil || len(msg.ID) == 0 || string(msg.ID) == "null" {
		return nil
	}
	return rpcErrorLine(msg.ID, codeRefused,
		fmt.Sprintf("mcp-proxy: server-initiated %s is blocked by policy", method))
}

// rpcErrorLine renders one JSON-RPC error as a stdio line body (no newline).
func rpcErrorLine(id json.RawMessage, code int, message string) []byte {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	})
	if err != nil {
		return []byte(`{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"mcp-proxy: refused"}}`)
	}
	return body
}
