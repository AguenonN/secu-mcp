package proxy_test

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"mcprogue/internal/proxy"
)

// scriptedUpstream plays a local MCP server over pipes: it answers every
// tools/call it receives with poisoned text, and can volunteer a
// server-initiated sampling request.
func scriptedUpstream(t *testing.T, in io.Reader, out io.WriteCloser, volunteerSampling bool) {
	t.Helper()
	go func() {
		defer out.Close()
		if volunteerSampling {
			_, _ = io.WriteString(out, `{"jsonrpc":"2.0","id":"srv-1","method":"sampling/createMessage","params":{}}`+"\n")
		}
		sc := bufio.NewScanner(in)
		for sc.Scan() {
			var req map[string]any
			if json.Unmarshal(sc.Bytes(), &req) != nil {
				continue
			}
			if req["method"] != "tools/call" {
				continue
			}
			resp, _ := json.Marshal(map[string]any{
				"jsonrpc": "2.0", "id": req["id"],
				"result": map[string]any{"content": []any{map[string]any{
					"type": "text", "text": "config token=glsa_S3cretTokenABCDEFGH0123",
				}}},
			})
			_, _ = out.Write(append(resp, '\n'))
		}
	}()
}

func newStdioProxy(t *testing.T, volunteerSampling bool) (hostIn io.WriteCloser, hostOut *bufio.Scanner, childSeen func() []string) {
	t.Helper()
	grants, err := proxy.ParseGrants("get_file:read")
	if err != nil {
		t.Fatal(err)
	}
	p, err := proxy.NewStdio(proxy.Config{Grants: grants, Logf: t.Logf})
	if err != nil {
		t.Fatalf("NewStdio: %v", err)
	}

	hostInR, hostInW := io.Pipe()
	hostOutR, hostOutW := io.Pipe()
	childInR, childInW := io.Pipe()
	childOutR, childOutW := io.Pipe()

	// Tap what the child receives, so tests assert on the upstream's view.
	var seenMu sync.Mutex
	var seen []string
	tapR, tapW := io.Pipe()
	go func() {
		sc := bufio.NewScanner(childInR)
		for sc.Scan() {
			line := sc.Text()
			seenMu.Lock()
			seen = append(seen, line)
			seenMu.Unlock()
			_, _ = io.WriteString(tapW, line+"\n")
		}
		_ = tapW.Close()
	}()

	scriptedUpstream(t, tapR, childOutW, volunteerSampling)

	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = p.BridgeStdio(context.Background(), hostInR, hostOutW, childInW, childOutR)
		_ = hostOutW.Close()
	}()
	t.Cleanup(func() {
		_ = hostInW.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("stdio bridge did not shut down")
		}
	})

	sc := bufio.NewScanner(hostOutR)
	return hostInW, sc, func() []string {
		seenMu.Lock()
		defer seenMu.Unlock()
		return append([]string(nil), seen...)
	}
}

func readLine(t *testing.T, sc *bufio.Scanner) string {
	t.Helper()
	lines := make(chan string, 1)
	go func() {
		if sc.Scan() {
			lines <- sc.Text()
		} else {
			lines <- ""
		}
	}()
	select {
	case l := <-lines:
		return l
	case <-time.After(5 * time.Second):
		t.Fatal("no line from the stdio proxy within 5s")
		return ""
	}
}

// The same locks hold over pipes as over the network: a granted call goes
// through and comes back scrubbed and sealed; an ungranted one is refused
// without the subprocess ever seeing it.
func TestStdio_ScreensAndSeals(t *testing.T) {
	hostIn, hostOut, childSeen := newStdioProxy(t, false)

	// Ungranted tool: refused in-process.
	_, _ = io.WriteString(hostIn, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"delete_everything","arguments":{}}}`+"\n")
	line := readLine(t, hostOut)
	if !strings.Contains(line, "not in grant set") {
		t.Fatalf("ungranted call not refused:\n%s", line)
	}

	// Unlisted method: default-deny applies on stdio too.
	_, _ = io.WriteString(hostIn, `{"jsonrpc":"2.0","id":2,"method":"jobs/execute"}`+"\n")
	line = readLine(t, hostOut)
	if !strings.Contains(line, "ERR_METHOD_NOT_ALLOWED") {
		t.Fatalf("unlisted method not refused:\n%s", line)
	}

	// Granted call: forwarded, and the reply is scrubbed and sealed.
	_, _ = io.WriteString(hostIn, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"get_file","arguments":{}}}`+"\n")
	line = readLine(t, hostOut)
	text := textAt(t, line, "content", "text")
	if strings.Contains(text, "glsa_S3cretTokenABCDEFGH0123") {
		t.Fatalf("the token survived the stdio scrubber:\n%s", text)
	}
	if !strings.Contains(text, "<untrusted_data id=") {
		t.Fatalf("stdio reply came back unsealed:\n%s", text)
	}

	for _, got := range childSeen() {
		if strings.Contains(got, "delete_everything") || strings.Contains(got, "jobs/execute") {
			t.Fatalf("a refused message reached the subprocess: %s", got)
		}
	}
}

// A server-initiated sampling request is not delivered to the host; the
// subprocess gets a refusal instead of a silent hang.
func TestStdio_BlocksServerSampling(t *testing.T) {
	hostIn, hostOut, childSeen := newStdioProxy(t, true)

	// Drive one normal exchange; if the sampling request had been forwarded
	// it would arrive on hostOut before this reply.
	_, _ = io.WriteString(hostIn, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"get_file","arguments":{}}}`+"\n")
	line := readLine(t, hostOut)
	if strings.Contains(line, "sampling/createMessage") {
		t.Fatalf("the sampling request reached the host:\n%s", line)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		refused := false
		for _, got := range childSeen() {
			if strings.Contains(got, `"srv-1"`) && strings.Contains(got, "blocked by policy") {
				refused = true
			}
		}
		if refused {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the subprocess never received a refusal for its sampling request; it saw: %v", childSeen())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// The supply-chain half: the binary must hash to its pin before it is spawned.
func TestStdio_VerifyBinarySHA256(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "fake-mcp-server")
	content := []byte("#!/bin/sh\necho hi\n")
	if err := os.WriteFile(bin, content, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	good := hex.EncodeToString(sum[:])

	if _, err := proxy.VerifyBinarySHA256(bin, "sha256:"+good); err != nil {
		t.Fatalf("the correct hash was refused: %v", err)
	}
	_, err := proxy.VerifyBinarySHA256(bin, strings.Repeat("00", 32))
	if err == nil {
		t.Fatal("a wrong hash let the binary through")
	}
	if !strings.Contains(err.Error(), "ERR_UPSTREAM_BINARY_MUTATED") {
		t.Fatalf("hash mismatch error %q does not carry the alertable code", err)
	}
}
