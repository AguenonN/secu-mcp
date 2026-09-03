// Package toolpin defends against the rug-pull: an upstream that is perfectly
// legitimate today and rewrites a tool's description or schema tomorrow, so
// the next session's model reads instructions the security review never saw.
// Identity does not catch this — the server proving who it is says nothing
// about its catalogue staying what it was.
//
// The mechanism is a lock file, the way dependency managers pin packages: each
// tool's identity-bearing fields (name, description, inputSchema) are hashed
// once, and every subsequent tools/list is checked against the recorded hash.
// A tool whose hash moved is not "updated", it is unverified, and it is
// disabled until an operator re-pins it deliberately.
//
// The first tools/list against a missing lock file writes it (trust on first
// use). TOFU is a deliberate trade: the alternative — hand-writing hashes —
// guarantees the file is never created at all. The pin is only as good as the
// state it was taken in, which the log line at pin time says out loud.
package toolpin

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
)

const hashPrefix = "sha256:"

// MutationError reports a tool whose advertised schema no longer matches its
// pin. The code string is stable so alerting can key on it.
type MutationError struct {
	Tool string
	Want string // pinned hash; empty when the tool was never pinned at all
	Got  string
}

func (e *MutationError) Error() string {
	if e.Want == "" {
		return fmt.Sprintf("ERR_TOOL_SCHEMA_MUTATED: tool %q is not in the lock file (a tool appearing after pinning is the rug-pull, not a feature)", e.Tool)
	}
	return fmt.Sprintf("ERR_TOOL_SCHEMA_MUTATED: tool %q advertises a schema (%s) that does not match its pin (%s)", e.Tool, e.Got, e.Want)
}

// Hash fingerprints the fields the model actually reads. Anything else a
// server adds (annotations, _meta) may vary freely; these three cannot.
//
// The tool is a decoded JSON object rather than a typed struct because the
// proxy forwards bytes it does not fully model. encoding/json sorts map keys
// at every level, so the hash is stable across upstream key reordering.
func Hash(tool map[string]any) (string, error) {
	pinned := map[string]any{
		"name":        tool["name"],
		"description": tool["description"],
		"inputSchema": tool["inputSchema"],
	}
	b, err := json.Marshal(pinned)
	if err != nil {
		return "", fmt.Errorf("toolpin: canonicalize tool: %w", err)
	}
	sum := sha256.Sum256(b)
	return hashPrefix + hex.EncodeToString(sum[:]), nil
}

// lockFile is the on-disk shape of tools.lock.json.
type lockFile struct {
	Version int               `json:"version"`
	Tools   map[string]string `json:"tools"`
}

// Lock holds the pinned catalogue. Zero value is unusable; build with Open.
type Lock struct {
	path string

	mu   sync.Mutex
	pins map[string]string
	tofu bool
}

// Open loads the lock file, or arms trust-on-first-use when it does not exist
// yet. A file that exists but cannot be parsed is a hard error: an unreadable
// pin set must not silently degrade to "pin everything I see next".
func Open(path string) (*Lock, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return &Lock{path: path, pins: map[string]string{}, tofu: true}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("toolpin: read %s: %w", path, err)
	}
	var f lockFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("toolpin: parse %s: %w", path, err)
	}
	if f.Version != 1 {
		return nil, fmt.Errorf("toolpin: %s has version %d, this build understands 1", path, f.Version)
	}
	if f.Tools == nil {
		f.Tools = map[string]string{}
	}
	return &Lock{path: path, pins: f.Tools}, nil
}

// TrustOnFirstUse reports whether the next full catalogue will be pinned
// rather than verified.
func (l *Lock) TrustOnFirstUse() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.tofu
}

// Verify checks one advertised tool against its pin. It never mutates the pin
// set: drift is an error to surface, not a state to converge to.
func (l *Lock) Verify(tool map[string]any) error {
	name, _ := tool["name"].(string)
	got, err := Hash(tool)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	want, pinned := l.pins[name]
	if !pinned {
		return &MutationError{Tool: name, Got: got}
	}
	if want != got {
		return &MutationError{Tool: name, Want: want, Got: got}
	}
	return nil
}

// Pin records the full catalogue and writes the lock file. It only acts in
// trust-on-first-use state; once a file exists, re-pinning is an operator
// action (delete or edit the file), never an automatic one.
func (l *Lock) Pin(tools []map[string]any) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.tofu {
		return nil
	}
	pins := make(map[string]string, len(tools))
	for _, tool := range tools {
		name, _ := tool["name"].(string)
		if name == "" {
			return fmt.Errorf("toolpin: refusing to pin a tool with no name")
		}
		h, err := Hash(tool)
		if err != nil {
			return err
		}
		pins[name] = h
	}
	if err := writeLock(l.path, pins); err != nil {
		return err
	}
	l.pins = pins
	l.tofu = false
	return nil
}

// Names lists the pinned tool names, for the startup log.
func (l *Lock) Names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	out := make([]string, 0, len(l.pins))
	for name := range l.pins {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// writeLock writes atomically: a half-written lock file would fail closed on
// the next start (parse error), but there is no reason to leave one around.
func writeLock(path string, pins map[string]string) error {
	b, err := json.MarshalIndent(lockFile{Version: 1, Tools: pins}, "", "  ")
	if err != nil {
		return fmt.Errorf("toolpin: encode lock: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tools.lock.*")
	if err != nil {
		return fmt.Errorf("toolpin: write lock: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(append(b, '\n')); err != nil {
		tmp.Close()
		return fmt.Errorf("toolpin: write lock: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("toolpin: write lock: %w", err)
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("toolpin: write lock: %w", err)
	}
	return nil
}
