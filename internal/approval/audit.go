package approval

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash"
	"io"
	"sync"
	"time"
)

// Entry is one approval decision in the audit trail. Every field except the
// chain fields is set by the caller; Time, Prev and MAC are filled by Record.
type Entry struct {
	Time         time.Time `json:"ts"`
	Tool         string    `json:"tool"`
	ActionDigest string    `json:"action_digest"`
	Decision     string    `json:"decision"` // "approved" | "refused"
	Approver     string    `json:"approver"`
	ApprovedBy   string    `json:"approved_by,omitempty"`
	TicketID     string    `json:"ticket_id,omitempty"`
	Reason       string    `json:"reason,omitempty"`

	// Prev is the previous entry's MAC (a run of zeros for the first entry),
	// and MAC authenticates this entry plus Prev. Together they chain the
	// file: an entry cannot be dropped, reordered or edited without breaking
	// every MAC after it. With a key, MAC is HMAC-SHA256 and forging it
	// requires the key; without one it degrades to plain SHA-256 — tamper
	// EVIDENT against accidents, not against an attacker who can rewrite the
	// whole file.
	Prev string `json:"prev"`
	MAC  string `json:"mac"`
}

// Audit writes the hash-chained trail, one JSON object per line. A nil *Audit
// is valid and records nothing, so wiring is unconditional at call sites.
type Audit struct {
	mu   sync.Mutex
	w    io.Writer
	key  []byte
	prev string
}

// NewAudit chains entries into w. key is the optional HMAC key; nil degrades
// the chain to integrity-only.
func NewAudit(w io.Writer, key []byte) *Audit {
	return &Audit{w: w, key: key, prev: genesis}
}

var genesis = hex.EncodeToString(make([]byte, sha256.Size))

// Record appends one entry. The write happens under the lock so the chain
// order on disk is the chain order in memory.
func (a *Audit) Record(e Entry) error {
	if a == nil {
		return nil
	}
	a.mu.Lock()
	defer a.mu.Unlock()

	e.Time = time.Now().UTC()
	e.Prev = a.prev
	e.MAC = ""
	body, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encode entry: %w", err)
	}
	e.MAC = a.seal(body)
	line, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("audit: encode entry: %w", err)
	}
	if _, err := a.w.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("audit: write entry: %w", err)
	}
	a.prev = e.MAC
	return nil
}

// seal computes the MAC over prev || entry-without-mac.
func (a *Audit) seal(body []byte) string {
	var h hash.Hash
	if len(a.key) > 0 {
		h = hmac.New(sha256.New, a.key)
	} else {
		h = sha256.New()
	}
	h.Write([]byte(a.prev))
	h.Write(body)
	return hex.EncodeToString(h.Sum(nil))
}
