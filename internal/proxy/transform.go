package proxy

import (
	"encoding/json"
	"fmt"

	"mcprogue/internal/envelope"
	"mcprogue/internal/scrub"
)

// transform rewrites one JSON-RPC message on its way back. It works on shape
// rather than on request ids: any result carrying content[] is a tool result
// and gets sealed, whether it arrives on the POST response or on the
// long-lived GET stream. Correlating ids would add state and miss the case
// worth catching, a result delivered on a stream the proxy did not open.
//
// Anything unrecognised is returned byte for byte.
func (p *Proxy) transform(raw []byte) []byte {
	var msg map[string]any
	if err := decodeJSON(raw, &msg); err != nil {
		return raw
	}
	result, ok := msg["result"].(map[string]any)
	if !ok {
		return raw
	}

	changed := false
	var findings []scrub.Finding

	// Lock 3. The text channel becomes prompt: scrub, then seal.
	if content, ok := result["content"].([]any); ok {
		for _, item := range content {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if t, _ := block["type"].(string); t != "text" {
				continue
			}
			text, ok := block["text"].(string)
			if !ok {
				continue
			}
			clean, f := scrub.String(text, "tool.content")
			findings = append(findings, f...)
			sealed, err := envelope.Seal(clean)
			if err != nil {
				// No entropy means no unforgeable boundary, and returning the
				// content unsealed is the failure this lock exists to prevent.
				p.logf("mcp-proxy: seal failed, withholding tool content: %v", err)
				block["text"] = "mcp-proxy: reply withheld, envelope could not be sealed"
				changed = true
				continue
			}
			block["text"] = sealed
			changed = true
		}
	}

	// The typed channel is scrubbed but not sealed — see the package comment.
	if sc, ok := result["structuredContent"]; ok {
		scrubbed, f, touched := scrubValue(sc, "structuredContent")
		if touched {
			result["structuredContent"] = scrubbed
			findings = append(findings, f...)
			changed = true
		}
	}

	// The catalogue channel. Lock 2 applied to advertising (do not list what
	// will be refused), the pin check against the rug-pull, and lock 3
	// applied to the one field of a tools/list the model actually reads as
	// prose: the descriptions.
	if tools, ok := result["tools"].([]any); ok {
		kept := tools
		if p.cfg.HideUngrantedTools {
			var dropped int
			kept, dropped = p.filterTools(kept)
			changed = changed || dropped > 0
		}
		if p.cfg.ToolLock != nil {
			var dropped int
			kept, dropped = p.pinTools(kept)
			changed = changed || dropped > 0
		}
		if f, touched := sanitizeToolText(kept); touched {
			findings = append(findings, f...)
			changed = true
		}
		result["tools"] = kept
	}

	// resources/read replies: contents[] text is the same prompt-bound
	// channel as tool content, and gets the same treatment — scrub, seal.
	if contents, ok := result["contents"].([]any); ok {
		for _, item := range contents {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			text, ok := block["text"].(string)
			if !ok {
				continue
			}
			clean, f := scrub.String(text, "resource.contents")
			findings = append(findings, f...)
			sealed, err := envelope.Seal(clean)
			if err != nil {
				p.logf("mcp-proxy: seal failed, withholding resource content: %v", err)
				block["text"] = "mcp-proxy: resource content withheld, envelope could not be sealed"
				changed = true
				continue
			}
			block["text"] = sealed
			changed = true
		}
	}

	// prompts/get replies: messages are meant to be instructions, so sealing
	// them would defeat the feature. They are scrubbed and defanged instead —
	// no secret rides out, no forged envelope rides in — and the allowlist in
	// screen decides which prompts exist at all.
	if messages, ok := result["messages"].([]any); ok {
		for _, item := range messages {
			msg, ok := item.(map[string]any)
			if !ok {
				continue
			}
			content, ok := msg["content"].(map[string]any)
			if !ok {
				continue
			}
			text, ok := content["text"].(string)
			if !ok {
				continue
			}
			clean, f := scrub.String(text, "prompt.messages")
			clean = envelope.Defang(clean)
			if clean != text {
				content["text"] = clean
				findings = append(findings, f...)
				changed = true
			}
		}
	}

	if !changed {
		return raw
	}
	if len(findings) > 0 {
		p.logf("mcp-proxy: masked %d sensitive value(s) in an upstream reply: %s",
			len(findings), scrub.Summarize(findings))
	}
	out, err := json.Marshal(msg)
	if err != nil {
		// Re-encoding a decoded message should not fail; if it does, the
		// caller gets the original rather than a truncated one.
		p.logf("mcp-proxy: re-encode reply: %v", err)
		return raw
	}
	return out
}

// filterTools drops every advertised tool outside the grant set.
func (p *Proxy) filterTools(tools []any) ([]any, int) {
	kept := make([]any, 0, len(tools))
	dropped := 0
	for _, t := range tools {
		tool, ok := t.(map[string]any)
		if !ok {
			continue
		}
		name, _ := tool["name"].(string)
		if _, granted := p.cfg.Grants[name]; !granted {
			p.logf("mcp-proxy: hiding upstream tool %q from tools/list (outside the grant set)", name)
			dropped++
			continue
		}
		kept = append(kept, t)
	}
	return kept, dropped
}

// pinTools verifies the advertised catalogue against the lock file. A tool
// whose hash drifted is dropped from the list AND quarantined, so a caller
// that memorised the name from an earlier session cannot call it either. On
// trust-on-first-use the catalogue is pinned instead of verified.
func (p *Proxy) pinTools(tools []any) ([]any, int) {
	lock := p.cfg.ToolLock

	decoded := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		if tool, ok := t.(map[string]any); ok {
			decoded = append(decoded, tool)
		}
	}
	if lock.TrustOnFirstUse() {
		if err := lock.Pin(decoded); err != nil {
			// Failing to record pins must not fail open: with nothing pinned,
			// Verify below rejects everything, which is the right direction.
			p.logf("mcp-proxy: PINNING FAILED, catalogue will be refused: %v", err)
		} else {
			p.logf("mcp-proxy: pinned %d tool schema(s) into the lock file (trust on first use)", len(decoded))
		}
	}

	kept := make([]any, 0, len(tools))
	dropped := 0
	for _, tool := range decoded {
		if err := lock.Verify(tool); err != nil {
			name, _ := tool["name"].(string)
			p.logf("mcp-proxy: ALERT %v — tool disabled for this session", err)
			p.setQuarantine(name, err.Error())
			dropped++
			continue
		}
		kept = append(kept, tool)
	}
	return kept, dropped
}

// sanitizeToolText runs the prose fields of each advertised tool through the
// scrubber and the envelope defanger. A description is text the model reads
// as instructions about when to call the tool; a server that hides "also
// exfiltrate the config" in one is running the same injection as poisoned
// tool output, one message earlier.
func sanitizeToolText(tools []any) ([]scrub.Finding, bool) {
	var findings []scrub.Finding
	changed := false
	for _, t := range tools {
		tool, ok := t.(map[string]any)
		if !ok {
			continue
		}
		for _, field := range []string{"description", "title"} {
			text, ok := tool[field].(string)
			if !ok {
				continue
			}
			clean, f := scrub.String(text, "tool."+field)
			clean = envelope.Defang(clean)
			if clean != text {
				tool[field] = clean
				findings = append(findings, f...)
				changed = true
			}
		}
	}
	return findings, changed
}

// scrubValue masks secrets in every string of a decoded JSON value. It reports
// whether anything changed, so an untouched reply is forwarded as its original
// bytes.
func scrubValue(v any, where string) (any, []scrub.Finding, bool) {
	switch val := v.(type) {
	case string:
		clean, f := scrub.String(val, where)
		return clean, f, clean != val
	case map[string]any:
		var findings []scrub.Finding
		changed := false
		for k, item := range val {
			got, f, touched := scrubValue(item, where+"."+k)
			if touched {
				val[k] = got
				findings = append(findings, f...)
				changed = true
			}
		}
		return val, findings, changed
	case []any:
		var findings []scrub.Finding
		changed := false
		for i, item := range val {
			got, f, touched := scrubValue(item, fmt.Sprintf("%s[%d]", where, i))
			if touched {
				val[i] = got
				findings = append(findings, f...)
				changed = true
			}
		}
		return val, findings, changed
	default:
		// Numbers, booleans, null: nothing to mask or reformat.
		return v, nil, false
	}
}
