package proxy

import (
	"encoding/json"
	"strings"
)

// baselineMethods is the client→server surface the proxy understands and
// screens. Everything outside it is refused (ERR_METHOD_NOT_ALLOWED) rather
// than forwarded: a method this code has never heard of is a method whose
// policy it cannot enforce, and "forward and hope" is how resources/read
// walked past the tools/call gate in the first place.
//
// The gated methods are not "safe", they are *screened*: tools/call by
// grants+approval, resources/read|subscribe by URI allowlist, prompts/get by
// prompt allowlist. Additional methods an operator vouches for go in
// Config.AllowedMethods.
var baselineMethods = []string{
	"initialize",
	"ping",
	"tools/list",
	"tools/call",
	"resources/list",
	"resources/templates/list",
	"resources/read",
	"resources/subscribe",
	"resources/unsubscribe",
	"prompts/list",
	"prompts/get",
	"completion/complete",
	"logging/setLevel",
	"notifications/initialized",
	"notifications/cancelled",
	"notifications/progress",
	"notifications/roots/list_changed",
}

func buildMethodSet(extra []string) map[string]bool {
	m := make(map[string]bool, len(baselineMethods)+len(extra))
	for _, name := range baselineMethods {
		m[name] = true
	}
	for _, name := range extra {
		if name = strings.TrimSpace(name); name != "" {
			m[name] = true
		}
	}
	return m
}

// serverInitiated classifies upstream→client requests the proxy blocks by
// default. sampling/createMessage is a server ordering the LLM to run a
// completion; elicitation/create is a server putting a question box in front
// of the user. Both invert who is driving whom, and a fronted third-party
// server gets neither unless the operator turns it on.
func (p *Proxy) blockedServerMethod(method string) bool {
	switch method {
	case "sampling/createMessage":
		return !p.cfg.AllowServerSampling
	case "elicitation/create":
		return !p.cfg.AllowServerElicitation
	}
	return false
}

// suppressedServerCall inspects an upstream→client message and reports
// whether it is a server-initiated request the policy blocks.
func (p *Proxy) suppressedServerCall(raw []byte) (string, bool) {
	var msg struct {
		Method string `json:"method"`
	}
	if json.Unmarshal(raw, &msg) != nil || msg.Method == "" {
		return "", false
	}
	return msg.Method, p.blockedServerMethod(msg.Method)
}

// uriAllowed matches a resource URI against the configured globs, where '*'
// matches any run of characters, '/' included ("file:///var/log/*",
// "https://docs.internal/*"). No glob configured means no resource is
// readable: the allowlist fails closed like every other one here.
func (p *Proxy) uriAllowed(uri string) bool {
	for _, pattern := range p.cfg.ResourceURIs {
		if matchGlob(pattern, uri) {
			return true
		}
	}
	return false
}

// matchGlob is the whole pattern language: literal text and '*'. Anything
// richer (regex, character classes) invites allowlists nobody can read.
func matchGlob(pattern, s string) bool {
	parts := strings.Split(pattern, "*")
	if len(parts) == 1 {
		return pattern == s
	}
	if !strings.HasPrefix(s, parts[0]) {
		return false
	}
	s = s[len(parts[0]):]
	for _, part := range parts[1 : len(parts)-1] {
		i := strings.Index(s, part)
		if i < 0 {
			return false
		}
		s = s[i+len(part):]
	}
	return strings.HasSuffix(s, parts[len(parts)-1])
}
