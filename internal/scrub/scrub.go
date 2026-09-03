// Package scrub masks sensitive values in observability data before it leaves
// the bridge.
//
// Telemetry looks harmless until you read the labels: a scrape target carries
// its bearer token in a URL, an alert annotation quotes a failing request with
// a customer id, an instance label is a public IP. The model may summarise any
// of it into a ticket or a dashboard annotation the whole team reads.
//
// Masking happens server-side, before serialisation, rather than on the
// client where an injection could argue its way around it. The agent cannot
// leak what it never received.
//
// This is not a classifier: it is a set of high-value shapes (tokens, keys,
// JWTs, emails, routable IPs, customer identifiers). Anything subtler is
// contained by the other locks, not by pattern matching.
package scrub

import (
	"fmt"
	"net/netip"
	"regexp"
	"strings"
)

// Mask is what replaces a matched secret.
const Mask = "[REDACTED]"

// Finding records one masked value. Kind names the pattern; it never carries
// the secret itself, so findings are safe to log.
type Finding struct {
	Kind  string
	Where string
}

type pattern struct {
	kind string
	re   *regexp.Regexp
	// group, when non-zero, is the submatch to mask instead of the whole
	// match — used to keep the key name and mask only its value.
	group int
}

var patterns = []pattern{
	// Credentials that announce themselves by prefix. These are the ones a
	// leak scanner would flag in a repo, and they turn up in scrape configs,
	// alert annotations and error strings alike.
	{kind: "grafana-token", re: regexp.MustCompile(`\bglsa_[A-Za-z0-9_\-]{8,}\b`)},
	{kind: "grafana-legacy-key", re: regexp.MustCompile(`\beyJrIjoi[A-Za-z0-9+/=_\-]{10,}\b`)},
	{kind: "openai-key", re: regexp.MustCompile(`\bsk-[A-Za-z0-9_\-]{16,}\b`)},
	{kind: "anthropic-key", re: regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_\-]{16,}\b`)},
	{kind: "aws-access-key", re: regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{kind: "gcp-service-key", re: regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{kind: "github-token", re: regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{20,}\b`)},
	{kind: "slack-token", re: regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9\-]{10,}\b`)},
	{kind: "jwt", re: regexp.MustCompile(`\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b`)},
	{kind: "private-key-block", re: regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)},

	// Credentials introduced by a key name. The name survives — downstream
	// still learns a token was involved — the value does not.
	{kind: "bearer-header", re: regexp.MustCompile(`(?i)\b(bearer|basic)\s+([A-Za-z0-9._~+/=\-]{12,})`), group: 2},
	{kind: "keyed-secret", re: regexp.MustCompile(
		`(?i)\b(api[_-]?key|apikey|token|secret|password|passwd|pwd|auth|credential)s?\s*[:=]\s*"?([^"\s,;&]{6,})"?`), group: 2},
	{kind: "url-userinfo", re: regexp.MustCompile(`\b([a-z][a-z0-9+.\-]*://[^/\s:@]+):([^/\s@]+)@`), group: 2},

	// Personal and customer identifiers that end up in alert annotations.
	{kind: "email", re: regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)},
	{kind: "customer-id", re: regexp.MustCompile(`(?i)\b(cust|customer|client|account|user)[_-]?(?:id)?[_-]?[:=]?\s*([A-Za-z0-9]{6,})\b`), group: 2},
	{kind: "credit-card", re: regexp.MustCompile(`\b(?:\d[ \-]?){13,19}\b`)},
}

// ipRe finds dotted quads; whether one is masked is decided by isRoutable, not
// by the pattern, because internal addresses are exactly what an SRE needs to
// see.
var ipRe = regexp.MustCompile(`\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b`)

// String masks every recognised secret in s. where labels the findings (e.g.
// the label name or "alert.summary") so an audit trail can say what leaked
// from where without repeating the value.
func String(s, where string) (string, []Finding) {
	if s == "" {
		return s, nil
	}
	var findings []Finding
	out := s

	for _, p := range patterns {
		out = p.re.ReplaceAllStringFunc(out, func(m string) string {
			sub := p.re.FindStringSubmatch(m)
			if p.group == 0 || len(sub) <= p.group {
				findings = append(findings, Finding{Kind: p.kind, Where: where})
				return Mask
			}
			// Keep everything but the secret group: rebuild by replacing the
			// group's text within the match.
			idx := strings.LastIndex(m, sub[p.group])
			if idx < 0 {
				findings = append(findings, Finding{Kind: p.kind, Where: where})
				return Mask
			}
			findings = append(findings, Finding{Kind: p.kind, Where: where})
			return m[:idx] + Mask
		})
	}

	out = ipRe.ReplaceAllStringFunc(out, func(m string) string {
		if !isRoutable(m) {
			return m
		}
		findings = append(findings, Finding{Kind: "public-ip", Where: where})
		return Mask
	})

	return out, findings
}

// isRoutable reports whether ip is a public address. RFC 1918, loopback,
// link-local, CGNAT and multicast ranges are left intact: masking 10.42.0.7
// blinds the on-call engineer and protects nothing, since the address means
// nothing outside the cluster.
func isRoutable(s string) bool {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return false
	}
	if addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsMulticast() || addr.IsUnspecified() {
		return false
	}
	// 100.64.0.0/10 — carrier-grade NAT, used by several CNIs.
	if cgnat := netip.MustParsePrefix("100.64.0.0/10"); cgnat.Contains(addr) {
		return false
	}
	return true
}

// Labels masks every value in a label set. Names are preserved: the shape of
// the telemetry is not secret, its contents are.
func Labels(in map[string]string) (map[string]string, []Finding) {
	if in == nil {
		return nil, nil
	}
	out := make(map[string]string, len(in))
	var all []Finding
	for k, v := range in {
		clean, f := String(v, "label:"+k)
		out[k] = clean
		all = append(all, f...)
	}
	return out, all
}

// Summarize renders findings as a short, value-free audit line.
func Summarize(findings []Finding) string {
	if len(findings) == 0 {
		return ""
	}
	counts := map[string]int{}
	order := []string{}
	for _, f := range findings {
		if counts[f.Kind] == 0 {
			order = append(order, f.Kind)
		}
		counts[f.Kind]++
	}
	parts := make([]string, 0, len(order))
	for _, k := range order {
		parts = append(parts, fmt.Sprintf("%s×%d", k, counts[k]))
	}
	return strings.Join(parts, ", ")
}
