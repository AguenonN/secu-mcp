package scrub

import (
	"strings"
	"testing"
)

func mustMask(t *testing.T, in, secret string) string {
	t.Helper()
	out, findings := String(in, "test")
	if strings.Contains(out, secret) {
		t.Errorf("secret %q survived scrubbing:\n  in:  %s\n  out: %s", secret, in, out)
	}
	if len(findings) == 0 {
		t.Errorf("masking %q produced no finding (in: %s)", secret, in)
	}
	return out
}

// The credential shapes that actually turn up in scrape configs, alert
// annotations and error strings.
func TestCredentialsAreMasked(t *testing.T) {
	cases := map[string]string{
		"scrape failed: Authorization: Bearer glsa_AbCdEf0123456789xyz":                                                             "glsa_AbCdEf0123456789xyz",
		"target http://user:hunter2@checkout.internal/metrics down":                                                                 "hunter2",
		`config api_key="0123456789abcdef" rejected`:                                                                                "0123456789abcdef",
		"aws credentials AKIAIOSFODNN7EXAMPLE expired":                                                                              "AKIAIOSFODNN7EXAMPLE",
		"token=ghp_1234567890abcdefghijklmnopqrstuv invalid":                                                                        "ghp_1234567890abcdefghijklmnopqrstuv",
		"jwt eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c rejected": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"openai sk-proj0123456789abcdefgh quota exceeded":                                                                           "sk-proj0123456789abcdefgh",
		"password: s3cr3tValue": "s3cr3tValue",
	}
	for in, secret := range cases {
		mustMask(t, in, secret)
	}
}

// Personal and customer identifiers leak out of alert annotations that quote
// the failing request.
func TestPersonalDataIsMasked(t *testing.T) {
	mustMask(t, "checkout failed for alice.martin@example.com", "alice.martin@example.com")
	mustMask(t, "customer_id=CUST8891023 saw a 500", "CUST8891023")
	mustMask(t, "card 4111 1111 1111 1111 declined", "4111 1111 1111 1111")
}

// Public addresses are masked; cluster-internal ones are not. Masking
// 10.42.0.7 would blind the on-call engineer and protect nothing.
func TestOnlyRoutableIPsAreMasked(t *testing.T) {
	out, findings := String("pod 10.42.0.7 could not reach 93.184.216.34 via 127.0.0.1", "test")
	if !strings.Contains(out, "10.42.0.7") || !strings.Contains(out, "127.0.0.1") {
		t.Errorf("private and loopback addresses must survive: %s", out)
	}
	if strings.Contains(out, "93.184.216.34") {
		t.Errorf("public address must be masked: %s", out)
	}
	if len(findings) != 1 || findings[0].Kind != "public-ip" {
		t.Errorf("expected exactly one public-ip finding, got %+v", findings)
	}
	// CGNAT (used by several CNIs) counts as internal.
	if out, _ := String("node 100.64.1.2", "test"); !strings.Contains(out, "100.64.1.2") {
		t.Errorf("CGNAT address must survive: %s", out)
	}
}

// Ordinary telemetry must come through untouched — a scrubber that mangles
// normal metric labels makes the tool useless during an incident.
func TestBenignTelemetryIsUntouched(t *testing.T) {
	for _, in := range []string{
		"checkout-api",
		"http_requests_total",
		"/checkout/v2",
		"pod checkout-api-7c65f5c949-f9xb4 restarted",
		"error rate 0.42 over 5m",
	} {
		out, findings := String(in, "test")
		if out != in {
			t.Errorf("benign value was altered:\n  in:  %s\n  out: %s (%+v)", in, out, findings)
		}
	}
}

// Label names survive, label values are scrubbed: the shape of the telemetry
// is not the secret, its contents are.
func TestLabelsKeepTheirNames(t *testing.T) {
	in := map[string]string{
		"job":      "checkout-api",
		"instance": "93.184.216.34:8080",
		"auth":     "Bearer glsa_AbCdEf0123456789xyz",
	}
	out, findings := Labels(in)
	if _, ok := out["instance"]; !ok {
		t.Fatal("label name must be preserved")
	}
	if out["job"] != "checkout-api" {
		t.Errorf("benign label altered: %q", out["job"])
	}
	if strings.Contains(out["instance"], "93.184.216.34") {
		t.Errorf("public IP survived in label: %q", out["instance"])
	}
	if strings.Contains(out["auth"], "glsa_") {
		t.Errorf("token survived in label: %q", out["auth"])
	}
	if len(findings) < 2 {
		t.Errorf("expected findings for both offending labels, got %+v", findings)
	}
}

// Findings must never carry the value they masked — they end up in logs.
func TestSummarizeCarriesNoSecret(t *testing.T) {
	_, findings := String("password: s3cr3tValue and Bearer glsa_AbCdEf0123456789xyz", "test")
	s := Summarize(findings)
	if strings.Contains(s, "s3cr3t") || strings.Contains(s, "glsa_") {
		t.Fatalf("audit summary leaks the secret: %s", s)
	}
	if s == "" {
		t.Fatal("expected a non-empty summary")
	}
	if got := Summarize(nil); got != "" {
		t.Fatalf("no findings should summarise to empty, got %q", got)
	}
}
