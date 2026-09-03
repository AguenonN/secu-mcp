package proxy

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"mcprogue/internal/toolpolicy"
)

// ParseGrants reads ALLOWED_TOOLS: a comma-separated list of "name" or
// "name:capability", capability being read or action, e.g.
//
//	ALLOWED_TOOLS="list_repos,get_issue:read,delete_repo:action"
//
// A bare name is granted as read, the capability that cannot mutate anything.
// An unknown capability is a configuration error rather than a default:
// guessing what the operator meant is how allowlists rot open.
//
// An empty specification grants nothing.
func ParseGrants(spec string) (toolpolicy.Grants, error) {
	grants := toolpolicy.Grants{}
	for _, entry := range splitList(spec) {
		name, capability, hasCap := strings.Cut(entry, ":")
		name = strings.TrimSpace(name)
		if name == "" {
			return nil, fmt.Errorf("ALLOWED_TOOLS: entry %q names no tool", entry)
		}
		c := toolpolicy.Read
		if hasCap {
			switch strings.ToLower(strings.TrimSpace(capability)) {
			case string(toolpolicy.Read):
				c = toolpolicy.Read
			case string(toolpolicy.Action):
				c = toolpolicy.Action
			default:
				return nil, fmt.Errorf("ALLOWED_TOOLS: entry %q has unknown capability %q (want read or action)",
					entry, capability)
			}
		}
		if prev, dup := grants[name]; dup && prev != c {
			return nil, fmt.Errorf("ALLOWED_TOOLS: tool %q is granted twice, as %q and %q", name, prev, c)
		}
		grants[name] = c
	}
	return grants, nil
}

// ApproverFromSpec reads APPROVED_ACTIONS into the human-in-the-loop gate:
// comma-separated "tool:target" pairs, e.g.
//
//	APPROVED_ACTIONS="drop_db:staging,delete_repo:repo1"
//
// The target is mandatory and is checked against the call. An engineer who
// approved dropping the staging database has not approved dropping
// production: an approval covers one operation, not a standing permission.
//
// An empty specification refuses everything.
func ApproverFromSpec(spec string) (toolpolicy.Approver, error) {
	approved := map[string]map[string]bool{}
	for _, entry := range splitList(spec) {
		tool, target, ok := strings.Cut(entry, ":")
		tool, target = strings.TrimSpace(tool), strings.TrimSpace(target)
		if !ok || tool == "" || target == "" {
			return nil, fmt.Errorf("APPROVED_ACTIONS: entry %q must be \"tool:target\"", entry)
		}
		if approved[tool] == nil {
			approved[tool] = map[string]bool{}
		}
		approved[tool][target] = true
	}

	return func(_ context.Context, params *mcp.CallToolParams) error {
		targets := approved[params.Name]
		if len(targets) == 0 {
			return fmt.Errorf("no approval on record for %q (APPROVED_ACTIONS holds %v)",
				params.Name, describe(approved))
		}
		args, _ := params.Arguments.(map[string]any)
		named, fromKnownKey := approvalTarget(args)
		if fromKnownKey {
			if targets[named] {
				return nil
			}
			return fmt.Errorf("%q targets %q, not in approved targets %v",
				params.Name, named, sortedKeys(targets))
		}
		// No argument the proxy recognises as a target. Rather than wave the
		// call through, require the approved value to appear in it.
		for _, v := range args {
			if s, ok := v.(string); ok && targets[s] {
				return nil
			}
		}
		return fmt.Errorf("%q carries none of the approved targets %v",
			params.Name, sortedKeys(targets))
	}, nil
}

// targetKeys are the argument names, in priority order, that conventionally
// name what an action acts on.
//
// This is the proxy's one heuristic, and it only locates the value an approval
// is checked against. Failing to recognise a key never approves a call: it
// falls through to the stricter branch above, where the approved value must
// appear in the arguments outright.
var targetKeys = []string{
	"target", "resource", "dashboard_uid", "database", "db", "repo", "repository",
	"namespace", "cluster", "service", "environment", "env", "bucket", "table",
	"channel", "path", "file", "name", "uid", "id",
}

// approvalTarget returns the value an approval is checked against and whether
// it came from a recognised key. A recognised key is authoritative: if the
// call says database=prod, no other argument stands in for it.
func approvalTarget(args map[string]any) (string, bool) {
	for _, k := range targetKeys {
		if v, ok := args[k].(string); ok && v != "" {
			return v, true
		}
	}
	return "", false
}

// splitList parses a comma-separated environment value, dropping empties.
func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// describe renders the approval set for an error message: what the operator
// configured, never what the caller asked for.
func describe(approved map[string]map[string]bool) []string {
	out := make([]string, 0, len(approved))
	for tool, targets := range approved {
		for _, t := range sortedKeys(targets) {
			out = append(out, tool+":"+t)
		}
	}
	sort.Strings(out)
	return out
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SplitList exposes the comma-separated parser for AUTHORIZED_CLIENT_IDS.
func SplitList(s string) []string { return splitList(s) }
