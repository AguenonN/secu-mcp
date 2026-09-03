package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
)

// codeRefused is returned for a call the policy declined. It sits in the
// implementation-defined range (-32000..-32099).
//
// A refusal is a JSON-RPC error, not a result carrying isError: isError means
// the tool ran and failed, and this one did not run. Go SDK clients surface
// the first as an error from CallTool and the second as a value.
const codeRefused = -32001

// bodyKind classifies an inbound JSON-RPC body.
type bodyKind int

const (
	bodyOther bodyKind = iota // any method the proxy does not gate
	bodyCall                  // a tools/call request
	bodyBatch                 // a JSON-RPC array
	bodyBad                   // not JSON-RPC at all
)

// rpcRequest is the part of a JSON-RPC request the proxy needs. Params stays
// raw: the decision runs on a decoded copy, the original bytes are forwarded.
type rpcRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params"`
}

// classify inspects a body without consuming it.
func classify(body []byte) (bodyKind, rpcRequest) {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	if len(trimmed) == 0 {
		return bodyBad, rpcRequest{}
	}
	if trimmed[0] == '[' {
		return bodyBatch, rpcRequest{}
	}
	var req rpcRequest
	if err := decodeJSON(trimmed, &req); err != nil {
		return bodyBad, rpcRequest{}
	}
	if req.Method == "tools/call" {
		return bodyCall, req
	}
	return bodyOther, req
}

// callParams pulls the tool name, arguments and approval token out of a
// tools/call. Arguments decode into a generic map because the upstream's
// tools are unknown here. A body the proxy cannot read is a body whose policy
// it cannot enforce, so it is refused rather than forwarded.
func callParams(raw json.RawMessage) (string, map[string]any, string, error) {
	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      struct {
			ApprovalToken string `json:"approvalToken"`
		} `json:"_meta"`
	}
	if len(raw) == 0 {
		return "", nil, "", fmt.Errorf("tools/call carries no params")
	}
	if err := decodeJSON(raw, &params); err != nil {
		return "", nil, "", fmt.Errorf("unreadable tools/call params: %w", err)
	}
	if params.Name == "" {
		return "", nil, "", fmt.Errorf("tools/call names no tool")
	}
	args := map[string]any{}
	if len(params.Arguments) > 0 && !bytes.Equal(bytes.TrimSpace(params.Arguments), []byte("null")) {
		if err := decodeJSON(params.Arguments, &args); err != nil {
			return "", nil, "", fmt.Errorf("tools/call arguments are not an object: %w", err)
		}
	}
	return params.Name, args, params.Meta.ApprovalToken, nil
}

// paramField reads one string field ("uri" for resources/read, "name" for
// prompts/get) out of a params object. Missing or non-string fails: a request
// the proxy cannot locate the target of is a request it cannot authorize.
func paramField(raw json.RawMessage, field string) (string, error) {
	if len(raw) == 0 {
		return "", fmt.Errorf("request carries no params")
	}
	var params map[string]json.RawMessage
	if err := decodeJSON(raw, &params); err != nil {
		return "", fmt.Errorf("unreadable params: %w", err)
	}
	var v string
	if err := decodeJSON(params[field], &v); err != nil || v == "" {
		return "", fmt.Errorf("params carry no usable %q", field)
	}
	return v, nil
}

// decodeJSON decodes with UseNumber. Without it every number becomes a
// float64 and a JSON-RPC id of 10000000 comes back as 1e+07: a different id,
// and a client waiting forever.
func decodeJSON(b []byte, into any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	return dec.Decode(into)
}

// writeRPCError answers a refused request in the caller's own protocol. The
// status stays 200: the transport worked, the JSON-RPC layer said no, and a
// 4xx reads as a broken endpoint.
func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	body, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"error":   map[string]any{"code": code, "message": message},
	})
	if err != nil {
		http.Error(w, "mcp-proxy: refused", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
