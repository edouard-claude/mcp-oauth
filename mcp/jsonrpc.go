package mcp

import (
	"encoding/json"
	"fmt"
)

// JSONRPCVersion est la version JSON-RPC utilisée
const JSONRPCVersion = "2.0"

// Request représente une requête JSON-RPC
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"` // string ou number, jamais null
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response représente une réponse JSON-RPC
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
}

// Notification représente une notification JSON-RPC (sans ID)
type Notification struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Error représente une erreur JSON-RPC
type Error struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

// Codes d'erreur JSON-RPC standard
const (
	ErrCodeParseError     = -32700
	ErrCodeInvalidRequest = -32600
	ErrCodeMethodNotFound = -32601
	ErrCodeInvalidParams  = -32602
	ErrCodeInternalError  = -32603
)

// Erreurs JSON-RPC prédéfinies
var (
	ErrParseError     = &Error{Code: ErrCodeParseError, Message: "Parse error"}
	ErrInvalidRequest = &Error{Code: ErrCodeInvalidRequest, Message: "Invalid Request"}
	ErrMethodNotFound = &Error{Code: ErrCodeMethodNotFound, Message: "Method not found"}
	ErrInvalidParams  = &Error{Code: ErrCodeInvalidParams, Message: "Invalid params"}
	ErrInternalError  = &Error{Code: ErrCodeInternalError, Message: "Internal error"}
)

// NewErrorResponse crée une réponse d'erreur
func NewErrorResponse(id interface{}, err *Error) *Response {
	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Error:   err,
	}
}

// NewSuccessResponse crée une réponse de succès
func NewSuccessResponse(id interface{}, result interface{}) (*Response, error) {
	resultJSON, err := json.Marshal(result)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal result: %w", err)
	}

	return &Response{
		JSONRPC: JSONRPCVersion,
		ID:      id,
		Result:  resultJSON,
	}, nil
}

// ValidateRequest valide une requête JSON-RPC
func ValidateRequest(req *Request) error {
	if req.JSONRPC != JSONRPCVersion {
		return fmt.Errorf("invalid jsonrpc version: %s", req.JSONRPC)
	}

	if req.ID == nil {
		return fmt.Errorf("id must not be null")
	}

	if req.Method == "" {
		return fmt.Errorf("method is required")
	}

	return nil
}

// ValidateNotification valide une notification JSON-RPC
func ValidateNotification(notif *Notification) error {
	if notif.JSONRPC != JSONRPCVersion {
		return fmt.Errorf("invalid jsonrpc version: %s", notif.JSONRPC)
	}

	if notif.Method == "" {
		return fmt.Errorf("method is required")
	}

	return nil
}

// ParseMessage parse un message JSON-RPC (request, response ou notification)
func ParseMessage(data []byte) (interface{}, error) {
	// D'abord, on essaie de détecter le type
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parse error: %w", err)
	}

	// Vérifier la version JSON-RPC
	if version, ok := raw["jsonrpc"].(string); !ok || version != JSONRPCVersion {
		return nil, fmt.Errorf("invalid or missing jsonrpc version")
	}

	// Si pas d'ID, c'est une notification
	if _, hasID := raw["id"]; !hasID {
		var notif Notification
		if err := json.Unmarshal(data, &notif); err != nil {
			return nil, fmt.Errorf("failed to parse notification: %w", err)
		}
		return &notif, nil
	}

	// Si on a "result" ou "error", c'est une réponse
	if _, hasResult := raw["result"]; hasResult {
		var resp Response
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse response: %w", err)
		}
		return &resp, nil
	}

	if _, hasError := raw["error"]; hasError {
		var resp Response
		if err := json.Unmarshal(data, &resp); err != nil {
			return nil, fmt.Errorf("failed to parse error response: %w", err)
		}
		return &resp, nil
	}

	// Sinon, c'est une requête
	var req Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to parse request: %w", err)
	}

	return &req, nil
}

