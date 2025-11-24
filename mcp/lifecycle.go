package mcp

import (
	"encoding/json"
	"fmt"
)

// ProtocolVersion est la version du protocole MCP supportée
const ProtocolVersion = "2025-06-18"

// InitializeParams contient les paramètres de la requête initialize
type InitializeParams struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    ClientCapabilities     `json:"capabilities"`
	ClientInfo      ClientInfo             `json:"clientInfo"`
}

// ClientCapabilities représente les capacités du client
type ClientCapabilities struct {
	Roots       *RootsCapability       `json:"roots,omitempty"`
	Sampling    map[string]interface{} `json:"sampling,omitempty"`
	Elicitation map[string]interface{} `json:"elicitation,omitempty"`
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

// RootsCapability représente les capacités roots
type RootsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ClientInfo contient les informations sur le client
type ClientInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

// InitializeResult contient le résultat de la requête initialize
type InitializeResult struct {
	ProtocolVersion string                 `json:"protocolVersion"`
	Capabilities    ServerCapabilities     `json:"capabilities"`
	ServerInfo      ServerInfo             `json:"serverInfo"`
	Instructions    string                 `json:"instructions,omitempty"`
}

// ServerCapabilities représente les capacités du serveur
type ServerCapabilities struct {
	Logging     map[string]interface{} `json:"logging,omitempty"`
	Prompts     *PromptsCapability      `json:"prompts,omitempty"`
	Resources   *ResourcesCapability    `json:"resources,omitempty"`
	Tools       *ToolsCapability        `json:"tools,omitempty"`
	Completions map[string]interface{}  `json:"completions,omitempty"`
	Experimental map[string]interface{} `json:"experimental,omitempty"`
}

// PromptsCapability représente les capacités prompts
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability représente les capacités resources
type ResourcesCapability struct {
	Subscribe  bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// ToolsCapability représente les capacités tools
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ServerInfo contient les informations sur le serveur
type ServerInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

// HandleInitialize gère la requête initialize
func HandleInitialize(params json.RawMessage) (*InitializeResult, error) {
	var initParams InitializeParams
	if err := json.Unmarshal(params, &initParams); err != nil {
		return nil, fmt.Errorf("invalid initialize params: %w", err)
	}

	// Négociation de version
	negotiatedVersion := ProtocolVersion
	if initParams.ProtocolVersion != ProtocolVersion {
		// Le serveur peut supporter d'autres versions, mais pour l'instant on utilise la version fixe
		negotiatedVersion = ProtocolVersion
	}

	// Construction des capacités du serveur
	capabilities := ServerCapabilities{
		Logging: map[string]interface{}{},
		Prompts: &PromptsCapability{
			ListChanged: true,
		},
		Resources: &ResourcesCapability{
			Subscribe:   true,
			ListChanged: true,
		},
		Tools: &ToolsCapability{
			ListChanged: true,
		},
	}

	result := &InitializeResult{
		ProtocolVersion: negotiatedVersion,
		Capabilities:    capabilities,
		ServerInfo: ServerInfo{
			Name:    "oauth2-mcp",
			Title:   "OAuth2 MCP Server",
			Version: "1.0.0",
		},
		Instructions: "OAuth2 MCP Server - Ready to handle requests",
	}

	return result, nil
}

// InitializedNotification représente la notification initialized
type InitializedNotification struct {
	Method string `json:"method"`
}

// NewInitializedNotification crée une notification initialized
func NewInitializedNotification() *Notification {
	return &Notification{
		JSONRPC: JSONRPCVersion,
		Method:  "notifications/initialized",
	}
}

