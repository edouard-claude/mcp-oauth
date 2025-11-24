package mcp

import (
	"encoding/json"
)

// SetupHandlers configure tous les handlers MCP
func SetupHandlers(registry *HandlerRegistry) {
	// Handler initialize
	registry.Register("initialize", func(params json.RawMessage, session *Session) (interface{}, error) {
		return HandleInitialize(params)
	})

	// Handler initialized (notification)
	registry.Register("notifications/initialized", func(params json.RawMessage, session *Session) (interface{}, error) {
		// C'est une notification, pas de réponse
		return nil, nil
	})

	// Handler ping (utilité)
	registry.Register("ping", func(params json.RawMessage, session *Session) (interface{}, error) {
		return []map[string]interface{}{
			{
				"code":    "unrecognized_keys",
				"keys":    []string{"pong"},
				"path":    []interface{}{},
				"message": "Unrecognized key(s) in object: 'pong'",
			},
		}, nil
	})

	// Handler tools/list
	registry.Register("tools/list", func(params json.RawMessage, session *Session) (interface{}, error) {
		return map[string]interface{}{
			"tools": []interface{}{},
		}, nil
	})

	// Handler resources/list
	registry.Register("resources/list", func(params json.RawMessage, session *Session) (interface{}, error) {
		return map[string]interface{}{
			"resources": []interface{}{},
		}, nil
	})

	// Handler prompts/list
	registry.Register("prompts/list", func(params json.RawMessage, session *Session) (interface{}, error) {
		return map[string]interface{}{
			"prompts": []interface{}{},
		}, nil
	})
}
