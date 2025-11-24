package config

import (
	"fmt"
	"os"
	"strconv"
)

// Config contient toute la configuration du serveur
type Config struct {
	// MCP Server
	ServerURL string
	Port      int

	// OAuth2
	AuthorizationServer string
	ClientID           string
	ClientSecret       string
	RedirectURI        string
	Scopes             string
	JWTSecret          string

	// Session
	SessionSecret string
}

// Load charge la configuration depuis les variables d'environnement
func Load() (*Config, error) {
	cfg := &Config{
		ServerURL: getEnv("MCP_SERVER_URL", "http://localhost:8080"),
		Port:      getEnvAsInt("MCP_PORT", 8080),

		AuthorizationServer: getEnv("OAUTH2_AUTHORIZATION_SERVER", ""),
		ClientID:           getEnv("OAUTH2_CLIENT_ID", ""),
		ClientSecret:       getEnv("OAUTH2_CLIENT_SECRET", ""),
		RedirectURI:        getEnv("OAUTH2_REDIRECT_URI", "http://localhost:8080/callback"),
		Scopes:             getEnv("OAUTH2_SCOPES", "openid"),
		JWTSecret:          getEnv("OAUTH2_JWT_SECRET", ""),

		SessionSecret: getEnv("MCP_SESSION_SECRET", ""),
	}

	// Si AuthorizationServer n'est pas défini, utiliser ServerURL (mode serveur d'autorisation intégré)
	originalAuthServer := cfg.AuthorizationServer
	if cfg.AuthorizationServer == "" {
		cfg.AuthorizationServer = cfg.ServerURL
	}

	// Validation
	if cfg.SessionSecret == "" {
		return nil, fmt.Errorf("MCP_SESSION_SECRET is required")
	}

	// Si en mode serveur d'autorisation intégré (vide ou égal à ServerURL), JWTSecret est requis
	isIntegratedAuthServer := originalAuthServer == "" || originalAuthServer == cfg.ServerURL
	if isIntegratedAuthServer && cfg.JWTSecret == "" {
		return nil, fmt.Errorf("OAUTH2_JWT_SECRET is required when using integrated authorization server")
	}

	return cfg, nil
}

func getEnv(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvAsInt(key string, defaultValue int) int {
	valueStr := os.Getenv(key)
	if valueStr == "" {
		return defaultValue
	}
	value, err := strconv.Atoi(valueStr)
	if err != nil {
		return defaultValue
	}
	return value
}

