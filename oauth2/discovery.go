package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ProtectedResourceMetadata représente les métadonnées de ressource protégée (RFC9728)
type ProtectedResourceMetadata struct {
	Resource                string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported         []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
}

// AuthorizationServerMetadata représente les métadonnées du serveur d'autorisation (RFC8414)
type AuthorizationServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported  []string `json:"token_endpoint_auth_methods_supported,omitempty"`
}

// DiscoveryClient gère la découverte OAuth2
type DiscoveryClient struct {
	httpClient *http.Client
}

// NewDiscoveryClient crée un nouveau client de découverte
func NewDiscoveryClient() *DiscoveryClient {
	return &DiscoveryClient{
		httpClient: &http.Client{},
	}
}

// GetProtectedResourceMetadata récupère les métadonnées de ressource protégée (RFC9728)
func (dc *DiscoveryClient) GetProtectedResourceMetadata(resourceServerURL string) (*ProtectedResourceMetadata, error) {
	// Construire l'URL du endpoint de métadonnées
	baseURL, err := url.Parse(resourceServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid resource server URL: %w", err)
	}

	metadataURL := baseURL.ResolveReference(&url.URL{Path: "/.well-known/oauth-protected-resource"})

	// Faire la requête
	resp, err := dc.httpClient.Get(metadataURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch resource metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parser la réponse
	var metadata ProtectedResourceMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse resource metadata: %w", err)
	}

	// Validation
	if len(metadata.AuthorizationServers) == 0 {
		return nil, fmt.Errorf("no authorization servers found in metadata")
	}

	return &metadata, nil
}

// GetAuthorizationServerMetadata récupère les métadonnées du serveur d'autorisation (RFC8414)
func (dc *DiscoveryClient) GetAuthorizationServerMetadata(authorizationServerURL string) (*AuthorizationServerMetadata, error) {
	// Construire l'URL du endpoint de métadonnées
	baseURL, err := url.Parse(authorizationServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization server URL: %w", err)
	}

	metadataURL := baseURL.ResolveReference(&url.URL{Path: "/.well-known/oauth-authorization-server"})

	// Faire la requête
	resp, err := dc.httpClient.Get(metadataURL.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch authorization server metadata: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	// Parser la réponse
	var metadata AuthorizationServerMetadata
	if err := json.NewDecoder(resp.Body).Decode(&metadata); err != nil {
		return nil, fmt.Errorf("failed to parse authorization server metadata: %w", err)
	}

	// Validation des champs requis
	if metadata.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if metadata.AuthorizationEndpoint == "" {
		return nil, fmt.Errorf("authorization_endpoint is required")
	}
	if metadata.TokenEndpoint == "" {
		return nil, fmt.Errorf("token_endpoint is required")
	}

	return &metadata, nil
}

// ParseWWWAuthenticateHeader parse le header WWW-Authenticate pour extraire l'URL de métadonnées
func ParseWWWAuthenticateHeader(header string) (string, error) {
	// Format: Bearer realm="...", resource_metadata="..."
	// On cherche resource_metadata="..."
	
	// Parsing simple (pour une implémentation complète, utiliser un parser plus robuste)
	start := "resource_metadata=\""
	startIdx := -1
	for i := 0; i < len(header)-len(start); i++ {
		if header[i:i+len(start)] == start {
			startIdx = i + len(start)
			break
		}
	}

	if startIdx == -1 {
		return "", fmt.Errorf("resource_metadata not found in WWW-Authenticate header")
	}

	// Trouver la fin (guillemet fermant)
	endIdx := startIdx
	for endIdx < len(header) && header[endIdx] != '"' {
		endIdx++
	}

	if endIdx >= len(header) {
		return "", fmt.Errorf("malformed WWW-Authenticate header")
	}

	metadataURL := header[startIdx:endIdx]
	return metadataURL, nil
}

