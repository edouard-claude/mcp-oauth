package oauth2

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
)

// ClientRegistrationRequest représente une requête d'enregistrement de client (RFC7591)
type ClientRegistrationRequest struct {
	RedirectURIs          []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes            []string `json:"grant_types,omitempty"`
	ResponseTypes         []string `json:"response_types,omitempty"`
	ClientName            string   `json:"client_name,omitempty"`
	ClientURI             string   `json:"client_uri,omitempty"`
	LogoURI               string   `json:"logo_uri,omitempty"`
	Scope                 string   `json:"scope,omitempty"`
	Contacts              []string `json:"contacts,omitempty"`
}

// ClientRegistrationResponse représente la réponse d'enregistrement de client (RFC7591)
type ClientRegistrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt  int64    `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string `json:"redirect_uris,omitempty"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes             []string `json:"grant_types,omitempty"`
	ResponseTypes          []string `json:"response_types,omitempty"`
	ClientName             string   `json:"client_name,omitempty"`
	ClientURI              string   `json:"client_uri,omitempty"`
	LogoURI                string   `json:"logo_uri,omitempty"`
	Scope                  string   `json:"scope,omitempty"`
	Contacts               []string `json:"contacts,omitempty"`
	RegistrationAccessToken string   `json:"registration_access_token,omitempty"`
	RegistrationClientURI  string   `json:"registration_client_uri,omitempty"`
}

// RegistrationClient gère l'enregistrement dynamique de client
type RegistrationClient struct {
	httpClient *http.Client
}

// NewRegistrationClient crée un nouveau client d'enregistrement
func NewRegistrationClient() *RegistrationClient {
	return &RegistrationClient{
		httpClient: &http.Client{},
	}
}

// RegisterClient enregistre un nouveau client auprès du serveur d'autorisation (RFC7591)
func (rc *RegistrationClient) RegisterClient(registrationEndpoint string, request *ClientRegistrationRequest) (*ClientRegistrationResponse, error) {
	// Construire l'URL
	regURL, err := url.Parse(registrationEndpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid registration endpoint URL: %w", err)
	}

	// Préparer la requête
	reqBody, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal registration request: %w", err)
	}

	// Créer la requête HTTP
	httpReq, err := http.NewRequest("POST", regURL.String(), bytes.NewBuffer(reqBody))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	// Envoyer la requête
	resp, err := rc.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send registration request: %w", err)
	}
	defer resp.Body.Close()

	// Vérifier le code de statut
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errorResp)
		return nil, fmt.Errorf("registration failed with status %d: %v", resp.StatusCode, errorResp)
	}

	// Parser la réponse
	var registrationResp ClientRegistrationResponse
	if err := json.NewDecoder(resp.Body).Decode(&registrationResp); err != nil {
		return nil, fmt.Errorf("failed to parse registration response: %w", err)
	}

	// Validation
	if registrationResp.ClientID == "" {
		return nil, fmt.Errorf("client_id is missing in registration response")
	}

	return &registrationResp, nil
}

// RegisterClientWithDefaults enregistre un client avec des valeurs par défaut pour MCP
func (rc *RegistrationClient) RegisterClientWithDefaults(registrationEndpoint string, redirectURI string) (*ClientRegistrationResponse, error) {
	request := &ClientRegistrationRequest{
		RedirectURIs:          []string{redirectURI},
		TokenEndpointAuthMethod: "none", // Public client, pas d'authentification
		GrantTypes:            []string{"authorization_code"},
		ResponseTypes:         []string{"code"},
		ClientName:            "MCP Client",
		Scope:                 "openid",
	}

	return rc.RegisterClient(registrationEndpoint, request)
}

