package oauth2

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Client représente un client OAuth2 enregistré (RFC7591)
type Client struct {
	ClientID                string    `json:"client_id"`
	ClientSecret            string    `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64     `json:"client_id_issued_at"`
	ClientSecretExpiresAt   int64     `json:"client_secret_expires_at,omitempty"`
	RedirectURIs            []string  `json:"redirect_uris"`
	TokenEndpointAuthMethod string    `json:"token_endpoint_auth_method,omitempty"`
	GrantTypes              []string  `json:"grant_types,omitempty"`
	ResponseTypes           []string  `json:"response_types,omitempty"`
	ClientName              string    `json:"client_name,omitempty"`
	ClientURI               string    `json:"client_uri,omitempty"`
	LogoURI                 string    `json:"logo_uri,omitempty"`
	Scope                   string    `json:"scope,omitempty"`
	Contacts                []string  `json:"contacts,omitempty"`
	RegistrationAccessToken string    `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string    `json:"registration_client_uri,omitempty"`
}

// ClientStore gère le stockage des clients OAuth2
type ClientStore struct {
	clients map[string]*Client
	mu      sync.RWMutex
}

// NewClientStore crée un nouveau store de clients
func NewClientStore() *ClientStore {
	return &ClientStore{
		clients: make(map[string]*Client),
	}
}

// Register enregistre un nouveau client
func (cs *ClientStore) Register(req *ClientRegistrationRequest) (*Client, error) {
	// Générer un client_id aléatoire (32 caractères en base64url = 24 bytes)
	clientIDBytes := make([]byte, 24)
	if _, err := rand.Read(clientIDBytes); err != nil {
		return nil, fmt.Errorf("failed to generate client_id: %w", err)
	}
	clientID := base64.RawURLEncoding.EncodeToString(clientIDBytes)

	// Générer un client_secret si nécessaire (pour clients confidentiels)
	var clientSecret string
	var clientSecretExpiresAt int64
	if req.TokenEndpointAuthMethod != "none" && req.TokenEndpointAuthMethod != "" {
		secretBytes := make([]byte, 32)
		if _, err := rand.Read(secretBytes); err != nil {
			return nil, fmt.Errorf("failed to generate client_secret: %w", err)
		}
		clientSecret = base64.RawURLEncoding.EncodeToString(secretBytes)
		// Secret n'expire jamais par défaut (0)
		clientSecretExpiresAt = 0
	}

	now := time.Now().Unix()

	client := &Client{
		ClientID:                clientID,
		ClientSecret:            clientSecret,
		ClientIDIssuedAt:        now,
		ClientSecretExpiresAt:  clientSecretExpiresAt,
		RedirectURIs:            req.RedirectURIs,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		ClientName:              req.ClientName,
		ClientURI:               req.ClientURI,
		LogoURI:                 req.LogoURI,
		Scope:                   req.Scope,
		Contacts:                req.Contacts,
	}

	// Valeurs par défaut si non spécifiées
	if len(client.GrantTypes) == 0 {
		client.GrantTypes = []string{"authorization_code"}
	}
	if len(client.ResponseTypes) == 0 {
		client.ResponseTypes = []string{"code"}
	}
	if client.TokenEndpointAuthMethod == "" {
		client.TokenEndpointAuthMethod = "none" // Client public par défaut
	}

	cs.mu.Lock()
	cs.clients[clientID] = client
	cs.mu.Unlock()

	return client, nil
}

// Get récupère un client par son client_id
func (cs *ClientStore) Get(clientID string) (*Client, bool) {
	cs.mu.RLock()
	defer cs.mu.RUnlock()
	client, exists := cs.clients[clientID]
	if !exists {
		return nil, false
	}
	// Retourner une copie pour éviter les modifications externes
	clientCopy := *client
	return &clientCopy, true
}

// Delete supprime un client
func (cs *ClientStore) Delete(clientID string) {
	cs.mu.Lock()
	defer cs.mu.Unlock()
	delete(cs.clients, clientID)
}

// ValidateRedirectURI vérifie si un redirect_uri est autorisé pour un client
func (cs *ClientStore) ValidateRedirectURI(clientID, redirectURI string) bool {
	client, exists := cs.Get(clientID)
	if !exists {
		return false
	}

	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true
		}
	}

	return false
}

