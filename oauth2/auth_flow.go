package oauth2

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"
)

// AuthFlow gère le flux d'autorisation OAuth2
type AuthFlow struct {
	httpClient *http.Client
}

// NewAuthFlow crée un nouveau gestionnaire de flux d'autorisation
func NewAuthFlow() *AuthFlow {
	return &AuthFlow{
		httpClient: &http.Client{},
	}
}

// AuthorizationRequest représente une requête d'autorisation
type AuthorizationRequest struct {
	AuthorizationEndpoint string
	ClientID             string
	RedirectURI          string
	Resource             string
	Scopes               []string
	State                string
	CodeChallenge        string
	CodeChallengeMethod  string
}

// BuildAuthorizationURL construit l'URL d'autorisation avec tous les paramètres requis
func (af *AuthFlow) BuildAuthorizationURL(req *AuthorizationRequest) (string, error) {
	authURL, err := url.Parse(req.AuthorizationEndpoint)
	if err != nil {
		return "", fmt.Errorf("invalid authorization endpoint: %w", err)
	}

	params := url.Values{}
	params.Set("response_type", "code")
	params.Set("client_id", req.ClientID)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("resource", req.Resource) // RFC8707
	params.Set("code_challenge", req.CodeChallenge)
	params.Set("code_challenge_method", req.CodeChallengeMethod)
	params.Set("state", req.State)

	if len(req.Scopes) > 0 {
		params.Set("scope", joinScopes(req.Scopes))
	}

	authURL.RawQuery = params.Encode()
	return authURL.String(), nil
}

// TokenRequest représente une requête de token
type TokenRequest struct {
	TokenEndpoint string
	ClientID      string
	Code          string
	RedirectURI   string
	CodeVerifier  string
	Resource      string
}

// TokenResponse représente la réponse du token endpoint
type TokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in,omitempty"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// ExchangeCodeForToken échange un code d'autorisation contre un token
func (af *AuthFlow) ExchangeCodeForToken(req *TokenRequest) (*TokenResponse, error) {
	// Construire les paramètres
	params := url.Values{}
	params.Set("grant_type", "authorization_code")
	params.Set("code", req.Code)
	params.Set("redirect_uri", req.RedirectURI)
	params.Set("code_verifier", req.CodeVerifier)
	params.Set("resource", req.Resource) // RFC8707

	// Créer la requête HTTP
	httpReq, err := http.NewRequest("POST", req.TokenEndpoint, bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	// Authentification client (si nécessaire)
	// Pour les clients publics, pas d'authentification
	// Pour les clients confidentiels, utiliser Basic Auth ou client_secret_post
	if req.ClientID != "" {
		// Ici on pourrait ajouter l'authentification si nécessaire
	}

	// Envoyer la requête
	resp, err := af.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send token request: %w", err)
	}
	defer resp.Body.Close()

	// Vérifier le code de statut
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errorResp)
		return nil, fmt.Errorf("token request failed with status %d: %v", resp.StatusCode, errorResp)
	}

	// Parser la réponse
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	// Validation
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("access_token is missing in token response")
	}

	if tokenResp.TokenType == "" {
		tokenResp.TokenType = "Bearer" // Par défaut
	}

	return &tokenResp, nil
}

// RefreshTokenRequest représente une requête de rafraîchissement de token
type RefreshTokenRequest struct {
	TokenEndpoint string
	ClientID      string
	RefreshToken  string
	Resource      string
}

// RefreshToken échange un refresh token contre un nouveau access token
func (af *AuthFlow) RefreshToken(req *RefreshTokenRequest) (*TokenResponse, error) {
	// Construire les paramètres
	params := url.Values{}
	params.Set("grant_type", "refresh_token")
	params.Set("refresh_token", req.RefreshToken)
	params.Set("resource", req.Resource) // RFC8707

	// Créer la requête HTTP
	httpReq, err := http.NewRequest("POST", req.TokenEndpoint, bytes.NewBufferString(params.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	httpReq.Header.Set("Accept", "application/json")

	// Envoyer la requête
	resp, err := af.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("failed to send refresh token request: %w", err)
	}
	defer resp.Body.Close()

	// Vérifier le code de statut
	if resp.StatusCode != http.StatusOK {
		var errorResp map[string]interface{}
		json.NewDecoder(resp.Body).Decode(&errorResp)
		return nil, fmt.Errorf("refresh token request failed with status %d: %v", resp.StatusCode, errorResp)
	}

	// Parser la réponse
	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh token response: %w", err)
	}

	// Validation
	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("access_token is missing in refresh token response")
	}

	if tokenResp.TokenType == "" {
		tokenResp.TokenType = "Bearer"
	}

	return &tokenResp, nil
}

// GenerateState génère un paramètre state sécurisé
func GenerateState() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate state: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}

// joinScopes joint les scopes avec des espaces
func joinScopes(scopes []string) string {
	result := ""
	for i, scope := range scopes {
		if i > 0 {
			result += " "
		}
		result += scope
	}
	return result
}

// TokenInfo représente les informations sur un token
type TokenInfo struct {
	AccessToken  string
	RefreshToken string
	TokenType    string
	ExpiresAt    time.Time
	Scopes       []string
}

// NewTokenInfo crée un TokenInfo depuis une TokenResponse
func NewTokenInfo(resp *TokenResponse) *TokenInfo {
	expiresAt := time.Now()
	if resp.ExpiresIn > 0 {
		expiresAt = expiresAt.Add(time.Duration(resp.ExpiresIn) * time.Second)
	}

	scopes := []string{}
	if resp.Scope != "" {
		scopes = splitScopes(resp.Scope)
	}

	return &TokenInfo{
		AccessToken:  resp.AccessToken,
		RefreshToken: resp.RefreshToken,
		TokenType:    resp.TokenType,
		ExpiresAt:    expiresAt,
		Scopes:       scopes,
	}
}

// splitScopes divise une chaîne de scopes en liste
func splitScopes(scopeStr string) []string {
	if scopeStr == "" {
		return []string{}
	}
	scopes := []string{}
	for _, scope := range bytes.Fields([]byte(scopeStr)) {
		scopes = append(scopes, string(scope))
	}
	return scopes
}

