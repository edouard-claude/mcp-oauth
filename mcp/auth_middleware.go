package mcp

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"oauth2-mcp/internal/config"
	"oauth2-mcp/oauth2"
	"strings"
	"time"
)

const corsAllowedHeaders = "Authorization, Content-Type, MCP-Protocol-Version, Mcp-Session-Id, Last-Event-ID, MCP-Proxy-Token"

// AuthMiddleware gère l'authentification OAuth2
type AuthMiddleware struct {
	config         *config.Config
	tokenValidator *oauth2.TokenValidator
	enabled        bool
	// Stores pour le serveur d'autorisation intégré
	clientStore   *oauth2.ClientStore
	authCodeStore *oauth2.AuthCodeStore
	jwtSecret     string
	// Mode serveur d'autorisation intégré (si AuthorizationServer == ServerURL)
	isIntegratedAuthServer bool
}

// NewAuthMiddleware crée un nouveau middleware d'authentification
func NewAuthMiddleware(cfg *config.Config, enabled bool, clientStore *oauth2.ClientStore, authCodeStore *oauth2.AuthCodeStore) *AuthMiddleware {
	var validator *oauth2.TokenValidator
	if enabled {
		// Passer le jwtSecret au validateur pour vérifier les signatures
		validator = oauth2.NewTokenValidator(cfg.ServerURL, cfg.JWTSecret)
	}

	isIntegrated := cfg.AuthorizationServer == cfg.ServerURL

	return &AuthMiddleware{
		config:                 cfg,
		tokenValidator:         validator,
		enabled:                enabled,
		clientStore:            clientStore,
		authCodeStore:          authCodeStore,
		jwtSecret:              cfg.JWTSecret,
		isIntegratedAuthServer: isIntegrated,
	}
}

// applyCORSHeaders ajoute les headers CORS nécessaires pour les requêtes simples
func (am *AuthMiddleware) applyCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return
	}

	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	w.Header().Set("Access-Control-Allow-Credentials", "true")
}

// RequireAuth vérifie que la requête est authentifiée
func (am *AuthMiddleware) RequireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		am.applyCORSHeaders(w, r)

		// Gérer les requêtes OPTIONS (CORS preflight) - toujours autorisées
		if r.Method == http.MethodOptions {
			am.handleCORS(w, r)
			return
		}

		// Si l'authentification n'est pas activée, passer directement
		if !am.enabled {
			next.ServeHTTP(w, r)
			return
		}

		// Extraire le token du header Authorization
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			am.sendUnauthorized(w, r)
			return
		}

		token, err := oauth2.ExtractTokenFromHeader(authHeader)
		if err != nil {
			am.sendUnauthorized(w, r)
			return
		}

		// Valider le token
		result, err := am.tokenValidator.ValidateToken(token)
		if err != nil {
			// Log l'erreur pour déboguer
			log.Printf("Token validation error: %v", err)
			am.sendUnauthorized(w, r)
			return
		}
		if result == nil || !result.Valid {
			if result != nil && result.Error != nil {
				log.Printf("Token validation failed: %v", result.Error)
			} else {
				log.Printf("Token validation failed: result is nil or invalid")
			}
			am.sendUnauthorized(w, r)
			return
		}

		// Token valide, continuer
		// Wrapper pour capturer les paniques et les convertir en erreurs 500
		defer func() {
			if r := recover(); r != nil {
				log.Printf("Panic in RequireAuth after token validation: %v", r)
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// sendUnauthorized envoie une réponse 401 avec le header WWW-Authenticate
func (am *AuthMiddleware) sendUnauthorized(w http.ResponseWriter, r *http.Request) {
	am.applyCORSHeaders(w, r)

	// Construire l'URL des métadonnées de ressource
	metadataURL := fmt.Sprintf("%s/.well-known/oauth-protected-resource", am.config.ServerURL)

	// Envoyer le header WWW-Authenticate selon RFC9728
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="%s", resource_metadata="%s"`, am.config.ServerURL, metadataURL))
	http.Error(w, "Unauthorized", http.StatusUnauthorized)
}

// handleCORS gère les requêtes OPTIONS (preflight CORS)
func (am *AuthMiddleware) handleCORS(w http.ResponseWriter, r *http.Request) {
	am.applyCORSHeaders(w, r)

	// Pour les endpoints .well-known, limiter aux méthodes de lecture
	if r.URL.Path == "/.well-known/oauth-protected-resource" ||
		r.URL.Path == "/.well-known/oauth-protected-resource/mcp" ||
		r.URL.Path == "/.well-known/oauth-authorization-server" ||
		r.URL.Path == "/.well-known/openid-configuration" {
		w.Header().Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	} else {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
	}
	w.Header().Set("Access-Control-Allow-Headers", corsAllowedHeaders)
	w.Header().Set("Access-Control-Max-Age", "3600")
	w.WriteHeader(http.StatusOK)
}

// ServeProtectedResourceMetadata sert les métadonnées de ressource protégée (RFC9728)
func (am *AuthMiddleware) ServeProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	// Gérer les requêtes OPTIONS (CORS preflight)
	if r.Method == http.MethodOptions {
		am.handleCORS(w, r)
		return
	}

	// Seulement GET est supporté
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	metadata := oauth2.ProtectedResourceMetadata{
		Resource:               am.config.ServerURL,
		AuthorizationServers:   []string{am.config.AuthorizationServer},
		ScopesSupported:        []string{"openid"},
		BearerMethodsSupported: []string{"header"},
	}

	// Ajouter les headers CORS
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)

	// Encoder la réponse JSON
	json.NewEncoder(w).Encode(metadata)
}

// ServeMCPProtectedResourceMetadata sert les métadonnées spécifiques MCP
func (am *AuthMiddleware) ServeMCPProtectedResourceMetadata(w http.ResponseWriter, r *http.Request) {
	// Gérer les requêtes OPTIONS (CORS preflight)
	if r.Method == http.MethodOptions {
		am.handleCORS(w, r)
		return
	}

	// Seulement GET est supporté
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Même métadonnées que l'endpoint principal
	am.ServeProtectedResourceMetadata(w, r)
}

// proxyToAuthorizationServer fait un proxy vers le serveur d'autorisation
func (am *AuthMiddleware) proxyToAuthorizationServer(w http.ResponseWriter, r *http.Request, path string) {
	// Construire l'URL du serveur d'autorisation
	authServerURL := fmt.Sprintf("%s%s", am.config.AuthorizationServer, path)

	// Faire la requête vers le serveur d'autorisation
	resp, err := http.Get(authServerURL)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to fetch from authorization server: %v", err), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copier les headers de la réponse (sauf ceux qui ne doivent pas être copiés)
	for key, values := range resp.Header {
		// Ignorer certains headers
		if key == "Content-Length" {
			continue
		}
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	// Ajouter les headers CORS
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	// Copier le status code
	w.WriteHeader(resp.StatusCode)

	// Copier le body
	io.Copy(w, resp.Body)
}

// ServeAuthorize gère l'endpoint /authorize (GET)
func (am *AuthMiddleware) ServeAuthorize(w http.ResponseWriter, r *http.Request) {
	// Gérer les requêtes OPTIONS (CORS preflight)
	if r.Method == http.MethodOptions {
		am.handleCORS(w, r)
		return
	}

	// Seulement GET est supporté
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Vérifier que nous sommes en mode serveur d'autorisation intégré
	if !am.isIntegratedAuthServer {
		http.Error(w, "Authorization server not integrated", http.StatusInternalServerError)
		return
	}

	// Extraire et valider les paramètres
	clientID := r.URL.Query().Get("client_id")
	redirectURI := r.URL.Query().Get("redirect_uri")
	responseType := r.URL.Query().Get("response_type")
	codeChallenge := r.URL.Query().Get("code_challenge")
	codeChallengeMethod := r.URL.Query().Get("code_challenge_method")
	state := r.URL.Query().Get("state")
	scopesStr := r.URL.Query().Get("scope")

	// Validation des paramètres requis
	if clientID == "" {
		am.sendError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		am.sendError(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if responseType != "code" {
		am.sendError(w, "unsupported_response_type", "response_type must be 'code'", http.StatusBadRequest)
		return
	}
	if codeChallenge == "" {
		am.sendError(w, "invalid_request", "code_challenge is required (PKCE)", http.StatusBadRequest)
		return
	}
	if codeChallengeMethod != "S256" {
		am.sendError(w, "invalid_request", "code_challenge_method must be 'S256'", http.StatusBadRequest)
		return
	}

	// Vérifier que le client existe
	_, exists := am.clientStore.Get(clientID)
	if !exists {
		am.sendError(w, "invalid_client", "client not found", http.StatusBadRequest)
		return
	}

	// Vérifier que le redirect_uri est autorisé
	if !am.clientStore.ValidateRedirectURI(clientID, redirectURI) {
		am.sendError(w, "invalid_request", "redirect_uri not registered for this client", http.StatusBadRequest)
		return
	}

	// Parser les scopes
	var scopes []string
	if scopesStr != "" {
		scopes = strings.Fields(scopesStr)
	} else {
		scopes = []string{"openid"}
	}

	// Générer un code d'autorisation (32+ caractères)
	codeBytes := make([]byte, 32)
	if _, err := rand.Read(codeBytes); err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	authCode := base64.RawURLEncoding.EncodeToString(codeBytes)

	// Stocker le code avec ses métadonnées
	am.authCodeStore.Store(authCode, clientID, redirectURI, codeChallenge, codeChallengeMethod, scopes, state)

	// Construire l'URL de redirection
	redirectURL, err := url.Parse(redirectURI)
	if err != nil {
		am.sendError(w, "invalid_request", "invalid redirect_uri", http.StatusBadRequest)
		return
	}

	params := redirectURL.Query()
	params.Set("code", authCode)
	if state != "" {
		params.Set("state", state)
	}
	redirectURL.RawQuery = params.Encode()

	// Rediriger vers le redirect_uri avec le code
	http.Redirect(w, r, redirectURL.String(), http.StatusFound)
}

// ServeToken gère l'endpoint /token (POST)
func (am *AuthMiddleware) ServeToken(w http.ResponseWriter, r *http.Request) {
	// Gérer les requêtes OPTIONS (CORS preflight)
	if r.Method == http.MethodOptions {
		am.handleCORS(w, r)
		return
	}

	// Seulement POST est supporté
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Vérifier que nous sommes en mode serveur d'autorisation intégré
	if !am.isIntegratedAuthServer {
		http.Error(w, "Authorization server not integrated", http.StatusInternalServerError)
		return
	}

	// Vérifier le Content-Type
	contentType := r.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/x-www-form-urlencoded") {
		am.sendError(w, "invalid_request", "Content-Type must be application/x-www-form-urlencoded", http.StatusBadRequest)
		return
	}

	// Parser le body
	if err := r.ParseForm(); err != nil {
		am.sendError(w, "invalid_request", "failed to parse form", http.StatusBadRequest)
		return
	}

	// Extraire les paramètres
	grantType := r.Form.Get("grant_type")
	code := r.Form.Get("code")
	redirectURI := r.Form.Get("redirect_uri")
	codeVerifier := r.Form.Get("code_verifier")
	clientID := r.Form.Get("client_id")

	// Validation
	if grantType != "authorization_code" {
		am.sendError(w, "unsupported_grant_type", "grant_type must be 'authorization_code'", http.StatusBadRequest)
		return
	}
	if code == "" {
		am.sendError(w, "invalid_request", "code is required", http.StatusBadRequest)
		return
	}
	if redirectURI == "" {
		am.sendError(w, "invalid_request", "redirect_uri is required", http.StatusBadRequest)
		return
	}
	if codeVerifier == "" {
		am.sendError(w, "invalid_request", "code_verifier is required (PKCE)", http.StatusBadRequest)
		return
	}
	if clientID == "" {
		am.sendError(w, "invalid_request", "client_id is required", http.StatusBadRequest)
		return
	}

	// Récupérer le code d'autorisation
	authCode, exists := am.authCodeStore.Get(code)
	if !exists {
		am.sendError(w, "invalid_grant", "authorization code not found or expired", http.StatusBadRequest)
		return
	}

	// Vérifier que le client_id correspond
	if authCode.ClientID != clientID {
		am.sendError(w, "invalid_grant", "client_id mismatch", http.StatusBadRequest)
		am.authCodeStore.Delete(code)
		return
	}

	// Vérifier que le redirect_uri correspond
	if authCode.RedirectURI != redirectURI {
		am.sendError(w, "invalid_grant", "redirect_uri mismatch", http.StatusBadRequest)
		am.authCodeStore.Delete(code)
		return
	}

	// Vérifier PKCE
	if !oauth2.ValidateCodeVerifier(codeVerifier, authCode.CodeChallenge) {
		am.sendError(w, "invalid_grant", "invalid code_verifier", http.StatusBadRequest)
		am.authCodeStore.Delete(code)
		return
	}

	// Supprimer le code (usage unique)
	am.authCodeStore.Delete(code)

	// Générer un JWT token
	if am.jwtSecret == "" {
		http.Error(w, "JWT secret not configured", http.StatusInternalServerError)
		return
	}

	accessToken, err := oauth2.GenerateJWT(
		am.config.ServerURL, // issuer
		"user",              // subject (par défaut pour boilerplate)
		am.config.ServerURL, // audience (ressource)
		authCode.Scopes,     // scopes
		am.jwtSecret,        // secret
		1*time.Hour,         // expiration
	)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}

	// Construire la réponse
	response := map[string]interface{}{
		"access_token": accessToken,
		"token_type":   "Bearer",
		"expires_in":   3600,
		"scope":        strings.Join(authCode.Scopes, " "),
	}

	// Ajouter les headers CORS
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(response)
}

// ServeRegister gère l'endpoint /register (POST, RFC7591)
func (am *AuthMiddleware) ServeRegister(w http.ResponseWriter, r *http.Request) {
	// Gérer les requêtes OPTIONS (CORS preflight)
	if r.Method == http.MethodOptions {
		am.handleCORS(w, r)
		return
	}

	// Seulement POST est supporté
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Vérifier que nous sommes en mode serveur d'autorisation intégré
	if !am.isIntegratedAuthServer {
		http.Error(w, "Authorization server not integrated", http.StatusInternalServerError)
		return
	}

	// Parser la requête JSON
	var req oauth2.ClientRegistrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		am.sendError(w, "invalid_request", "failed to parse JSON", http.StatusBadRequest)
		return
	}

	// Validation minimale
	if len(req.RedirectURIs) == 0 {
		am.sendError(w, "invalid_request", "redirect_uris is required", http.StatusBadRequest)
		return
	}

	// Enregistrer le client
	client, err := am.clientStore.Register(&req)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to register client: %v", err), http.StatusInternalServerError)
		return
	}

	// Construire la réponse
	response := oauth2.ClientRegistrationResponse{
		ClientID:                client.ClientID,
		ClientSecret:            client.ClientSecret,
		ClientIDIssuedAt:        client.ClientIDIssuedAt,
		ClientSecretExpiresAt:   client.ClientSecretExpiresAt,
		RedirectURIs:            client.RedirectURIs,
		TokenEndpointAuthMethod: client.TokenEndpointAuthMethod,
		GrantTypes:              client.GrantTypes,
		ResponseTypes:           client.ResponseTypes,
		ClientName:              client.ClientName,
		ClientURI:               client.ClientURI,
		LogoURI:                 client.LogoURI,
		Scope:                   client.Scope,
		Contacts:                client.Contacts,
	}

	// Ajouter les headers CORS
	origin := r.Header.Get("Origin")
	if origin != "" {
		w.Header().Set("Access-Control-Allow-Origin", origin)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(response)
}

// sendError envoie une réponse d'erreur OAuth2
func (am *AuthMiddleware) sendError(w http.ResponseWriter, errorCode, errorDescription string, statusCode int) {
	response := map[string]string{
		"error":             errorCode,
		"error_description": errorDescription,
	}

	// Ajouter les headers CORS
	origin := w.Header().Get("Origin")
	if origin == "" {
		// Essayer de récupérer depuis la requête si disponible
		// Note: dans ce contexte, on n'a pas accès à la requête, donc on laisse vide
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	json.NewEncoder(w).Encode(response)
}

// ServeAuthorizationServerMetadata sert les métadonnées du serveur d'autorisation
func (am *AuthMiddleware) ServeAuthorizationServerMetadata(w http.ResponseWriter, r *http.Request) {
	// Gérer les requêtes OPTIONS (CORS preflight)
	if r.Method == http.MethodOptions {
		am.handleCORS(w, r)
		return
	}

	// Seulement GET est supporté
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Si nous sommes en mode serveur d'autorisation intégré, servir directement
	if am.isIntegratedAuthServer {
		metadata := oauth2.AuthorizationServerMetadata{
			Issuer:                            am.config.ServerURL,
			AuthorizationEndpoint:             fmt.Sprintf("%s/authorize", am.config.ServerURL),
			TokenEndpoint:                     fmt.Sprintf("%s/token", am.config.ServerURL),
			RegistrationEndpoint:              fmt.Sprintf("%s/register", am.config.ServerURL),
			ScopesSupported:                   []string{"openid"},
			ResponseTypesSupported:            []string{"code"},
			ResponseModesSupported:            []string{"query"},
			GrantTypesSupported:               []string{"authorization_code"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			TokenEndpointAuthMethodsSupported: []string{"none"},
		}

		// Ajouter les headers CORS
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(metadata)
		return
	}

	// Sinon, faire un proxy vers le serveur d'autorisation externe
	am.proxyToAuthorizationServer(w, r, "/.well-known/oauth-authorization-server")
}

// ServeOpenIDConfiguration sert la configuration OpenID Connect
func (am *AuthMiddleware) ServeOpenIDConfiguration(w http.ResponseWriter, r *http.Request) {
	// Gérer les requêtes OPTIONS (CORS preflight)
	if r.Method == http.MethodOptions {
		am.handleCORS(w, r)
		return
	}

	// Seulement GET est supporté
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Si nous sommes en mode serveur d'autorisation intégré, servir directement
	if am.isIntegratedAuthServer {
		// Pour OpenID Connect, on peut retourner les mêmes métadonnées que OAuth2
		// avec quelques champs supplémentaires si nécessaire
		metadata := oauth2.AuthorizationServerMetadata{
			Issuer:                            am.config.ServerURL,
			AuthorizationEndpoint:             fmt.Sprintf("%s/authorize", am.config.ServerURL),
			TokenEndpoint:                     fmt.Sprintf("%s/token", am.config.ServerURL),
			RegistrationEndpoint:              fmt.Sprintf("%s/register", am.config.ServerURL),
			ScopesSupported:                   []string{"openid"},
			ResponseTypesSupported:            []string{"code"},
			ResponseModesSupported:            []string{"query"},
			GrantTypesSupported:               []string{"authorization_code"},
			CodeChallengeMethodsSupported:     []string{"S256"},
			TokenEndpointAuthMethodsSupported: []string{"none"},
		}

		// Ajouter les headers CORS
		origin := r.Header.Get("Origin")
		if origin != "" {
			w.Header().Set("Access-Control-Allow-Origin", origin)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(metadata)
		return
	}

	// Sinon, faire un proxy vers le serveur d'autorisation externe
	am.proxyToAuthorizationServer(w, r, "/.well-known/openid-configuration")
}
