package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// TokenValidator valide les tokens OAuth2 selon OAuth 2.1 Section 5.2
type TokenValidator struct {
	resourceURI string
	httpClient  *http.Client
	jwtSecret   string // Secret pour vérifier la signature JWT (si mode serveur intégré)
}

// NewTokenValidator crée un nouveau validateur de tokens
func NewTokenValidator(resourceURI string, jwtSecret string) *TokenValidator {
	return &TokenValidator{
		resourceURI: resourceURI,
		httpClient:  &http.Client{},
		jwtSecret:   jwtSecret,
	}
}

// TokenValidationResult représente le résultat de la validation
type TokenValidationResult struct {
	Valid     bool
	Audience  []string
	ExpiresAt time.Time
	IssuedAt  time.Time
	Scopes    []string
	Subject   string
	Error     error
}

// ValidateToken valide un token selon OAuth 2.1 Section 5.2
// Pour une implémentation complète, on devrait :
// 1. Vérifier la signature (si JWT)
// 2. Vérifier l'expiration
// 3. Vérifier l'audience (RFC8707)
// 4. Vérifier l'issuer
// 5. Optionnellement, faire un introspection request
func (tv *TokenValidator) ValidateToken(token string) (*TokenValidationResult, error) {
	// Pour l'instant, on fait une validation basique
	// Dans une implémentation complète, on devrait :
	// - Parser le JWT si c'est un JWT
	// - Vérifier la signature
	// - Vérifier les claims

	// Essayer de parser comme JWT
	parts := strings.Split(token, ".")
	if len(parts) == 3 {
		// C'est probablement un JWT
		return tv.validateJWT(token)
	}

	// Sinon, on pourrait faire une introspection request
	// Pour l'instant, on retourne une validation basique
	return &TokenValidationResult{
		Valid: true, // Validation basique - à améliorer
	}, nil
}

// validateJWT valide un JWT token
func (tv *TokenValidator) validateJWT(token string) (*TokenValidationResult, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return &TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("invalid JWT format"),
		}, nil
	}

	// Décoder le header pour vérifier l'algorithme
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return &TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("failed to decode JWT header: %w", err),
		}, nil
	}

	var headerClaims map[string]interface{}
	if err := json.Unmarshal(header, &headerClaims); err != nil {
		return &TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("failed to parse JWT header: %w", err),
		}, nil
	}

	// Vérifier l'algorithme
	if alg, ok := headerClaims["alg"].(string); ok {
		if alg != "HS256" {
			return &TokenValidationResult{
				Valid: false,
				Error: fmt.Errorf("unsupported JWT algorithm: %s", alg),
			}, nil
		}
	}

	// Vérifier la signature si jwtSecret est fourni
	if tv.jwtSecret != "" {
		if !tv.verifyJWTSignature(token, parts) {
			return &TokenValidationResult{
				Valid: false,
				Error: fmt.Errorf("invalid JWT signature"),
			}, nil
		}
	}

	// Décoder le payload
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return &TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("failed to decode JWT payload: %w", err),
		}, nil
	}

	var claims map[string]interface{}
	if err := json.Unmarshal(payload, &claims); err != nil {
		return &TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("failed to parse JWT claims: %w", err),
		}, nil
	}

	result := &TokenValidationResult{
		Valid: true,
	}

	// Extraire l'audience
	if aud, ok := claims["aud"].(string); ok {
		result.Audience = []string{aud}
	} else if audArray, ok := claims["aud"].([]interface{}); ok {
		for _, a := range audArray {
			if aStr, ok := a.(string); ok {
				result.Audience = append(result.Audience, aStr)
			}
		}
	}

	// Vérifier que le token est destiné à cette ressource
	// Si l'audience est vide, on accepte (pour compatibilité)
	if len(result.Audience) > 0 && !tv.validateAudience(result.Audience) {
		return &TokenValidationResult{
			Valid: false,
			Error: fmt.Errorf("token audience does not match resource URI"),
		}, nil
	}

	// Extraire l'expiration
	if exp, ok := claims["exp"].(float64); ok {
		result.ExpiresAt = time.Unix(int64(exp), 0)
		if time.Now().After(result.ExpiresAt) {
			return &TokenValidationResult{
				Valid: false,
				Error: fmt.Errorf("token has expired"),
			}, nil
		}
	}

	// Extraire l'issued at
	if iat, ok := claims["iat"].(float64); ok {
		result.IssuedAt = time.Unix(int64(iat), 0)
	}

	// Extraire les scopes
	if scope, ok := claims["scope"].(string); ok {
		result.Scopes = strings.Fields(scope)
	}

	// Extraire le subject
	if sub, ok := claims["sub"].(string); ok {
		result.Subject = sub
	}

	return result, nil
}

// validateAudience valide que l'audience contient l'URI de la ressource
func (tv *TokenValidator) validateAudience(audiences []string) bool {
	if len(audiences) == 0 {
		// Si pas d'audience, on accepte (pour compatibilité)
		return true
	}

	// Normaliser l'URI de la ressource
	normalizedResource := strings.ToLower(strings.TrimSpace(tv.resourceURI))
	// Retirer le trailing slash pour comparaison
	normalizedResource = strings.TrimSuffix(normalizedResource, "/")

	for _, aud := range audiences {
		normalizedAud := strings.ToLower(strings.TrimSpace(aud))
		normalizedAud = strings.TrimSuffix(normalizedAud, "/")

		// Vérifier si l'audience correspond exactement
		if normalizedAud == normalizedResource {
			return true
		}
		// Vérifier si l'audience est un préfixe de la ressource
		if normalizedResource != "" && strings.HasPrefix(normalizedResource, normalizedAud+"/") {
			return true
		}
		// Vérifier si la ressource est un préfixe de l'audience (pour compatibilité)
		if normalizedAud != "" && strings.HasPrefix(normalizedAud, normalizedResource+"/") {
			return true
		}
	}

	return false
}

// verifyJWTSignature vérifie la signature HMAC-SHA256 d'un JWT
func (tv *TokenValidator) verifyJWTSignature(token string, parts []string) bool {
	if len(parts) != 3 {
		return false
	}

	// Reconstruire le message signé (header.payload)
	signatureInput := fmt.Sprintf("%s.%s", parts[0], parts[1])

	// Calculer la signature attendue
	mac := hmac.New(sha256.New, []byte(tv.jwtSecret))
	mac.Write([]byte(signatureInput))
	expectedSignature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Comparer avec la signature fournie
	return hmac.Equal([]byte(expectedSignature), []byte(parts[2]))
}

// ExtractTokenFromHeader extrait le token du header Authorization
func ExtractTokenFromHeader(header string) (string, error) {
	// Format: "Bearer <token>"
	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid Authorization header format")
	}

	if strings.ToLower(parts[0]) != "bearer" {
		return "", fmt.Errorf("unsupported authorization scheme: %s", parts[0])
	}

	return parts[1], nil
}

// TokenStorage gère le stockage des tokens
type TokenStorage struct {
	tokens map[string]*TokenInfo
	mu     sync.RWMutex
}

// NewTokenStorage crée un nouveau stockage de tokens
func NewTokenStorage() *TokenStorage {
	return &TokenStorage{
		tokens: make(map[string]*TokenInfo),
	}
}

// Store stocke un token
func (ts *TokenStorage) Store(key string, token *TokenInfo) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	ts.tokens[key] = token
}

// Get récupère un token
func (ts *TokenStorage) Get(key string) (*TokenInfo, bool) {
	ts.mu.RLock()
	defer ts.mu.RUnlock()
	token, exists := ts.tokens[key]
	return token, exists
}

// Delete supprime un token
func (ts *TokenStorage) Delete(key string) {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	delete(ts.tokens, key)
}

// IsExpired vérifie si un token est expiré
func (ti *TokenInfo) IsExpired() bool {
	return time.Now().After(ti.ExpiresAt)
}

// NeedsRefresh vérifie si un token a besoin d'être rafraîchi
func (ti *TokenInfo) NeedsRefresh() bool {
	// Rafraîchir si le token expire dans moins de 5 minutes
	return time.Until(ti.ExpiresAt) < 5*time.Minute
}
