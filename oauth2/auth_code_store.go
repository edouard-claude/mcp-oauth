package oauth2

import (
	"sync"
	"time"
)

// AuthorizationCode représente un code d'autorisation temporaire
type AuthorizationCode struct {
	Code          string
	ClientID      string
	RedirectURI   string
	CodeChallenge string
	CodeChallengeMethod string
	Scopes        []string
	State         string
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

// AuthCodeStore gère le stockage des codes d'autorisation
type AuthCodeStore struct {
	codes map[string]*AuthorizationCode
	mu    sync.RWMutex
	// Durée de vie des codes (10 minutes par défaut)
	ttl time.Duration
}

// NewAuthCodeStore crée un nouveau store de codes d'autorisation
func NewAuthCodeStore() *AuthCodeStore {
	store := &AuthCodeStore{
		codes: make(map[string]*AuthorizationCode),
		ttl:   10 * time.Minute,
	}
	// Démarrer le nettoyage périodique des codes expirés
	go store.cleanupExpired()
	return store
}

// Store stocke un code d'autorisation
func (acs *AuthCodeStore) Store(code string, clientID, redirectURI, codeChallenge, codeChallengeMethod string, scopes []string, state string) {
	now := time.Now()
	authCode := &AuthorizationCode{
		Code:                code,
		ClientID:            clientID,
		RedirectURI:         redirectURI,
		CodeChallenge:       codeChallenge,
		CodeChallengeMethod: codeChallengeMethod,
		Scopes:              scopes,
		State:               state,
		CreatedAt:           now,
		ExpiresAt:            now.Add(acs.ttl),
	}

	acs.mu.Lock()
	acs.codes[code] = authCode
	acs.mu.Unlock()
}

// Get récupère un code d'autorisation
func (acs *AuthCodeStore) Get(code string) (*AuthorizationCode, bool) {
	acs.mu.RLock()
	defer acs.mu.RUnlock()

	authCode, exists := acs.codes[code]
	if !exists {
		return nil, false
	}

	// Vérifier l'expiration
	if time.Now().After(authCode.ExpiresAt) {
		// Le code est expiré, le supprimer
		acs.mu.RUnlock()
		acs.mu.Lock()
		delete(acs.codes, code)
		acs.mu.Unlock()
		acs.mu.RLock()
		return nil, false
	}

	// Retourner une copie pour éviter les modifications externes
	codeCopy := *authCode
	return &codeCopy, true
}

// Delete supprime un code d'autorisation (usage unique)
func (acs *AuthCodeStore) Delete(code string) {
	acs.mu.Lock()
	defer acs.mu.Unlock()
	delete(acs.codes, code)
}

// cleanupExpired nettoie périodiquement les codes expirés
func (acs *AuthCodeStore) cleanupExpired() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		acs.mu.Lock()
		now := time.Now()
		for code, authCode := range acs.codes {
			if now.After(authCode.ExpiresAt) {
				delete(acs.codes, code)
			}
		}
		acs.mu.Unlock()
	}
}

