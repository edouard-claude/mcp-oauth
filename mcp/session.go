package mcp

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"sync"
	"time"
)

// Session représente une session MCP
type Session struct {
	ID        string
	CreatedAt time.Time
	LastUsed  time.Time
	Data      map[string]interface{}
}

// SessionManager gère les sessions HTTP
type SessionManager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	secret   string
	ttl      time.Duration
}

// NewSessionManager crée un nouveau gestionnaire de sessions
func NewSessionManager(secret string, ttl time.Duration) *SessionManager {
	sm := &SessionManager{
		sessions: make(map[string]*Session),
		secret:   secret,
		ttl:      ttl,
	}

	// Nettoyage périodique des sessions expirées
	go sm.cleanup()

	return sm
}

// GenerateSessionID génère un ID de session sécurisé
func (sm *SessionManager) GenerateSessionID() (string, error) {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return "", fmt.Errorf("failed to generate session ID: %w", err)
	}

	// Encoder en base64url (sans padding)
	sessionID := base64.RawURLEncoding.EncodeToString(bytes)
	return sessionID, nil
}

// CreateSession crée une nouvelle session
func (sm *SessionManager) CreateSession() (*Session, error) {
	id, err := sm.GenerateSessionID()
	if err != nil {
		return nil, err
	}

	session := &Session{
		ID:        id,
		CreatedAt: time.Now(),
		LastUsed:  time.Now(),
		Data:      make(map[string]interface{}),
	}

	sm.mu.Lock()
	sm.sessions[id] = session
	sm.mu.Unlock()

	return session, nil
}

// GetSession récupère une session par son ID
func (sm *SessionManager) GetSession(id string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	session, exists := sm.sessions[id]
	if !exists {
		return nil, false
	}

	// Vérifier si la session est expirée
	if time.Since(session.LastUsed) > sm.ttl {
		return nil, false
	}

	// Mettre à jour le dernier accès
	session.LastUsed = time.Now()

	return session, true
}

// DeleteSession supprime une session
func (sm *SessionManager) DeleteSession(id string) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	delete(sm.sessions, id)
}

// cleanup nettoie les sessions expirées périodiquement
func (sm *SessionManager) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		sm.mu.Lock()
		now := time.Now()
		for id, session := range sm.sessions {
			if now.Sub(session.LastUsed) > sm.ttl {
				delete(sm.sessions, id)
			}
		}
		sm.mu.Unlock()
	}
}

