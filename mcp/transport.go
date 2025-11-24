package mcp

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"oauth2-mcp/internal/config"
)

const (
	HeaderProtocolVersion = "MCP-Protocol-Version"
	HeaderSessionID       = "Mcp-Session-Id"
	HeaderLastEventID     = "Last-Event-ID"
)

// Transport gère le transport HTTP Streamable
type Transport struct {
	config         *config.Config
	sessionManager *SessionManager
	handler        *HandlerRegistry
}

// NewTransport crée un nouveau transport HTTP
func NewTransport(cfg *config.Config, sessionManager *SessionManager, handler *HandlerRegistry) *Transport {
	return &Transport{
		config:         cfg,
		sessionManager: sessionManager,
		handler:        handler,
	}
}

// ServeHTTP implémente http.Handler pour gérer les requêtes MCP
func (t *Transport) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Wrapper pour capturer les paniques
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in Transport.ServeHTTP: %v", rec)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	// Validation de l'Origin pour prévenir DNS rebinding
	if err := t.validateOrigin(r); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	switch r.Method {
	case http.MethodPost:
		t.handlePOST(w, r)
	case http.MethodGet:
		t.handleGET(w, r)
	case http.MethodDelete:
		t.handleDELETE(w, r)
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// validateOrigin valide le header Origin
func (t *Transport) validateOrigin(r *http.Request) error {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Pas d'Origin header, on accepte (pour compatibilité)
		return nil
	}

	// Pour localhost, on accepte
	if strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "https://localhost") {
		return nil
	}

	// Pour les autres origines, on pourrait ajouter une whitelist
	// Pour l'instant, on accepte toutes les origines HTTPS
	if strings.HasPrefix(origin, "https://") {
		return nil
	}

	return fmt.Errorf("invalid origin: %s", origin)
}

// handlePOST gère les requêtes POST (messages JSON-RPC)
func (t *Transport) handlePOST(w http.ResponseWriter, r *http.Request) {
	// Wrapper pour capturer les paniques
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in Transport.handlePOST: %v", rec)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	// Vérifier le header Accept
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "application/json") && !strings.Contains(accept, "text/event-stream") {
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, "Accept header must include application/json or text/event-stream", http.StatusBadRequest)
		return
	}

	// Lire le body
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		w.Header().Set("Content-Type", "application/json")
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	// Parser le message JSON-RPC
	message, err := ParseMessage(body)
	if err != nil {
		log.Printf("Error parsing JSON-RPC message: %v", err)
		w.Header().Set("Content-Type", "application/json")
		resp := NewErrorResponse(nil, ErrParseError)
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Gérer selon le type de message
	switch msg := message.(type) {
	case *Request:
		t.handleRequest(w, r, msg)
	case *Notification:
		t.handleNotification(w, r, msg)
	case *Response:
		w.WriteHeader(http.StatusAccepted)
	default:
		log.Printf("Unknown message type: %T", message)
		w.Header().Set("Content-Type", "application/json")
		resp := NewErrorResponse(nil, ErrInvalidRequest)
		json.NewEncoder(w).Encode(resp)
	}
}

// handleRequest gère une requête JSON-RPC
func (t *Transport) handleRequest(w http.ResponseWriter, r *http.Request, req *Request) {
	// Wrapper pour capturer les paniques
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in Transport.handleRequest: %v", rec)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	// Valider la requête
	if err := ValidateRequest(req); err != nil {
		log.Printf("Request validation failed: %v", err)
		w.Header().Set("Content-Type", "application/json")
		resp := NewErrorResponse(req.ID, &Error{
			Code:    ErrCodeInvalidRequest,
			Message: err.Error(),
		})
		json.NewEncoder(w).Encode(resp)
		return
	}

	// Récupérer ou créer la session
	sessionID := r.Header.Get(HeaderSessionID)
	var session *Session
	if sessionID != "" {
		s, ok := t.sessionManager.GetSession(sessionID)
		if !ok {
			log.Printf("Session not found: %s", sessionID)
			w.Header().Set("Content-Type", "application/json")
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}
		session = s
	}

	// Traiter la requête
	result, err := t.handler.Handle(req, session)
	if err != nil {
		log.Printf("Error handling request %s: %v", req.Method, err)
	}

	// Si c'est une requête initialize, on peut créer une session
	if req.Method == "initialize" && session == nil {
		newSession, err := t.sessionManager.CreateSession()
		if err == nil {
			session = newSession
			w.Header().Set(HeaderSessionID, session.ID)
		} else {
			log.Printf("Error creating session: %v", err)
		}
	}

	// Si on a une session, l'inclure dans les headers
	if session != nil {
		w.Header().Set(HeaderSessionID, session.ID)
		// Exposer le header pour que le client puisse y accéder via JavaScript
		exposeHeaders := w.Header().Get("Access-Control-Expose-Headers")
		if exposeHeaders == "" {
			w.Header().Set("Access-Control-Expose-Headers", HeaderSessionID)
		} else {
			w.Header().Set("Access-Control-Expose-Headers", exposeHeaders+", "+HeaderSessionID)
		}
	}

	// Vérifier si on doit utiliser SSE ou JSON simple
	// Pour les requêtes initialize, on utilise toujours JSON pour la compatibilité
	accept := r.Header.Get("Accept")
	useSSE := strings.Contains(accept, "text/event-stream") && req.Method != "initialize"

	if useSSE {
		t.sendSSEResponse(w, req.ID, result, err)
	} else {
		t.sendJSONResponse(w, req.ID, result, err)
	}
}

// handleNotification gère une notification JSON-RPC
func (t *Transport) handleNotification(w http.ResponseWriter, r *http.Request, notif *Notification) {
	// Valider la notification
	if err := ValidateNotification(notif); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// Traiter la notification (pas de réponse)
	t.handler.HandleNotification(notif)

	// Retourner 202 Accepted
	w.WriteHeader(http.StatusAccepted)
}

// sendJSONResponse envoie une réponse JSON simple
func (t *Transport) sendJSONResponse(w http.ResponseWriter, id interface{}, result interface{}, err error) {
	w.Header().Set("Content-Type", "application/json")

	var resp *Response
	if err != nil {
		log.Printf("Error in request handler: %v", err)
		resp = NewErrorResponse(id, &Error{
			Code:    ErrCodeInternalError,
			Message: err.Error(),
		})
		w.WriteHeader(http.StatusOK) // JSON-RPC utilise toujours 200, même pour les erreurs
	} else {
		var respErr error
		resp, respErr = NewSuccessResponse(id, result)
		if respErr != nil {
			log.Printf("Error marshaling result: %v", respErr)
			resp = NewErrorResponse(id, ErrInternalError)
		}
		w.WriteHeader(http.StatusOK)
	}

	// Encoder la réponse JSON
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		log.Printf("Error encoding JSON response: %v", err)
		// L'erreur est loggée, mais on ne peut plus modifier la réponse à ce stade
	}
}

// sendSSEResponse envoie une réponse via Server-Sent Events
func (t *Transport) sendSSEResponse(w http.ResponseWriter, id interface{}, result interface{}, err error) {
	// Wrapper pour capturer les paniques
	defer func() {
		if rec := recover(); rec != nil {
			log.Printf("Panic in sendSSEResponse: %v", rec)
			http.Error(w, "Internal server error", http.StatusInternalServerError)
		}
	}()

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		// Fallback vers JSON si SSE n'est pas supporté
		t.sendJSONResponse(w, id, result, err)
		return
	}

	// Construire la réponse
	var resp *Response
	if err != nil {
		resp = NewErrorResponse(id, &Error{
			Code:    ErrCodeInternalError,
			Message: err.Error(),
		})
	} else {
		var respErr error
		resp, respErr = NewSuccessResponse(id, result)
		if respErr != nil {
			resp = NewErrorResponse(id, ErrInternalError)
		}
	}

	// Écrire le status code avant d'écrire le body
	w.WriteHeader(http.StatusOK)

	// Envoyer la réponse comme événement SSE
	respJSON, err := json.Marshal(resp)
	if err != nil {
		log.Printf("Error marshaling SSE response: %v", err)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	fmt.Fprintf(w, "data: %s\n\n", respJSON)

	flusher.Flush()
}

// handleGET gère les requêtes GET (SSE stream)
func (t *Transport) handleGET(w http.ResponseWriter, r *http.Request) {
	accept := r.Header.Get("Accept")
	if !strings.Contains(accept, "text/event-stream") {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Récupérer la session
	sessionID := r.Header.Get(HeaderSessionID)

	var session *Session
	if sessionID == "" {
		// Si pas de session ID, créer une nouvelle session pour le stream SSE
		newSession, err := t.sessionManager.CreateSession()
		if err != nil {
			log.Printf("Error creating session: %v", err)
			http.Error(w, "Failed to create session", http.StatusInternalServerError)
			return
		}
		session = newSession
		sessionID = session.ID
		// Inclure le session ID dans les headers de réponse
		w.Header().Set(HeaderSessionID, sessionID)
		w.Header().Set("Access-Control-Expose-Headers", HeaderSessionID)
	} else {
		// Session ID fourni, récupérer la session existante
		_, ok := t.sessionManager.GetSession(sessionID)
		if !ok {
			log.Printf("Session not found: %s", sessionID)
			http.Error(w, "Session not found", http.StatusNotFound)
			return
		}
		// Inclure le session ID dans les headers de réponse
		w.Header().Set(HeaderSessionID, sessionID)
		w.Header().Set("Access-Control-Expose-Headers", HeaderSessionID)
	}

	// Configurer les headers SSE
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "SSE not supported", http.StatusInternalServerError)
		return
	}

	// Écrire le status code avant d'envoyer des données
	w.WriteHeader(http.StatusOK)

	// Envoyer un événement initial pour confirmer la connexion
	fmt.Fprintf(w, ": connected\n\n")
	flusher.Flush()

	// Pour l'instant, on garde la connexion ouverte
	// Dans une implémentation complète, on pourrait gérer les messages serveur->client ici
	// et supporter la résumabilité avec Last-Event-ID

	// Garder la connexion ouverte jusqu'à ce que le contexte soit annulé
	// Utiliser un channel pour détecter la fermeture de la connexion
	// Créer un ticker pour envoyer des keep-alive périodiques (toutes les 30 secondes)
	// Cela aide à maintenir la connexion ouverte et à détecter si le client est toujours connecté
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Channel pour gérer la fermeture
	done := make(chan bool)
	go func() {
		<-r.Context().Done()
		close(done)
	}()

	// Boucle pour maintenir la connexion et envoyer des keep-alive
	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			// Envoyer un commentaire keep-alive pour maintenir la connexion
			if _, err := fmt.Fprintf(w, ": keep-alive\n\n"); err != nil {
				log.Printf("Error sending keep-alive for session %s: %v", sessionID, err)
				return
			}
			flusher.Flush()
		}
	}
}

// handleDELETE gère les requêtes DELETE (terminer session)
func (t *Transport) handleDELETE(w http.ResponseWriter, r *http.Request) {
	sessionID := r.Header.Get(HeaderSessionID)
	if sessionID == "" {
		http.Error(w, "Session ID required", http.StatusBadRequest)
		return
	}

	t.sessionManager.DeleteSession(sessionID)
	w.WriteHeader(http.StatusNoContent)
}

// HandlerRegistry gère l'enregistrement et l'appel des handlers
type HandlerRegistry struct {
	handlers map[string]func(json.RawMessage, *Session) (interface{}, error)
}

// NewHandlerRegistry crée un nouveau registre de handlers
func NewHandlerRegistry() *HandlerRegistry {
	return &HandlerRegistry{
		handlers: make(map[string]func(json.RawMessage, *Session) (interface{}, error)),
	}
}

// Register enregistre un handler pour une méthode
func (hr *HandlerRegistry) Register(method string, handler func(json.RawMessage, *Session) (interface{}, error)) {
	hr.handlers[method] = handler
}

// Handle appelle le handler approprié pour une requête
func (hr *HandlerRegistry) Handle(req *Request, session *Session) (interface{}, error) {
	handler, exists := hr.handlers[req.Method]
	if !exists {
		return nil, fmt.Errorf("method not found: %s", req.Method)
	}

	return handler(req.Params, session)
}

// HandleNotification gère une notification
func (hr *HandlerRegistry) HandleNotification(notif *Notification) {
	handler, exists := hr.handlers[notif.Method]
	if !exists {
		log.Printf("Notification handler not found: %s", notif.Method)
		return
	}

	// Les notifications n'ont pas de session dans ce contexte
	_, err := handler(notif.Params, nil)
	if err != nil {
		log.Printf("Error handling notification %s: %v", notif.Method, err)
	}
}
