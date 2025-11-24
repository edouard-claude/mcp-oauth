package mcp

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"oauth2-mcp/internal/config"
	"oauth2-mcp/oauth2"
	"time"
)

// Server représente le serveur MCP
type Server struct {
	config         *config.Config
	httpServer     *http.Server
	transport      *Transport
	sessionManager *SessionManager
	authMiddleware *AuthMiddleware
}

// NewServer crée un nouveau serveur MCP
func NewServer(cfg *config.Config, enableAuth bool) (*Server, error) {
	// Créer le gestionnaire de sessions
	sessionManager := NewSessionManager(cfg.SessionSecret, 24*time.Hour)

	// Créer le registre de handlers
	handlerRegistry := NewHandlerRegistry()
	SetupHandlers(handlerRegistry)

	// Créer le transport
	transport := NewTransport(cfg, sessionManager, handlerRegistry)

	// Créer les stores pour le serveur d'autorisation intégré
	clientStore := oauth2.NewClientStore()
	authCodeStore := oauth2.NewAuthCodeStore()

	// Créer le middleware d'authentification
	authMiddleware := NewAuthMiddleware(cfg, enableAuth, clientStore, authCodeStore)

	// Créer le serveur HTTP
	mux := http.NewServeMux()

	// Endpoints pour les métadonnées OAuth2 (publics, pas d'authentification requise)
	// Endpoint pour les métadonnées de ressource protégée (RFC9728)
	metadataHandler := http.HandlerFunc(authMiddleware.ServeProtectedResourceMetadata)
	mux.Handle("/.well-known/oauth-protected-resource", metadataHandler)

	// Endpoint spécifique MCP pour les métadonnées
	mcpMetadataHandler := http.HandlerFunc(authMiddleware.ServeMCPProtectedResourceMetadata)
	mux.Handle("/.well-known/oauth-protected-resource/mcp", mcpMetadataHandler)

	// Endpoint pour les métadonnées du serveur d'autorisation (redirige vers le serveur d'autorisation)
	authServerHandler := http.HandlerFunc(authMiddleware.ServeAuthorizationServerMetadata)
	mux.Handle("/.well-known/oauth-authorization-server", authServerHandler)

	// Endpoint pour la configuration OpenID Connect (redirige vers le serveur d'autorisation)
	openIDHandler := http.HandlerFunc(authMiddleware.ServeOpenIDConfiguration)
	mux.Handle("/.well-known/openid-configuration", openIDHandler)

	// Endpoints OAuth2 pour le serveur d'autorisation intégré (si activé)
	if enableAuth {
		// Endpoint d'autorisation OAuth2
		authorizeHandler := http.HandlerFunc(authMiddleware.ServeAuthorize)
		mux.Handle("/authorize", authorizeHandler)

		// Endpoint de token OAuth2
		tokenHandler := http.HandlerFunc(authMiddleware.ServeToken)
		mux.Handle("/token", tokenHandler)

		// Endpoint d'enregistrement de client (RFC7591)
		registerHandler := http.HandlerFunc(authMiddleware.ServeRegister)
		mux.Handle("/register", registerHandler)
	}

	// Endpoint MCP principal avec chaînage des middlewares
	mcpHandler := authMiddleware.RequireAuth(transport)
	mux.Handle("/mcp", mcpHandler)

	// Pour compatibilité, on peut aussi servir sur la racine
	mux.Handle("/", mcpHandler)

	httpServer := &http.Server{
		Addr:         fmt.Sprintf(":%d", cfg.Port),
		Handler:      mux,
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 15 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	return &Server{
		config:         cfg,
		httpServer:     httpServer,
		transport:      transport,
		sessionManager: sessionManager,
		authMiddleware: authMiddleware,
	}, nil
}

// Start démarre le serveur
func (s *Server) Start() error {
	log.Printf("Starting MCP server on port %d", s.config.Port)
	log.Printf("Server URL: %s", s.config.ServerURL)
	if s.authMiddleware.enabled {
		log.Printf("OAuth2 authentication enabled")
		log.Printf("Authorization Server: %s", s.config.AuthorizationServer)
	} else {
		log.Printf("OAuth2 authentication disabled")
	}

	if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("server failed to start: %w", err)
	}

	return nil
}

// Shutdown arrête le serveur de manière gracieuse
func (s *Server) Shutdown(ctx context.Context) error {
	log.Println("Shutting down MCP server...")
	return s.httpServer.Shutdown(ctx)
}
