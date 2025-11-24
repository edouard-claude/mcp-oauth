package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"oauth2-mcp/internal/config"
	"oauth2-mcp/mcp"
)

func main() {
	// Parse des flags
	enableAuth := flag.Bool("auth", false, "Enable OAuth2 authentication")
	flag.Parse()

	// Charger la configuration
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Créer le serveur
	server, err := mcp.NewServer(cfg, *enableAuth)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	// Démarrer le serveur dans une goroutine
	go func() {
		if err := server.Start(); err != nil {
			log.Fatalf("Server error: %v", err)
		}
	}()

	// Attendre les signaux pour arrêt gracieux
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("Shutting down server...")

	// Créer un contexte avec timeout pour l'arrêt
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Arrêter le serveur
	if err := server.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exited")
}

