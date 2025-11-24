.PHONY: build run run-auth clean help

# Nom du binaire
BINARY_NAME=mcp
BINARY_PATH=./bin/$(BINARY_NAME)

help: ## Affiche l'aide
	@echo "Commandes disponibles:"
	@echo "  make build      - Compile le binaire dans ./bin/mcp"
	@echo "  make run        - Lance le serveur (sans auth)"
	@echo "  make run-auth   - Lance le serveur avec OAuth2 activé"
	@echo "  make clean      - Supprime le binaire"
	@echo "  make help       - Affiche cette aide"

build: ## Compile le binaire
	@echo "Compilation..."
	@mkdir -p bin
	@go build -o $(BINARY_PATH) .
	@echo "Binaire créé: $(BINARY_PATH)"

run: build ## Lance le serveur sans authentification
	@echo "Démarrage du serveur (sans auth)..."
	@if [ -f .env ]; then \
		set -a; \
		source .env; \
		set +a; \
		$(BINARY_PATH); \
	else \
		echo "Attention: fichier .env non trouvé, utilisation des variables d'environnement système"; \
		$(BINARY_PATH); \
	fi

run-auth: build ## Lance le serveur avec OAuth2 activé
	@echo "Démarrage du serveur (avec OAuth2)..."
	@if [ -f .env ]; then \
		set -a; \
		source .env; \
		set +a; \
		$(BINARY_PATH) -auth; \
	else \
		echo "Attention: fichier .env non trouvé, utilisation des variables d'environnement système"; \
		$(BINARY_PATH) -auth; \
	fi

clean: ## Supprime le binaire
	@echo "Nettoyage..."
	@rm -rf bin
	@echo "Nettoyage terminé"

