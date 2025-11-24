# OAuth2 MCP Server

Boilerplate MCP (Model Context Protocol) avec support OAuth2 HTTP conforme à la spécification 2025-06-18.

## Vue d'ensemble

Ce projet fournit un serveur MCP complet avec authentification OAuth2, implémentant :

- **MCP 2025-06-18** : Transport HTTP Streamable, cycle de vie, JSON-RPC 2.0
- **OAuth 2.1** : Flux d'autorisation avec PKCE, validation des tokens
- **RFC8414** : Authorization Server Metadata
- **RFC7591** : Dynamic Client Registration
- **RFC9728** : Protected Resource Metadata
- **RFC8707** : Resource Indicators

## Structure du projet

```
oauth2-mcp/
├── main.go                    # Point d'entrée du serveur
├── mcp/                       # Package principal MCP
│   ├── server.go             # Serveur MCP principal
│   ├── transport.go          # Transport HTTP Streamable
│   ├── lifecycle.go          # Cycle de vie (initialize, initialized)
│   ├── jsonrpc.go            # JSON-RPC 2.0
│   ├── session.go            # Sessions HTTP
│   ├── handlers.go           # Méthodes MCP
│   └── auth_middleware.go    # Authentification OAuth2 + CORS
├── oauth2/                    # Package OAuth2
│   ├── discovery.go          # Découverte serveur d'autorisation (RFC9728, RFC8414)
│   ├── client_reg.go         # Enregistrement dynamique client (RFC7591)
│   ├── auth_flow.go          # Flux d'autorisation avec PKCE
│   ├── token.go              # Gestion et validation des tokens
│   ├── pkce.go               # Génération et validation PKCE
│   └── resource.go           # Gestion paramètre resource (RFC8707)
└── internal/                  # Packages internes
    ├── config/               # Configuration depuis variables d'environnement
    │   └── config.go
    └── utils/                # Utilitaires
        └── crypto.go         # Utilitaires cryptographiques (PKCE, etc.)
```

## Installation

1. Cloner le repository
2. Copier `env.example` vers `.env` et configurer les variables
3. Installer les dépendances :
   ```bash
   go mod tidy
   ```
4. Lancer le serveur avec le Makefile :
   ```bash
   make run        # Sans authentification
   make run-auth   # Avec OAuth2 activé
   ```
   
   Ou directement avec Go :
   ```bash
   go run main.go
   ```

## Configuration

Le serveur utilise des variables d'environnement pour la configuration. Voir `.env.example` pour la liste complète.

### Variables requises

- `MCP_SERVER_URL` : URL du serveur MCP
- `MCP_PORT` : Port d'écoute (défaut: 8080)
- `OAUTH2_AUTHORIZATION_SERVER` : URL du serveur d'autorisation OAuth2
- `MCP_SESSION_SECRET` : Secret pour génération des session IDs

### Variables optionnelles

- `OAUTH2_CLIENT_ID` : ID client (optionnel si enregistrement dynamique)
- `OAUTH2_CLIENT_SECRET` : Secret client (optionnel)
- `OAUTH2_REDIRECT_URI` : URI de redirection (défaut: http://localhost:8080/callback)
- `OAUTH2_SCOPES` : Scopes demandés (défaut: openid)

## Utilisation

### Avec Makefile (recommandé)

Le Makefile charge automatiquement les variables d'environnement depuis `.env` :

```bash
make run        # Lance le serveur sans authentification
make run-auth   # Lance le serveur avec OAuth2 activé
make build      # Compile uniquement le binaire
make clean      # Supprime le binaire compilé
```

### Sans Makefile

Pour démarrer le serveur sans authentification OAuth2 :

```bash
go run main.go
```

Pour activer l'authentification OAuth2 :

```bash
go run main.go -auth
```

## Endpoints

### Endpoint MCP principal

- **POST /mcp** : Envoyer des messages JSON-RPC au serveur MCP
- **GET /mcp** : Ouvrir un stream SSE pour recevoir des messages du serveur
- **DELETE /mcp** : Terminer une session (avec header `Mcp-Session-Id`)

### Métadonnées OAuth2

- **GET /.well-known/oauth-protected-resource** : Métadonnées de ressource protégée (RFC9728)

## Flux d'autorisation OAuth2

Le serveur implémente le flux d'autorisation OAuth2 complet :

1. **Découverte** : Le client découvre le serveur d'autorisation via les métadonnées de ressource protégée
2. **Enregistrement** : Le client s'enregistre dynamiquement (RFC7591) si nécessaire
3. **Autorisation** : Le client redirige l'utilisateur vers le serveur d'autorisation avec PKCE
4. **Token** : Le client échange le code d'autorisation contre un token d'accès
5. **Requêtes** : Le client utilise le token dans le header `Authorization: Bearer <token>`

## Sécurité

Le serveur implémente les meilleures pratiques de sécurité :

- Validation du header `Origin` pour prévenir DNS rebinding
- Binding localhost par défaut
- PKCE obligatoire pour tous les clients
- Validation stricte de l'audience des tokens
- Tokens jamais dans les query strings
- HTTPS requis pour les endpoints OAuth2
- Session IDs cryptographiquement sécurisés

## Développement

### Ajouter un nouveau handler MCP

Dans `mcp/handlers.go`, ajouter un nouveau handler :

```go
registry.Register("tools/my-tool", func(params json.RawMessage, session *Session) (interface{}, error) {
    // Votre logique ici
    return result, nil
})
```

### Tests

```bash
go test ./...
```

## Conformité aux spécifications

- ✅ MCP 2025-06-18 : Transport HTTP Streamable, cycle de vie, JSON-RPC 2.0
- ✅ OAuth 2.1 : Flux d'autorisation, PKCE, validation tokens
- ✅ RFC8414 : Authorization Server Metadata
- ✅ RFC7591 : Dynamic Client Registration
- ✅ RFC9728 : Protected Resource Metadata
- ✅ RFC8707 : Resource Indicators

## Licence

MIT

