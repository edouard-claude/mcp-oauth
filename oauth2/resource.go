package oauth2

import (
	"fmt"
	"net/url"
	"strings"
)

// CanonicalURI représente une URI canonique selon RFC8707
type CanonicalURI struct {
	Scheme string
	Host   string
	Port   string
	Path   string
}

// BuildCanonicalURI construit une URI canonique depuis une URL
func BuildCanonicalURI(rawURL string) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Validation selon RFC8707
	if parsed.Scheme == "" {
		return "", fmt.Errorf("URI must have a scheme")
	}

	if parsed.Host == "" {
		return "", fmt.Errorf("URI must have a host")
	}

	// Les fragments ne sont pas autorisés
	if parsed.Fragment != "" {
		return "", fmt.Errorf("URI must not contain a fragment")
	}

	// Construire l'URI canonique
	// Scheme et host en minuscules
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())

	// Port
	port := parsed.Port()
	if port == "" {
		// Port par défaut selon le schéma
		if scheme == "https" {
			port = "443"
		} else if scheme == "http" {
			port = "80"
		}
	}

	// Path (sans trailing slash sauf si nécessaire)
	path := parsed.Path
	if path == "" {
		path = "/"
	} else if len(path) > 1 && strings.HasSuffix(path, "/") {
		// Retirer le trailing slash sauf pour la racine
		path = strings.TrimSuffix(path, "/")
	}

	// Construire l'URI
	var canonical string
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		// Port par défaut, ne pas l'inclure
		canonical = fmt.Sprintf("%s://%s%s", scheme, host, path)
	} else {
		canonical = fmt.Sprintf("%s://%s:%s%s", scheme, host, port, path)
	}

	// Query string (si présent)
	if parsed.RawQuery != "" {
		canonical += "?" + parsed.RawQuery
	}

	return canonical, nil
}

// ValidateCanonicalURI valide qu'une URI est canonique
func ValidateCanonicalURI(uri string) error {
	parsed, err := url.Parse(uri)
	if err != nil {
		return fmt.Errorf("invalid URI: %w", err)
	}

	// Vérifier le schéma
	if parsed.Scheme == "" {
		return fmt.Errorf("URI must have a scheme")
	}

	// Vérifier le host
	if parsed.Host == "" {
		return fmt.Errorf("URI must have a host")
	}

	// Vérifier qu'il n'y a pas de fragment
	if parsed.Fragment != "" {
		return fmt.Errorf("URI must not contain a fragment")
	}

	return nil
}

