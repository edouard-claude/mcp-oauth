package oauth2

import (
	"crypto/sha256"
	"fmt"
	"oauth2-mcp/internal/utils"
)

// PKCE représente les paramètres PKCE
type PKCE struct {
	CodeVerifier  string
	CodeChallenge string
	CodeChallengeMethod string
}

// GeneratePKCE génère les paramètres PKCE
// Le code_verifier doit être entre 43 et 128 caractères, URL-safe
func GeneratePKCE() (*PKCE, error) {
	// Générer un code_verifier de 64 caractères (entre 43 et 128)
	verifierBytes, err := utils.GenerateRandomBytes(48) // 48 bytes = 64 caractères en base64url
	if err != nil {
		return nil, fmt.Errorf("failed to generate code verifier: %w", err)
	}

	codeVerifier := utils.Base64URLEncode(verifierBytes)

	// Générer le code_challenge (SHA256 hash du verifier, encodé en base64url)
	hash := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := utils.Base64URLEncode(hash[:])

	return &PKCE{
		CodeVerifier:       codeVerifier,
		CodeChallenge:      codeChallenge,
		CodeChallengeMethod: "S256",
	}, nil
}

// ValidateCodeVerifier valide un code_verifier contre un code_challenge
func ValidateCodeVerifier(codeVerifier, codeChallenge string) bool {
	// Calculer le hash du verifier
	hash := sha256.Sum256([]byte(codeVerifier))
	calculatedChallenge := utils.Base64URLEncode(hash[:])

	// Comparer avec le challenge fourni
	return calculatedChallenge == codeChallenge
}

// IsValidCodeVerifier vérifie si un code_verifier a un format valide
func IsValidCodeVerifier(verifier string) bool {
	// Doit être entre 43 et 128 caractères
	if len(verifier) < 43 || len(verifier) > 128 {
		return false
	}

	// Doit être URL-safe (caractères alphanumériques, -, ., _, ~)
	for _, r := range verifier {
		if !((r >= 'A' && r <= 'Z') ||
			(r >= 'a' && r <= 'z') ||
			(r >= '0' && r <= '9') ||
			r == '-' || r == '.' || r == '_' || r == '~') {
			return false
		}
	}

	return true
}

