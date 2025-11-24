package oauth2

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

// GenerateJWT génère un token JWT signé avec HS256
func GenerateJWT(issuer, subject, audience string, scopes []string, jwtSecret string, expiresIn time.Duration) (string, error) {
	now := time.Now()
	expiresAt := now.Add(expiresIn)

	// Générer un jti (JWT ID) unique
	jtiBytes := make([]byte, 16)
	if _, err := time.Now().MarshalBinary(); err == nil {
		// Utiliser le timestamp comme base pour le jti
		jtiBytes = []byte(fmt.Sprintf("%d", now.UnixNano()))
	}

	// Header
	header := map[string]interface{}{
		"alg": "HS256",
		"typ": "JWT",
	}

	// Payload (claims)
	payload := map[string]interface{}{
		"iss":   issuer,
		"sub":   subject,
		"aud":   audience,
		"exp":   expiresAt.Unix(),
		"iat":   now.Unix(),
		"scope": joinScopes(scopes),
		"jti":   base64.RawURLEncoding.EncodeToString(jtiBytes),
	}

	// Encoder le header en base64url
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("failed to marshal header: %w", err)
	}
	headerEncoded := base64.RawURLEncoding.EncodeToString(headerJSON)

	// Encoder le payload en base64url
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("failed to marshal payload: %w", err)
	}
	payloadEncoded := base64.RawURLEncoding.EncodeToString(payloadJSON)

	// Créer la signature
	signatureInput := fmt.Sprintf("%s.%s", headerEncoded, payloadEncoded)
	mac := hmac.New(sha256.New, []byte(jwtSecret))
	mac.Write([]byte(signatureInput))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))

	// Assembler le JWT
	jwt := fmt.Sprintf("%s.%s.%s", headerEncoded, payloadEncoded, signature)

	return jwt, nil
}

