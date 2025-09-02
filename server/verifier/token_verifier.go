package verifier

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
	"oidc-example/server/models"
	"oidc-example/server/storage"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

type TokenVerifier struct {
	store      storage.Storage
	jwksCache  map[string]*rsa.PublicKey
	cacheMutex sync.RWMutex
}

func NewTokenVerifier(store storage.Storage) *TokenVerifier {
	return &TokenVerifier{
		store:     store,
		jwksCache: make(map[string]*rsa.PublicKey),
	}
}

// VerifyAccessToken verifies an access token
func (v *TokenVerifier) VerifyAccessToken(ctx context.Context, tokenString string) (*models.AccessToken, error) {
	// First try to validate as JWT
	claims, err := v.verifyJWT(tokenString)
	if err == nil {
		// JWT is valid, check if it's revoked
		accessToken, err := v.store.GetAccessToken(ctx, tokenString)
		if err == nil && accessToken.Revoked {
			return nil, errors.New("token has been revoked")
		}
		return v.claimsToAccessToken(claims), nil
	}

	// If JWT verification fails, try database lookup
	accessToken, err := v.store.ValidateAccessToken(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid access token: %w", err)
	}

	return accessToken, nil
}

// VerifyRefreshToken verifies a refresh token
func (v *TokenVerifier) VerifyRefreshToken(ctx context.Context, tokenString string) (*models.RefreshToken, error) {
	refreshToken, err := v.store.ValidateRefreshToken(ctx, tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid refresh token: %w", err)
	}
	return refreshToken, nil
}

// VerifyIDToken verifies an ID token
func (v *TokenVerifier) VerifyIDToken(ctx context.Context, tokenString string, expectedAudience string, expectedNonce string) (jwt.MapClaims, error) {
	claims, err := v.verifyJWT(tokenString)
	if err != nil {
		return nil, fmt.Errorf("invalid ID token: %w", err)
	}

	// Validate standard claims
	if err := v.validateIDTokenClaims(claims, expectedAudience, expectedNonce); err != nil {
		return nil, err
	}

	return claims, nil
}

// VerifyAuthorizationCode verifies an authorization code
func (v *TokenVerifier) VerifyAuthorizationCode(ctx context.Context, code string, clientID string, redirectURI string) (*models.AuthorizationCode, error) {
	authCode, err := v.store.GetAuthorizationCode(ctx, code)
	if err != nil {
		return nil, fmt.Errorf("invalid authorization code: %w", err)
	}

	// Validate client ID
	if authCode.ClientID != clientID {
		return nil, errors.New("authorization code was issued to a different client")
	}

	// Validate redirect URI if provided
	if redirectURI != "" && authCode.RedirectURI != redirectURI {
		return nil, errors.New("redirect URI mismatch")
	}

	return authCode, nil
}

// VerifyClientCredentials verifies client credentials
func (v *TokenVerifier) VerifyClientCredentials(ctx context.Context, clientID, clientSecret string) (*models.Client, error) {
	client, err := v.store.GetClientByCredentials(ctx, clientID, clientSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid client credentials: %w", err)
	}
	return client, nil
}

// VerifyClientRedirectURI verifies client redirect URI
func (v *TokenVerifier) VerifyClientRedirectURI(ctx context.Context, clientID, redirectURI string) (bool, error) {
	valid, err := v.store.ValidateClientRedirectURI(ctx, clientID, redirectURI)
	if err != nil {
		return false, fmt.Errorf("failed to validate redirect URI: %w", err)
	}
	return valid, nil
}

// Internal JWT verification
func (v *TokenVerifier) verifyJWT(tokenString string) (jwt.MapClaims, error) {
	// Parse token to get header without verification
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	// Get key ID from header
	kid, ok := token.Header["kid"].(string)
	if !ok {
		return nil, errors.New("token missing kid header")
	}

	// Get public key
	publicKey, err := v.getPublicKey(kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get public key: %w", err)
	}

	// Parse and verify token
	parsedToken, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		// Validate signing method
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		// Validate key ID matches
		if tokenKid, ok := token.Header["kid"].(string); !ok || tokenKid != kid {
			return nil, errors.New("kid mismatch")
		}

		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("token verification failed: %w", err)
	}

	if !parsedToken.Valid {
		return nil, errors.New("invalid token")
	}

	claims, ok := parsedToken.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	// Validate standard claims
	if err := v.validateJWTClaims(claims); err != nil {
		return nil, err
	}

	return claims, nil
}

// Get public key from cache or database
func (v *TokenVerifier) getPublicKey(kid string) (*rsa.PublicKey, error) {
	// Check cache first
	v.cacheMutex.RLock()
	cachedKey, exists := v.jwksCache[kid]
	v.cacheMutex.RUnlock()

	if exists {
		return cachedKey, nil
	}

	// Get from database
	jwk, err := v.store.GetJWK(context.Background(), kid)
	if err != nil {
		return nil, fmt.Errorf("failed to get JWK: %w", err)
	}

	// Convert JWK to RSA public key
	publicKey, err := v.jwkToPublicKey(jwk)
	if err != nil {
		return nil, fmt.Errorf("failed to convert JWK to public key: %w", err)
	}

	// Cache the public key
	v.cacheMutex.Lock()
	v.jwksCache[kid] = publicKey
	v.cacheMutex.Unlock()

	return publicKey, nil
}

// Convert JWK to RSA public key
func (v *TokenVerifier) jwkToPublicKey(jwk *models.JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, errors.New("only RSA keys are supported")
	}

	// Decode modulus (n)
	nBytes, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("failed to decode modulus: %w", err)
	}

	// Decode exponent (e)
	eBytes, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("failed to decode exponent: %w", err)
	}

	// Convert exponent bytes to integer
	var eInt int
	for _, b := range eBytes {
		eInt = eInt<<8 + int(b)
	}

	// Create RSA public key
	publicKey := &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: eInt,
	}

	return publicKey, nil
}

// Validate JWT standard claims
func (v *TokenVerifier) validateJWTClaims(claims jwt.MapClaims) error {
	// Validate expiration
	if exp, ok := claims["exp"].(float64); ok {
		expTime := time.Unix(int64(exp), 0)
		if expTime.Before(time.Now()) {
			return errors.New("token has expired")
		}
	} else {
		return errors.New("token missing exp claim")
	}

	// Validate not before
	if nbf, ok := claims["nbf"].(float64); ok {
		nbfTime := time.Unix(int64(nbf), 0)
		if nbfTime.After(time.Now()) {
			return errors.New("token not yet valid")
		}
	}

	// Validate issued at
	if iat, ok := claims["iat"].(float64); ok {
		iatTime := time.Unix(int64(iat), 0)
		if iatTime.After(time.Now()) {
			return errors.New("token issued in the future")
		}
	}

	return nil
}

// Validate ID token specific claims
func (v *TokenVerifier) validateIDTokenClaims(claims jwt.MapClaims, expectedAudience string, expectedNonce string) error {
	// Validate audience
	if aud, ok := claims["aud"].(string); ok {
		if aud != expectedAudience {
			return errors.New("audience mismatch")
		}
	} else {
		return errors.New("token missing aud claim")
	}

	// Validate issuer
	if iss, ok := claims["iss"].(string); ok {
		// You might want to validate against your issuer URL
		if iss == "" {
			return errors.New("invalid issuer")
		}
	} else {
		return errors.New("token missing iss claim")
	}

	// Validate nonce
	if expectedNonce != "" {
		if nonce, ok := claims["nonce"].(string); !ok || nonce != expectedNonce {
			return errors.New("nonce mismatch")
		}
	}

	// Validate authentication time if required
	if authTime, ok := claims["auth_time"].(float64); ok {
		authTime := time.Unix(int64(authTime), 0)
		if authTime.After(time.Now()) {
			return errors.New("auth_time in the future")
		}
	}

	return nil
}

// Convert JWT claims to access token
func (v *TokenVerifier) claimsToAccessToken(claims jwt.MapClaims) *models.AccessToken {
	token := &models.AccessToken{
		Token:     "", // JWT doesn't have a separate token value
		ExpiresAt: time.Unix(int64(claims["exp"].(float64)), 0),
	}

	if sub, ok := claims["sub"].(string); ok {
		token.UserID = sub
	}

	if aud, ok := claims["aud"].(string); ok {
		token.ClientID = aud
	}

	if scope, ok := claims["scope"].(string); ok {
		token.Scope = scope
	}

	return token
}

// Extract token from Authorization header
func (v *TokenVerifier) ExtractTokenFromHeader(authHeader string) (string, error) {
	if authHeader == "" {
		return "", errors.New("authorization header is required")
	}

	parts := strings.Split(authHeader, " ")
	if len(parts) != 2 || parts[0] != "Bearer" {
		return "", errors.New("authorization header format must be: Bearer {token}")
	}

	return parts[1], nil
}

// Clear cache (useful for testing or when keys are rotated)
func (v *TokenVerifier) ClearCache() {
	v.cacheMutex.Lock()
	v.jwksCache = make(map[string]*rsa.PublicKey)
	v.cacheMutex.Unlock()
}

// Refresh cache (force reload of all keys)
func (v *TokenVerifier) RefreshCache() error {
	v.ClearCache()

	// Load all active keys
	jwks, err := v.store.GetActiveJWKs(context.Background())
	if err != nil {
		return err
	}

	v.cacheMutex.Lock()
	for _, jwk := range jwks {
		publicKey, err := v.jwkToPublicKey(jwk)
		if err == nil {
			v.jwksCache[jwk.KID] = publicKey
		}
	}
	v.cacheMutex.Unlock()

	return nil
}
