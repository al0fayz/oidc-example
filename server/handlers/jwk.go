package handlers

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math/big"
	"net/http"
	"oidc-example/server/models"
	"oidc-example/server/storage"
	"oidc-example/server/utils"
	"time"

	"github.com/gin-gonic/gin"
)

type JWKHandler struct {
	store      storage.Storage
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewJWKHandler(store storage.Storage) *JWKHandler {
	privateKey, publicKey, err := utils.GenerateRSAKeyPair()
	if err != nil {
		panic("Failed to generate RSA key pair: " + err.Error())
	}

	handler := &JWKHandler{
		store:      store,
		privateKey: privateKey,
		publicKey:  publicKey,
	}

	// Ensure default JWK exists
	handler.ensureDefaultJWK()

	return handler
}

// GetJWKS returns the JSON Web Key Set
func (h *JWKHandler) GetJWKS(c *gin.Context) {
	jwks, err := h.store.GetActiveJWKs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   err.Error(),
			"message": "Failed to retrieve JWKS",
		})
		return
	}

	// Convert to JWKS format
	keys := make([]map[string]interface{}, 0, len(jwks))
	for _, jwk := range jwks {
		keys = append(keys, h.jwkToMap(jwk))
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
}

// CreateJWK creates a new JSON Web Key
func (h *JWKHandler) CreateJWK(c *gin.Context) {
	var req struct {
		KID        string   `json:"kid" binding:"required"`
		Kty        string   `json:"kty" binding:"required"`
		Use        string   `json:"key_use"`
		Alg        string   `json:"alg"`
		Operations []string `json:"operations"`
		ExpiresIn  int      `json:"expires_in"` // in seconds
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	// Generate RSA key pair
	_, publicKey, err := utils.GenerateRSAKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to generate key pair",
		})
		return
	}

	// Convert public key to JWK format
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	var expiresAt *time.Time
	if req.ExpiresIn > 0 {
		expiry := time.Now().Add(time.Duration(req.ExpiresIn) * time.Second)
		expiresAt = &expiry
	}

	jwk := &models.JWK{
		KID:        req.KID,
		Kty:        req.Kty,
		Use:        req.Use,
		Alg:        req.Alg,
		N:          base64.RawURLEncoding.EncodeToString(nBytes),
		E:          base64.RawURLEncoding.EncodeToString(eBytes),
		Operations: req.Operations,
		ExpiresAt:  expiresAt,
		CreatedAt:  time.Now(),
	}

	// Store private key securely (in production, use proper key storage)
	// For now, we'll just store the public key information

	if err := h.store.CreateJWK(c.Request.Context(), jwk); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to store JWK",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "JWK created successfully",
		"jwk":     h.jwkToMap(jwk),
	})
}

// RotateJWK rotates an existing JWK
func (h *JWKHandler) RotateJWK(c *gin.Context) {
	kid := c.Param("kid")

	// Get existing JWK
	existingJWK, err := h.store.GetJWK(c.Request.Context(), kid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "JWK not found",
		})
		return
	}

	// Generate new key pair
	_, publicKey, err := utils.GenerateRSAKeyPair()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to generate key pair",
		})
		return
	}

	// Convert public key to JWK format
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	// Create new JWK with same kid but new key material
	newJWK := &models.JWK{
		KID:        existingJWK.KID,
		Kty:        existingJWK.Kty,
		Use:        existingJWK.Use,
		Alg:        existingJWK.Alg,
		N:          base64.RawURLEncoding.EncodeToString(nBytes),
		E:          base64.RawURLEncoding.EncodeToString(eBytes),
		Operations: existingJWK.Operations,
		ExpiresAt:  existingJWK.ExpiresAt,
		CreatedAt:  time.Now(),
		RotatedAt:  &time.Time{},
	}

	// Update the existing JWK
	if err := h.store.RotateJWK(c.Request.Context(), kid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to rotate JWK",
		})
		return
	}

	// Create new JWK entry
	if err := h.store.CreateJWK(c.Request.Context(), newJWK); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to create new JWK",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "JWK rotated successfully",
		"jwk":     h.jwkToMap(newJWK),
	})
}

// GetJWK returns a specific JWK
func (h *JWKHandler) GetJWK(c *gin.Context) {
	kid := c.Param("kid")

	jwk, err := h.store.GetJWK(c.Request.Context(), kid)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "JWK not found",
		})
		return
	}

	c.JSON(http.StatusOK, h.jwkToMap(jwk))
}

// ListJWKs returns all JWKs
func (h *JWKHandler) ListJWKs(c *gin.Context) {
	jwks, err := h.store.GetActiveJWKs(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to retrieve JWKs",
		})
		return
	}

	keys := make([]map[string]interface{}, 0, len(jwks))
	for _, jwk := range jwks {
		keys = append(keys, h.jwkToMap(jwk))
	}

	c.JSON(http.StatusOK, gin.H{
		"keys": keys,
	})
}

// DeleteJWK deletes a JWK
func (h *JWKHandler) DeleteJWK(c *gin.Context) {
	kid := c.Param("kid")

	if err := h.store.DeleteJWK(c.Request.Context(), kid); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to delete JWK",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "JWK deleted successfully",
	})
}

// Helper methods
func (h *JWKHandler) jwkToMap(jwk *models.JWK) map[string]interface{} {
	jwkMap := map[string]interface{}{
		"kid":     jwk.KID,
		"kty":     jwk.Kty,
		"key_use": jwk.Use,
		"alg":     jwk.Alg,
		"n":       jwk.N,
		"e":       jwk.E,
	}

	if jwk.Operations != nil && len(jwk.Operations) > 0 {
		jwkMap["key_ops"] = jwk.Operations
	}

	if jwk.ExpiresAt != nil {
		jwkMap["exp"] = jwk.ExpiresAt.Unix()
	}

	return jwkMap
}

func (h *JWKHandler) ensureDefaultJWK() {
	ctx := context.Background()

	// Check if default JWK already exists
	_, err := h.store.GetJWK(ctx, "1")
	if err == nil {
		return
	}

	// Create default JWK
	nBytes := h.publicKey.N.Bytes()
	eBytes := big.NewInt(int64(h.publicKey.E)).Bytes()

	jwk := &models.JWK{
		KID:       "1",
		Kty:       "RSA",
		Use:       "sig",
		Alg:       "RS256",
		N:         base64.RawURLEncoding.EncodeToString(nBytes),
		E:         base64.RawURLEncoding.EncodeToString(eBytes),
		CreatedAt: time.Now(),
	}

	if err := h.store.CreateJWK(ctx, jwk); err != nil {
		// Log error but don't panic - server can still run
		fmt.Printf("Failed to create default JWK: %v\n", err)
	}
}
