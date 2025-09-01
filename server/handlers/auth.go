package handlers

import (
	"fmt"
	"net/http"
	"oidc-example/server/models"
	"oidc-example/server/storage"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

type AuthHandler struct {
	store storage.Storage
}

func NewAuthHandler(store storage.Storage) *AuthHandler {
	return &AuthHandler{store: store}
}

// Register handles user registration
func (h *AuthHandler) Register(c *gin.Context) {
	var req struct {
		Username string `json:"username" binding:"required"`
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required,min=8"`
		Name     string `json:"name" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request", "details": err.Error()})
		return
	}

	// Check if user already exists
	_, err := h.store.GetUserByEmail(c.Request.Context(), req.Email)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "User already exists"})
		return
	}

	// Check if username already exists
	_, err = h.store.GetUserByUsername(c.Request.Context(), req.Username)
	if err == nil {
		c.JSON(http.StatusConflict, gin.H{"error": "Username already taken"})
		return
	}

	// Hash password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	// Create user
	user := &models.User{
		ID:           uuid.New().String(),
		Username:     req.Username,
		Email:        req.Email,
		PasswordHash: string(hashedPassword),
		Name:         req.Name,
		CreatedAt:    time.Now(),
		UpdatedAt:    time.Now(),
	}

	if err := h.store.CreateUser(c.Request.Context(), user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "User created successfully",
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"name":     user.Name,
		},
	})
}

// Login handles user login
func (h *AuthHandler) Login(c *gin.Context) {
	var req struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Get user by email
	user, err := h.store.GetUserByEmail(c.Request.Context(), req.Email)
	if err != nil {
		// Don't reveal whether user exists or not
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check password
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid credentials"})
		return
	}

	// Check if user is blocked
	if user.Blocked {
		c.JSON(http.StatusForbidden, gin.H{"error": "Account is blocked"})
		return
	}

	// Create session
	sessionToken := uuid.New().String()
	session := &models.Session{
		Token:     sessionToken,
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := h.store.CreateSession(c.Request.Context(), session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// Update user last login
	now := time.Now()
	user.LastLogin = &now
	user.LoginCount++
	user.LastIP = c.ClientIP()

	if err := h.store.UpdateUser(c.Request.Context(), user); err != nil {
		// Log error but don't fail the login
		fmt.Printf("Failed to update user last login: %v\n", err)
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Login successful",
		"token":   sessionToken,
		"expires": session.ExpiresAt,
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"name":     user.Name,
		},
	})
}

// Logout handles user logout
func (h *AuthHandler) Logout(c *gin.Context) {
	_, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Get session token from header
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Authorization header required"})
		return
	}

	token := strings.TrimPrefix(authHeader, "Bearer ")
	if token == authHeader {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Bearer token required"})
		return
	}

	// Delete the session
	if err := h.store.DeleteSession(c.Request.Context(), token); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to logout"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Logout successful",
	})
}

// RefreshToken handles token refresh
func (h *AuthHandler) RefreshToken(c *gin.Context) {
	var req struct {
		RefreshToken string `json:"refresh_token" binding:"required"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	// Validate refresh token
	refreshToken, err := h.store.ValidateRefreshToken(c.Request.Context(), req.RefreshToken)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid refresh token"})
		return
	}

	// Get user
	user, err := h.store.GetUserByID(c.Request.Context(), refreshToken.UserID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user"})
		return
	}

	// Get client (if needed for token generation)
	var client *models.Client
	if refreshToken.ClientID != "" {
		client, err = h.store.GetClientByID(c.Request.Context(), refreshToken.ClientID)
		fmt.Println(client)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get client"})
			return
		}
	}

	// Create new session token
	sessionToken := uuid.New().String()
	session := &models.Session{
		Token:     sessionToken,
		UserID:    user.ID,
		ClientID:  refreshToken.ClientID,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CreatedAt: time.Now(),
	}

	if err := h.store.CreateSession(c.Request.Context(), session); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create session"})
		return
	}

	// For OIDC flows, you might want to generate proper access tokens here
	// For now, we'll just return a new session token

	c.JSON(http.StatusOK, gin.H{
		"access_token":  sessionToken,
		"token_type":    "Bearer",
		"expires_in":    3600,
		"refresh_token": req.RefreshToken,
		"scope":         refreshToken.Scope,
	})
}

// Helper function to generate unique ID (fallback)
func generateID() string {
	return uuid.New().String()
}
