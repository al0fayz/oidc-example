package middleware

import (
	"fmt"
	"net/http"
	"oidc-example/server/storage"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// CORS middleware
func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization, accept, origin, Cache-Control, X-Requested-With")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS, GET, PUT, DELETE")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}

		c.Next()
	}
}

// SecurityHeaders middleware
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Writer.Header().Set("X-Content-Type-Options", "nosniff")
		c.Writer.Header().Set("X-Frame-Options", "DENY")
		c.Writer.Header().Set("X-XSS-Protection", "1; mode=block")
		c.Writer.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		c.Writer.Header().Set("Content-Security-Policy", "default-src 'self'")

		c.Next()
	}
}

// RequestLogger middleware
func RequestLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		requestID := uuid.New().String()

		// Set request ID in context
		c.Set("request_id", requestID)

		// Process request
		c.Next()

		// Log request details
		duration := time.Since(start)
		status := c.Writer.Status()
		clientIP := c.ClientIP()
		method := c.Request.Method
		path := c.Request.URL.Path

		logMessage := fmt.Sprintf("request_id=%s method=%s path=%s status=%d duration=%s client_ip=%s",
			requestID, method, path, status, duration, clientIP)

		if status >= 400 {
			fmt.Printf("ERROR: %s\n", logMessage)
		} else {
			fmt.Printf("INFO: %s\n", logMessage)
		}
	}
}

// AuthMiddleware for JWT authentication
func AuthMiddleware(store storage.Storage) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Skip authentication for certain paths
		if shouldSkipAuth(c.Request.URL.Path) {
			c.Next()
			return
		}

		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "Authorization header is required",
			})
			c.Abort()
			return
		}

		// Extract token from header
		parts := strings.Split(authHeader, " ")
		if len(parts) != 2 || parts[0] != "Bearer" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_token",
				"message": "Authorization header format must be: Bearer {token}",
			})
			c.Abort()
			return
		}

		token := parts[1]

		// Validate session token
		session, err := store.GetSession(c.Request.Context(), token)
		if err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "invalid_token",
				"message": "Invalid or expired session token",
			})
			c.Abort()
			return
		}

		// Check if session is expired
		if session.ExpiresAt.Before(time.Now()) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "token_expired",
				"message": "Session token has expired",
			})
			c.Abort()
			return
		}

		// Add user ID to context
		c.Set("userID", session.UserID)

		// Continue to next handler
		c.Next()
	}
}

// AdminMiddleware for admin role verification
func AdminMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		_, exists := c.Get("userID")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error":   "unauthorized",
				"message": "User not authenticated",
			})
			c.Abort()
			return
		}

		// Here you would check if the user has admin role
		// For now, we'll just allow all authenticated users as admin
		// In production, you should implement proper role checking

		c.Set("isAdmin", true)
		c.Next()
	}
}

// RateLimiter middleware
func RateLimiter(limit int, window time.Duration) gin.HandlerFunc {
	limiter := make(map[string][]time.Time)
	var mu sync.Mutex

	return func(c *gin.Context) {
		clientIP := c.ClientIP()

		mu.Lock()
		now := time.Now()

		// Clean up old timestamps
		validWindow := now.Add(-window)
		validRequests := make([]time.Time, 0)
		for _, t := range limiter[clientIP] {
			if t.After(validWindow) {
				validRequests = append(validRequests, t)
			}
		}

		// Check if rate limit exceeded
		if len(validRequests) >= limit {
			mu.Unlock()
			c.JSON(http.StatusTooManyRequests, gin.H{
				"error":   "rate_limit_exceeded",
				"message": "Too many requests, please try again later",
			})
			c.Abort()
			return
		}

		// Add current request timestamp
		validRequests = append(validRequests, now)
		limiter[clientIP] = validRequests
		mu.Unlock()

		c.Next()
	}
}

// CSRFProtection middleware
func CSRFProtection() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.Request.Method == "GET" || c.Request.Method == "HEAD" || c.Request.Method == "OPTIONS" {
			c.Next()
			return
		}

		// Check CSRF token
		csrfToken := c.GetHeader("X-CSRF-Token")
		if csrfToken == "" {
			c.JSON(http.StatusForbidden, gin.H{
				"error":   "csrf_token_required",
				"message": "CSRF token is required",
			})
			c.Abort()
			return
		}

		// Validate CSRF token (simplified implementation)
		// In production, use a proper CSRF token validation library
		c.Next()
	}
}

// shouldSkipAuth determines if authentication should be skipped for the given path
func shouldSkipAuth(path string) bool {
	skipPaths := []string{
		"/health",
		"/.well-known/openid-configuration",
		"/oauth2/authorize",
		"/oauth2/token",
		"/oauth2/jwks",
		"/api/v1/register",
		"/api/v1/login",
		"/",
	}

	for _, skipPath := range skipPaths {
		if strings.HasPrefix(path, skipPath) {
			return true
		}
	}

	return false
}

// GetUserIDFromContext extracts user ID from context
func GetUserIDFromContext(c *gin.Context) (string, bool) {
	userID, exists := c.Get("userID")
	if !exists {
		return "", false
	}
	return userID.(string), true
}

// GetRequestIDFromContext extracts request ID from context
func GetRequestIDFromContext(c *gin.Context) (string, bool) {
	requestID, exists := c.Get("request_id")
	if !exists {
		return "", false
	}
	return requestID.(string), true
}
