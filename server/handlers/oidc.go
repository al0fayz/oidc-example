package handlers

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"net/url"
	"oidc-example/server/models"
	"oidc-example/server/storage"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

type OIDCHandler struct {
	store      storage.Storage
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
}

func NewOIDCHandler(store storage.Storage) *OIDCHandler {
	privateKey, publicKey, err := generateRSAKeyPair()
	if err != nil {
		log.Fatal("Failed to generate RSA key pair:", err)
	}

	return &OIDCHandler{
		store:      store,
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

// Discovery endpoint
func (h *OIDCHandler) Discovery(c *gin.Context) {
	baseURL := getBaseURL(c.Request)
	discovery := map[string]interface{}{
		"issuer":                                baseURL,
		"authorization_endpoint":                baseURL + "/oauth2/authorize",
		"token_endpoint":                        baseURL + "/oauth2/token",
		"userinfo_endpoint":                     baseURL + "/oauth2/userinfo",
		"jwks_uri":                              baseURL + "/oauth2/jwks",
		"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
		"response_types_supported":              []string{"code", "token", "id_token"},
		"response_modes_supported":              []string{"query", "fragment", "form_post"},
		"grant_types_supported":                 []string{"authorization_code", "refresh_token", "client_credentials"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_basic", "client_secret_post"},
		"claims_supported":                      []string{"sub", "name", "email", "email_verified"},
	}

	c.JSON(http.StatusOK, discovery)
}

// Authorization endpoint
func (h *OIDCHandler) Authorize(c *gin.Context) {
	var req struct {
		ClientID     string `form:"client_id" binding:"required"`
		RedirectURI  string `form:"redirect_uri" binding:"required"`
		ResponseType string `form:"response_type" binding:"required"`
		Scope        string `form:"scope"`
		State        string `form:"state"`
		Nonce        string `form:"nonce"`
	}

	if err := c.ShouldBindQuery(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// Validate client
	_, err := h.store.GetClientByID(c.Request.Context(), req.ClientID)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_client"})
		return
	}

	// Validate redirect URI
	valid, err := h.store.ValidateClientRedirectURI(c.Request.Context(), req.ClientID, req.RedirectURI)
	if err != nil || !valid {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_redirect_uri"})
		return
	}

	// Check if user is authenticated (simplified)
	sessionToken, _ := c.Cookie("session_token")
	if sessionToken == "" {
		// Store auth request and redirect to login
		authRequest := map[string]interface{}{
			"client_id":     req.ClientID,
			"redirect_uri":  req.RedirectURI,
			"response_type": req.ResponseType,
			"scope":         req.Scope,
			"state":         req.State,
			"nonce":         req.Nonce,
		}

		authRequestJSON, _ := json.Marshal(authRequest)
		c.SetCookie("auth_request", string(authRequestJSON), 300, "/", "", false, true)

		loginURL := "/login?redirect=" + url.QueryEscape(c.Request.URL.String())
		c.Redirect(http.StatusFound, loginURL)
		return
	}

	// Get user from session
	session, err := h.store.GetSession(c.Request.Context(), sessionToken)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_session"})
		return
	}

	// Generate authorization code
	code := uuid.New().String()
	authCode := &models.AuthorizationCode{
		Code:        code,
		ClientID:    req.ClientID,
		RedirectURI: req.RedirectURI,
		Scope:       req.Scope,
		UserID:      session.UserID,
		Nonce:       req.Nonce,
		ExpiresAt:   time.Now().Add(10 * time.Minute),
		CreatedAt:   time.Now(),
	}

	if err := h.store.CreateAuthorizationCode(c.Request.Context(), authCode); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	// Redirect with authorization code
	redirectURL, _ := url.Parse(req.RedirectURI)
	query := redirectURL.Query()
	query.Set("code", code)
	if req.State != "" {
		query.Set("state", req.State)
	}
	redirectURL.RawQuery = query.Encode()

	c.Redirect(http.StatusFound, redirectURL.String())
}

// Token endpoint
func (h *OIDCHandler) Token(c *gin.Context) {
	var req struct {
		GrantType    string `form:"grant_type" binding:"required"`
		Code         string `form:"code"`
		RedirectURI  string `form:"redirect_uri"`
		ClientID     string `form:"client_id"`
		ClientSecret string `form:"client_secret"`
		RefreshToken string `form:"refresh_token"`
		Scope        string `form:"scope"`
	}

	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	// Authenticate client
	client, err := h.authenticateClient(c, req.ClientID, req.ClientSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_client"})
		return
	}

	switch req.GrantType {
	case "authorization_code":
		h.handleAuthorizationCode(c, client, struct {
			GrantType    string
			Code         string
			RedirectURI  string
			ClientID     string
			ClientSecret string
			RefreshToken string
			Scope        string
		}{
			GrantType:    req.GrantType,
			Code:         req.Code,
			RedirectURI:  req.RedirectURI,
			ClientID:     req.ClientID,
			ClientSecret: req.ClientSecret,
			RefreshToken: req.RefreshToken,
			Scope:        req.Scope,
		})
	case "refresh_token":
		h.handleRefreshToken(c, client, struct {
			GrantType    string
			Code         string
			RedirectURI  string
			ClientID     string
			ClientSecret string
			RefreshToken string
			Scope        string
		}{
			GrantType:    req.GrantType,
			Code:         req.Code,
			RedirectURI:  req.RedirectURI,
			ClientID:     req.ClientID,
			ClientSecret: req.ClientSecret,
			RefreshToken: req.RefreshToken,
			Scope:        req.Scope,
		})
	case "client_credentials":
		h.handleClientCredentials(c, client, struct {
			GrantType    string
			Code         string
			RedirectURI  string
			ClientID     string
			ClientSecret string
			RefreshToken string
			Scope        string
		}{
			GrantType:    req.GrantType,
			Code:         req.Code,
			RedirectURI:  req.RedirectURI,
			ClientID:     req.ClientID,
			ClientSecret: req.ClientSecret,
			RefreshToken: req.RefreshToken,
			Scope:        req.Scope,
		})
	default:
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported_grant_type"})
	}
}

// UserInfo endpoint
func (h *OIDCHandler) UserInfo(c *gin.Context) {
	authHeader := c.GetHeader("Authorization")
	if authHeader == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Authorization header required"})
		return
	}

	tokenString := strings.TrimPrefix(authHeader, "Bearer ")
	if tokenString == authHeader {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "Bearer token required"})
		return
	}

	claims, err := h.validateToken(tokenString)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": err.Error()})
		return
	}

	userID, ok := claims["sub"].(string)
	if !ok {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid_token", "error_description": "sub claim required"})
		return
	}

	user, err := h.store.GetUserByID(c.Request.Context(), userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "server_error"})
		return
	}

	userInfo := map[string]interface{}{
		"sub":                user.ID,
		"name":               user.Name,
		"email":              user.Email,
		"email_verified":     user.EmailVerified,
		"preferred_username": user.Username,
		"updated_at":         user.UpdatedAt.Unix(),
	}

	c.JSON(http.StatusOK, userInfo)
}

// JWKS endpoint
func (h *OIDCHandler) JWKS(c *gin.Context) {
	nBase64 := base64.RawURLEncoding.EncodeToString(h.publicKey.N.Bytes())
	eBytes := big.NewInt(int64(h.publicKey.E)).Bytes()
	eBase64 := base64.RawURLEncoding.EncodeToString(eBytes)

	jwks := map[string]interface{}{
		"keys": []map[string]interface{}{
			{
				"kty": "RSA",
				"use": "sig",
				"kid": "1",
				"alg": "RS256",
				"n":   nBase64,
				"e":   eBase64,
			},
		},
	}

	c.JSON(http.StatusOK, jwks)
}

// Helper methods...
func (h *OIDCHandler) authenticateClient(c *gin.Context, clientID, clientSecret string) (*models.Client, error) {
	// Try basic auth first
	username, password, hasAuth := c.Request.BasicAuth()
	if hasAuth {
		clientID = username
		clientSecret = password
	}

	if clientID == "" {
		return nil, fmt.Errorf("client_id required")
	}

	client, err := h.store.GetClientByCredentials(c.Request.Context(), clientID, clientSecret)
	if err != nil {
		return nil, err
	}

	return client, nil
}

func (h *OIDCHandler) handleAuthorizationCode(c *gin.Context, client *models.Client, req struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scope        string
}) {
	// Implementation...
}

func (h *OIDCHandler) handleRefreshToken(c *gin.Context, client *models.Client, req struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scope        string
}) {
	// Implementation...
}

func (h *OIDCHandler) handleClientCredentials(c *gin.Context, client *models.Client, req struct {
	GrantType    string
	Code         string
	RedirectURI  string
	ClientID     string
	ClientSecret string
	RefreshToken string
	Scope        string
}) {
	// Implementation...
}

func (h *OIDCHandler) validateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return h.publicKey, nil
	})

	if err != nil {
		return nil, err
	}

	if !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, fmt.Errorf("invalid claims format")
	}

	if exp, ok := claims["exp"].(float64); ok {
		if time.Unix(int64(exp), 0).Before(time.Now()) {
			return nil, fmt.Errorf("token expired")
		}
	}

	return claims, nil
}

func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func getBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}
