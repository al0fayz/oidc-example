package handlers

import (
	"net/http"
	"oidc-example/server/models"
	"oidc-example/server/storage"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

type ClientHandler struct {
	store storage.Storage
}

func NewClientHandler(store storage.Storage) *ClientHandler {
	return &ClientHandler{store: store}
}

// CreateClient handles client registration
func (h *ClientHandler) CreateClient(c *gin.Context) {
	var req struct {
		Name                              string                 `json:"name" binding:"required"`
		Description                       string                 `json:"description"`
		RedirectURIs                      []string               `json:"redirect_uris" binding:"required"`
		GrantTypes                        []string               `json:"grant_types"`
		ResponseTypes                     []string               `json:"response_types"`
		Scope                             string                 `json:"scope"`
		TokenEndpointAuthMethod           string                 `json:"token_endpoint_auth_method"`
		AllowedCORSOrigins                []string               `json:"allowed_cors_origins"`
		LogoURI                           string                 `json:"logo_uri"`
		ClientURI                         string                 `json:"client_uri"`
		PolicyURI                         string                 `json:"policy_uri"`
		TosURI                            string                 `json:"tos_uri"`
		Contacts                          []string               `json:"contacts"`
		JWKS                              map[string]interface{} `json:"jwks"`
		JWKSURI                           string                 `json:"jwks_uri"`
		SectorIdentifierURI               string                 `json:"sector_identifier_uri"`
		SubjectType                       string                 `json:"subject_type"`
		BackchannelLogoutURI              string                 `json:"backchannel_logout_uri"`
		BackchannelLogoutSessionRequired  bool                   `json:"backchannel_logout_session_required"`
		FrontchannelLogoutURI             string                 `json:"frontchannel_logout_uri"`
		FrontchannelLogoutSessionRequired bool                   `json:"frontchannel_logout_session_required"`
		PostLogoutRedirectURIs            []string               `json:"post_logout_redirect_uris"`
		RequireAuthTime                   bool                   `json:"require_auth_time"`
		DefaultMaxAge                     int                    `json:"default_max_age"`
		RequireSignedRequestObject        bool                   `json:"require_signed_request_object"`
		UserinfoSignedResponseAlg         string                 `json:"userinfo_signed_response_alg"`
		IDTokenSignedResponseAlg          string                 `json:"id_token_signed_response_alg"`
		IDTokenEncryptedResponseAlg       string                 `json:"id_token_encrypted_response_alg"`
		IDTokenEncryptedResponseEnc       string                 `json:"id_token_encrypted_response_enc"`
		RequestURIs                       []string               `json:"request_uris"`
		SoftwareID                        string                 `json:"software_id"`
		SoftwareVersion                   string                 `json:"software_version"`
		Metadata                          map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	// Generate client ID and secret
	clientID := uuid.New().String()
	clientSecret := uuid.New().String()

	// Set defaults
	if req.GrantTypes == nil {
		req.GrantTypes = []string{"authorization_code", "refresh_token"}
	}
	if req.ResponseTypes == nil {
		req.ResponseTypes = []string{"code"}
	}
	if req.Scope == "" {
		req.Scope = "openid profile email"
	}
	if req.TokenEndpointAuthMethod == "" {
		req.TokenEndpointAuthMethod = "client_secret_basic"
	}
	if req.SubjectType == "" {
		req.SubjectType = "public"
	}
	if req.IDTokenSignedResponseAlg == "" {
		req.IDTokenSignedResponseAlg = "RS256"
	}

	// Create token lifetimes
	tokenLifetimes := map[string]interface{}{
		"authorization_code": 600,     // 10 minutes
		"access_token":       3600,    // 1 hour
		"refresh_token":      2592000, // 30 days
		"id_token":           3600,    // 1 hour
	}

	client := &models.Client{
		ID:                                clientID,
		Secret:                            clientSecret,
		Name:                              req.Name,
		Description:                       req.Description,
		RedirectURIs:                      req.RedirectURIs,
		GrantTypes:                        req.GrantTypes,
		ResponseTypes:                     req.ResponseTypes,
		Scope:                             req.Scope,
		TokenEndpointAuthMethod:           req.TokenEndpointAuthMethod,
		AllowedCORSOrigins:                req.AllowedCORSOrigins,
		LogoURI:                           req.LogoURI,
		ClientURI:                         req.ClientURI,
		PolicyURI:                         req.PolicyURI,
		TosURI:                            req.TosURI,
		Contacts:                          req.Contacts,
		JWKS:                              req.JWKS,
		JWKSURI:                           req.JWKSURI,
		SectorIdentifierURI:               req.SectorIdentifierURI,
		SubjectType:                       req.SubjectType,
		TokenLifetimes:                    tokenLifetimes,
		BackchannelLogoutURI:              req.BackchannelLogoutURI,
		BackchannelLogoutSessionRequired:  req.BackchannelLogoutSessionRequired,
		FrontchannelLogoutURI:             req.FrontchannelLogoutURI,
		FrontchannelLogoutSessionRequired: req.FrontchannelLogoutSessionRequired,
		PostLogoutRedirectURIs:            req.PostLogoutRedirectURIs,
		RequireAuthTime:                   req.RequireAuthTime,
		DefaultMaxAge:                     req.DefaultMaxAge,
		RequireSignedRequestObject:        req.RequireSignedRequestObject,
		UserinfoSignedResponseAlg:         req.UserinfoSignedResponseAlg,
		IDTokenSignedResponseAlg:          req.IDTokenSignedResponseAlg,
		IDTokenEncryptedResponseAlg:       req.IDTokenEncryptedResponseAlg,
		IDTokenEncryptedResponseEnc:       req.IDTokenEncryptedResponseEnc,
		RequestURIs:                       req.RequestURIs,
		SoftwareID:                        req.SoftwareID,
		SoftwareVersion:                   req.SoftwareVersion,
		Metadata:                          req.Metadata,
		CreatedAt:                         time.Now(),
		UpdatedAt:                         time.Now(),
	}

	if err := h.store.CreateClient(c.Request.Context(), client); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to create client",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message": "Client created successfully",
		"client": gin.H{
			"client_id":     client.ID,
			"client_secret": client.Secret,
			"name":          client.Name,
			"redirect_uris": client.RedirectURIs,
			"grant_types":   client.GrantTypes,
			"scope":         client.Scope,
			"created_at":    client.CreatedAt,
		},
	})
}

// GetClient retrieves a client by ID
func (h *ClientHandler) GetClient(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.store.GetClientByID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Client not found",
		})
		return
	}

	c.JSON(http.StatusOK, h.clientToResponse(client, false)) // Don't include secret
}

// ListClients retrieves all clients with pagination
func (h *ClientHandler) ListClients(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit > 100 {
		limit = 100
	}
	if limit < 1 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	clients, err := h.store.ListClients(c.Request.Context(), limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to retrieve clients",
		})
		return
	}

	count, err := h.store.CountClients(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to count clients",
		})
		return
	}

	response := make([]map[string]interface{}, 0, len(clients))
	for _, client := range clients {
		response = append(response, h.clientToResponse(client, false)) // Don't include secrets
	}

	c.JSON(http.StatusOK, gin.H{
		"clients":  response,
		"total":    count,
		"limit":    limit,
		"offset":   offset,
		"has_more": count > int64(offset+limit),
	})
}

// UpdateClient updates a client
func (h *ClientHandler) UpdateClient(c *gin.Context) {
	clientID := c.Param("id")

	var req struct {
		Name                              string                 `json:"name"`
		Description                       string                 `json:"description"`
		RedirectURIs                      []string               `json:"redirect_uris"`
		GrantTypes                        []string               `json:"grant_types"`
		ResponseTypes                     []string               `json:"response_types"`
		Scope                             string                 `json:"scope"`
		TokenEndpointAuthMethod           string                 `json:"token_endpoint_auth_method"`
		AllowedCORSOrigins                []string               `json:"allowed_cors_origins"`
		LogoURI                           string                 `json:"logo_uri"`
		ClientURI                         string                 `json:"client_uri"`
		PolicyURI                         string                 `json:"policy_uri"`
		TosURI                            string                 `json:"tos_uri"`
		Contacts                          []string               `json:"contacts"`
		JWKS                              map[string]interface{} `json:"jwks"`
		JWKSURI                           string                 `json:"jwks_uri"`
		SectorIdentifierURI               string                 `json:"sector_identifier_uri"`
		SubjectType                       string                 `json:"subject_type"`
		BackchannelLogoutURI              string                 `json:"backchannel_logout_uri"`
		BackchannelLogoutSessionRequired  bool                   `json:"backchannel_logout_session_required"`
		FrontchannelLogoutURI             string                 `json:"frontchannel_logout_uri"`
		FrontchannelLogoutSessionRequired bool                   `json:"frontchannel_logout_session_required"`
		PostLogoutRedirectURIs            []string               `json:"post_logout_redirect_uris"`
		RequireAuthTime                   bool                   `json:"require_auth_time"`
		DefaultMaxAge                     int                    `json:"default_max_age"`
		RequireSignedRequestObject        bool                   `json:"require_signed_request_object"`
		UserinfoSignedResponseAlg         string                 `json:"userinfo_signed_response_alg"`
		IDTokenSignedResponseAlg          string                 `json:"id_token_signed_response_alg"`
		IDTokenEncryptedResponseAlg       string                 `json:"id_token_encrypted_response_alg"`
		IDTokenEncryptedResponseEnc       string                 `json:"id_token_encrypted_response_enc"`
		RequestURIs                       []string               `json:"request_uris"`
		SoftwareID                        string                 `json:"software_id"`
		SoftwareVersion                   string                 `json:"software_version"`
		Metadata                          map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	// Get existing client
	existingClient, err := h.store.GetClientByID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Client not found",
		})
		return
	}

	// Update fields
	if req.Name != "" {
		existingClient.Name = req.Name
	}
	if req.Description != "" {
		existingClient.Description = req.Description
	}
	if req.RedirectURIs != nil {
		existingClient.RedirectURIs = req.RedirectURIs
	}
	if req.GrantTypes != nil {
		existingClient.GrantTypes = req.GrantTypes
	}
	if req.ResponseTypes != nil {
		existingClient.ResponseTypes = req.ResponseTypes
	}
	if req.Scope != "" {
		existingClient.Scope = req.Scope
	}
	if req.TokenEndpointAuthMethod != "" {
		existingClient.TokenEndpointAuthMethod = req.TokenEndpointAuthMethod
	}
	// ... update other fields similarly

	existingClient.UpdatedAt = time.Now()

	if err := h.store.UpdateClient(c.Request.Context(), existingClient); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to update client",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Client updated successfully",
		"client":  h.clientToResponse(existingClient, false),
	})
}

// DeleteClient deletes a client
func (h *ClientHandler) DeleteClient(c *gin.Context) {
	clientID := c.Param("id")

	if err := h.store.DeleteClient(c.Request.Context(), clientID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to delete client",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Client deleted successfully",
	})
}

// RotateClientSecret rotates the client secret
func (h *ClientHandler) RotateClientSecret(c *gin.Context) {
	clientID := c.Param("id")

	client, err := h.store.GetClientByID(c.Request.Context(), clientID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{
			"error":   "not_found",
			"message": "Client not found",
		})
		return
	}

	// Generate new secret
	newSecret := uuid.New().String()
	client.Secret = newSecret
	client.UpdatedAt = time.Now()

	if err := h.store.UpdateClient(c.Request.Context(), client); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to rotate client secret",
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Client secret rotated successfully",
		"client": gin.H{
			"client_id":     client.ID,
			"client_secret": client.Secret,
			"updated_at":    client.UpdatedAt,
		},
	})
}

// Helper methods
func (h *ClientHandler) clientToResponse(client *models.Client, includeSecret bool) map[string]interface{} {
	response := map[string]interface{}{
		"client_id":                    client.ID,
		"name":                         client.Name,
		"description":                  client.Description,
		"redirect_uris":                client.RedirectURIs,
		"grant_types":                  client.GrantTypes,
		"response_types":               client.ResponseTypes,
		"scope":                        client.Scope,
		"token_endpoint_auth_method":   client.TokenEndpointAuthMethod,
		"client_uri":                   client.ClientURI,
		"logo_uri":                     client.LogoURI,
		"policy_uri":                   client.PolicyURI,
		"tos_uri":                      client.TosURI,
		"jwks_uri":                     client.JWKSURI,
		"subject_type":                 client.SubjectType,
		"id_token_signed_response_alg": client.IDTokenSignedResponseAlg,
		"created_at":                   client.CreatedAt,
		"updated_at":                   client.UpdatedAt,
	}

	if includeSecret {
		response["client_secret"] = client.Secret
	}

	return response
}
