package handlers

import (
	"net/http"
	"oidc-example/server/storage"
	"time"

	"github.com/gin-gonic/gin"
)

type UserHandler struct {
	store storage.Storage
}

func NewUserHandler(store storage.Storage) *UserHandler {
	return &UserHandler{store: store}
}

// GetCurrentUser returns the current authenticated user
func (h *UserHandler) GetCurrentUser(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	user, err := h.store.GetUserByID(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Return user info without sensitive data
	c.JSON(http.StatusOK, gin.H{
		"user": gin.H{
			"id":             user.ID,
			"username":       user.Username,
			"email":          user.Email,
			"email_verified": user.EmailVerified,
			"name":           user.Name,
			"given_name":     user.GivenName,
			"family_name":    user.FamilyName,
			"picture":        user.Picture,
			"locale":         user.Locale,
			"phone_number":   user.PhoneNumber,
			"phone_verified": user.PhoneNumberVerified,
			"created_at":     user.CreatedAt,
			"updated_at":     user.UpdatedAt,
			"last_login":     user.LastLogin,
		},
	})
}

// UpdateUser updates the current user's information
func (h *UserHandler) UpdateUser(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	var updateData struct {
		Name        string `json:"name"`
		GivenName   string `json:"given_name"`
		FamilyName  string `json:"family_name"`
		MiddleName  string `json:"middle_name"`
		Nickname    string `json:"nickname"`
		Profile     string `json:"profile"`
		Picture     string `json:"picture"`
		Website     string `json:"website"`
		Gender      string `json:"gender"`
		Birthdate   string `json:"birthdate"`
		Zoneinfo    string `json:"zoneinfo"`
		Locale      string `json:"locale"`
		PhoneNumber string `json:"phone_number"`
	}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request"})
		return
	}

	user, err := h.store.GetUserByID(c.Request.Context(), userID.(string))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Update user fields
	if updateData.Name != "" {
		user.Name = updateData.Name
	}
	if updateData.GivenName != "" {
		user.GivenName = updateData.GivenName
	}
	if updateData.FamilyName != "" {
		user.FamilyName = updateData.FamilyName
	}
	// ... update other fields

	user.UpdatedAt = time.Now()

	if err := h.store.UpdateUser(c.Request.Context(), user); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "User updated successfully",
		"user": gin.H{
			"id":       user.ID,
			"username": user.Username,
			"email":    user.Email,
			"name":     user.Name,
		},
	})
}

// GetClients returns the user's authorized clients
func (h *UserHandler) GetClients(c *gin.Context) {
	userID, exists := c.Get("userID")
	if !exists {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Not authenticated"})
		return
	}

	// Get user's consent sessions to find authorized clients
	sessions, err := h.store.GetConsentSessionsForUser(c.Request.Context(), userID.(string), 100, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get client information"})
		return
	}

	clientIDs := make(map[string]bool)
	for _, session := range sessions {
		if !session.Rejected {
			clientIDs[session.ClientID] = true
		}
	}

	clients := make([]gin.H, 0)
	for clientID := range clientIDs {
		client, err := h.store.GetClientByID(c.Request.Context(), clientID)
		if err == nil {
			clients = append(clients, gin.H{
				"client_id":   client.ID,
				"client_name": client.Name,
				"client_uri":  client.ClientURI,
				"logo_uri":    client.LogoURI,
				"policy_uri":  client.PolicyURI,
				"tos_uri":     client.TosURI,
			})
		}
	}

	c.JSON(http.StatusOK, gin.H{"clients": clients})
}
