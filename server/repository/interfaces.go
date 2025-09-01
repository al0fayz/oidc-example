package repository

import (
	"context"
	"oidc-example/server/models"
	"time"
)

// UserRepository defines the interface for user data operations
type UserRepository interface {
	Create(ctx context.Context, user *models.User) error
	FindByID(ctx context.Context, id string) (*models.User, error)
	FindByEmail(ctx context.Context, email string) (*models.User, error)
	FindByUsername(ctx context.Context, username string) (*models.User, error)
	Update(ctx context.Context, user *models.User) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, limit, offset int) ([]*models.User, error)
	Count(ctx context.Context) (int64, error)
}

// ClientRepository defines the interface for client data operations
type ClientRepository interface {
	Create(ctx context.Context, client *models.Client) error
	FindByID(ctx context.Context, id string) (*models.Client, error)
	FindByCredentials(ctx context.Context, clientID, clientSecret string) (*models.Client, error)
	Update(ctx context.Context, client *models.Client) error
	Delete(ctx context.Context, id string) error
	List(ctx context.Context, limit, offset int) ([]*models.Client, error)
	Count(ctx context.Context) (int64, error)
	ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) (bool, error)
}

// AuthorizationCodeRepository defines the interface for authorization code operations
type AuthorizationCodeRepository interface {
	Create(ctx context.Context, code *models.AuthorizationCode) error
	FindByCode(ctx context.Context, code string) (*models.AuthorizationCode, error)
	Invalidate(ctx context.Context, code string) error
	Delete(ctx context.Context, code string) error
	CleanupExpired(ctx context.Context) error
}

// TokenRepository defines the interface for token operations
type TokenRepository interface {
	CreateAccessToken(ctx context.Context, token *models.AccessToken) error
	FindAccessToken(ctx context.Context, token string) (*models.AccessToken, error)
	ValidateAccessToken(ctx context.Context, token string) (*models.AccessToken, error)
	RevokeAccessToken(ctx context.Context, token string) error
	CleanupExpiredAccessTokens(ctx context.Context) error

	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	FindRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
	ValidateRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	RevokeRefreshTokensForUserClient(ctx context.Context, userID, clientID string) error
	CleanupExpiredRefreshTokens(ctx context.Context) error
}

// SessionRepository defines the interface for session operations
type SessionRepository interface {
	Create(ctx context.Context, session *models.Session) error
	FindByToken(ctx context.Context, token string) (*models.Session, error)
	FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.Session, error)
	Update(ctx context.Context, session *models.Session) error
	Delete(ctx context.Context, token string) error
	DeleteByUserID(ctx context.Context, userID string) error
	CleanupExpired(ctx context.Context) error
}

// JWKRepository defines the interface for JWK operations
type JWKRepository interface {
	Create(ctx context.Context, jwk *models.JWK) error
	FindByKID(ctx context.Context, kid string) (*models.JWK, error)
	FindActive(ctx context.Context) ([]*models.JWK, error)
	Rotate(ctx context.Context, kid string) error
	Delete(ctx context.Context, kid string) error
}

// ConsentSessionRepository defines the interface for consent session operations
type ConsentSessionRepository interface {
	Create(ctx context.Context, session *models.ConsentSession) error
	FindByID(ctx context.Context, id string) (*models.ConsentSession, error)
	FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.ConsentSession, error)
	Update(ctx context.Context, session *models.ConsentSession) error
	Delete(ctx context.Context, id string) error
	CleanupExpired(ctx context.Context) error
}

// DeviceCodeRepository defines the interface for device code operations
type DeviceCodeRepository interface {
	Create(ctx context.Context, deviceCode *models.DeviceCode) error
	FindByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error)
	FindByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error)
	Update(ctx context.Context, deviceCode *models.DeviceCode) error
	Delete(ctx context.Context, deviceCode string) error
	CleanupExpired(ctx context.Context) error
}

// AuditLogRepository defines the interface for audit log operations
type AuditLogRepository interface {
	Create(ctx context.Context, log *models.AuditLog) error
	Find(ctx context.Context, filter AuditLogFilter, limit, offset int) ([]*models.AuditLog, error)
	Count(ctx context.Context, filter AuditLogFilter) (int64, error)
}

type AuditLogFilter struct {
	EventType  string
	ClientID   string
	UserID     string
	StartTime  time.Time
	EndTime    time.Time
	IPAddress  string
	WithErrors bool
}
