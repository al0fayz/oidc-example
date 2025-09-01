package storage

import (
	"context"
	"oidc-example/server/models"
	"oidc-example/server/repository"
)

type Storage interface {
	// User management
	CreateUser(ctx context.Context, user *models.User) error
	GetUserByID(ctx context.Context, id string) (*models.User, error)
	GetUserByEmail(ctx context.Context, email string) (*models.User, error)
	GetUserByUsername(ctx context.Context, username string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, id string) error
	ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error)
	CountUsers(ctx context.Context) (int64, error)

	// Client management
	CreateClient(ctx context.Context, client *models.Client) error
	GetClientByID(ctx context.Context, id string) (*models.Client, error)
	GetClientByCredentials(ctx context.Context, clientID, clientSecret string) (*models.Client, error)
	UpdateClient(ctx context.Context, client *models.Client) error
	DeleteClient(ctx context.Context, id string) error
	ListClients(ctx context.Context, limit, offset int) ([]*models.Client, error)
	CountClients(ctx context.Context) (int64, error)
	ValidateClientRedirectURI(ctx context.Context, clientID, redirectURI string) (bool, error)

	// Authorization code management
	CreateAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error
	GetAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error)
	InvalidateAuthorizationCode(ctx context.Context, code string) error
	DeleteAuthorizationCode(ctx context.Context, code string) error
	CleanupExpiredAuthorizationCodes(ctx context.Context) error

	// Token management
	CreateAccessToken(ctx context.Context, token *models.AccessToken) error
	GetAccessToken(ctx context.Context, token string) (*models.AccessToken, error)
	RevokeAccessToken(ctx context.Context, token string) error
	ValidateAccessToken(ctx context.Context, token string) (*models.AccessToken, error)
	CleanupExpiredAccessTokens(ctx context.Context) error

	CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error
	GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
	RevokeRefreshToken(ctx context.Context, token string) error
	ValidateRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error)
	RevokeRefreshTokensForUserClient(ctx context.Context, userID, clientID string) error
	CleanupExpiredRefreshTokens(ctx context.Context) error

	// Session management
	CreateSession(ctx context.Context, session *models.Session) error
	GetSession(ctx context.Context, token string) (*models.Session, error)
	GetSessionsForUser(ctx context.Context, userID string, limit, offset int) ([]*models.Session, error)
	UpdateSession(ctx context.Context, session *models.Session) error
	DeleteSession(ctx context.Context, token string) error
	DeleteSessionsForUser(ctx context.Context, userID string) error
	CleanupExpiredSessions(ctx context.Context) error

	// JWK management
	CreateJWK(ctx context.Context, jwk *models.JWK) error
	GetJWK(ctx context.Context, kid string) (*models.JWK, error)
	GetActiveJWKs(ctx context.Context) ([]*models.JWK, error)
	RotateJWK(ctx context.Context, kid string) error
	DeleteJWK(ctx context.Context, kid string) error

	// Consent management
	CreateConsentSession(ctx context.Context, session *models.ConsentSession) error
	GetConsentSession(ctx context.Context, id string) (*models.ConsentSession, error)
	GetConsentSessionsForUser(ctx context.Context, userID string, limit, offset int) ([]*models.ConsentSession, error)
	UpdateConsentSession(ctx context.Context, session *models.ConsentSession) error
	DeleteConsentSession(ctx context.Context, id string) error
	CleanupExpiredConsentSessions(ctx context.Context) error

	// Device code management
	CreateDeviceCode(ctx context.Context, deviceCode *models.DeviceCode) error
	GetDeviceCodeByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error)
	GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error)
	UpdateDeviceCode(ctx context.Context, deviceCode *models.DeviceCode) error
	DeleteDeviceCode(ctx context.Context, deviceCode string) error
	CleanupExpiredDeviceCodes(ctx context.Context) error

	// Audit logging
	CreateAuditLog(ctx context.Context, log *models.AuditLog) error
	GetAuditLogs(ctx context.Context, filter repository.AuditLogFilter, limit, offset int) ([]*models.AuditLog, error)
	CountAuditLogs(ctx context.Context, filter repository.AuditLogFilter) (int64, error)

	// Maintenance operations
	Ping(ctx context.Context) error
	Close() error
	WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error
}
