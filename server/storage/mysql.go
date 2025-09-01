package storage

import (
	"context"
	"oidc-example/server/models"
	"oidc-example/server/storage/mysql"
	"time"

	"github.com/jmoiron/sqlx"

	"oidc-example/server/repository"
)

type mysqlStorage struct {
	db                 *sqlx.DB
	userRepo           repository.UserRepository
	clientRepo         repository.ClientRepository
	tokenRepo          repository.TokenRepository
	sessionRepo        repository.SessionRepository
	authCodeRepo       repository.AuthorizationCodeRepository
	jwkRepo            repository.JWKRepository
	consentSessionRepo repository.ConsentSessionRepository
	deviceCodeRepo     repository.DeviceCodeRepository
	auditLogRepo       repository.AuditLogRepository
}

func newMySQLStorage(connectionString string) (*mysqlStorage, error) {
	db, err := sqlx.Connect("mysql", connectionString)
	if err != nil {
		return nil, err
	}

	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(5 * time.Minute)

	// Initialize all repositories
	userRepo := mysql.NewUserRepository(db)
	clientRepo := mysql.NewClientRepository(db)
	tokenRepo := mysql.NewTokenRepository(db)
	sessionRepo := mysql.NewSessionRepository(db)
	authCodeRepo := mysql.NewAuthorizationCodeRepository(db)
	jwkRepo := mysql.NewJWKRepository(db)
	consentSessionRepo := mysql.NewConsentSessionRepository(db)
	deviceCodeRepo := mysql.NewDeviceCodeRepository(db)
	auditLogRepo := mysql.NewAuditLogRepository(db)

	return &mysqlStorage{
		db:                 db,
		userRepo:           userRepo,
		clientRepo:         clientRepo,
		tokenRepo:          tokenRepo,
		sessionRepo:        sessionRepo,
		authCodeRepo:       authCodeRepo,
		jwkRepo:            jwkRepo,
		consentSessionRepo: consentSessionRepo,
		deviceCodeRepo:     deviceCodeRepo,
		auditLogRepo:       auditLogRepo,
	}, nil
}

// User management
func (s *mysqlStorage) CreateUser(ctx context.Context, user *models.User) error {
	return s.userRepo.Create(ctx, user)
}

func (s *mysqlStorage) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	return s.userRepo.FindByID(ctx, id)
}

func (s *mysqlStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	return s.userRepo.FindByEmail(ctx, email)
}

func (s *mysqlStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	return s.userRepo.FindByUsername(ctx, username)
}

func (s *mysqlStorage) UpdateUser(ctx context.Context, user *models.User) error {
	return s.userRepo.Update(ctx, user)
}

func (s *mysqlStorage) DeleteUser(ctx context.Context, id string) error {
	return s.userRepo.Delete(ctx, id)
}

func (s *mysqlStorage) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error) {
	return s.userRepo.List(ctx, limit, offset)
}

func (s *mysqlStorage) CountUsers(ctx context.Context) (int64, error) {
	return s.userRepo.Count(ctx)
}

// Client management
func (s *mysqlStorage) CreateClient(ctx context.Context, client *models.Client) error {
	return s.clientRepo.Create(ctx, client)
}

func (s *mysqlStorage) GetClientByID(ctx context.Context, id string) (*models.Client, error) {
	return s.clientRepo.FindByID(ctx, id)
}

func (s *mysqlStorage) GetClientByCredentials(ctx context.Context, clientID, clientSecret string) (*models.Client, error) {
	return s.clientRepo.FindByCredentials(ctx, clientID, clientSecret)
}

func (s *mysqlStorage) ValidateClientRedirectURI(ctx context.Context, clientID, redirectURI string) (bool, error) {
	return s.clientRepo.ValidateRedirectURI(ctx, clientID, redirectURI)
}

func (s *mysqlStorage) UpdateClient(ctx context.Context, client *models.Client) error {
	return s.clientRepo.Update(ctx, client)
}

func (s *mysqlStorage) DeleteClient(ctx context.Context, id string) error {
	return s.clientRepo.Delete(ctx, id)
}

func (s *mysqlStorage) ListClients(ctx context.Context, limit, offset int) ([]*models.Client, error) {
	return s.clientRepo.List(ctx, limit, offset)
}

func (s *mysqlStorage) CountClients(ctx context.Context) (int64, error) {
	return s.clientRepo.Count(ctx)
}

// Token management
func (s *mysqlStorage) CreateAccessToken(ctx context.Context, token *models.AccessToken) error {
	return s.tokenRepo.CreateAccessToken(ctx, token)
}

func (s *mysqlStorage) GetAccessToken(ctx context.Context, token string) (*models.AccessToken, error) {
	return s.tokenRepo.FindAccessToken(ctx, token)
}

func (s *mysqlStorage) ValidateAccessToken(ctx context.Context, token string) (*models.AccessToken, error) {
	return s.tokenRepo.ValidateAccessToken(ctx, token)
}

func (s *mysqlStorage) RevokeAccessToken(ctx context.Context, token string) error {
	return s.tokenRepo.RevokeAccessToken(ctx, token)
}

func (s *mysqlStorage) CleanupExpiredAccessTokens(ctx context.Context) error {
	return s.tokenRepo.CleanupExpiredAccessTokens(ctx)
}

func (s *mysqlStorage) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	return s.tokenRepo.CreateRefreshToken(ctx, token)
}

func (s *mysqlStorage) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	return s.tokenRepo.FindRefreshToken(ctx, token)
}

func (s *mysqlStorage) ValidateRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	return s.tokenRepo.ValidateRefreshToken(ctx, token)
}

func (s *mysqlStorage) RevokeRefreshToken(ctx context.Context, token string) error {
	return s.tokenRepo.RevokeRefreshToken(ctx, token)
}

func (s *mysqlStorage) RevokeRefreshTokensForUserClient(ctx context.Context, userID, clientID string) error {
	return s.tokenRepo.RevokeRefreshTokensForUserClient(ctx, userID, clientID)
}

func (s *mysqlStorage) CleanupExpiredRefreshTokens(ctx context.Context) error {
	return s.tokenRepo.CleanupExpiredRefreshTokens(ctx)
}

// Implement other methods using the respective repositories...
func (m *mysqlStorage) CleanupExpiredAuthorizationCodes() error {
	// Implement the logic to clean up expired authorization codes from MySQL.
	// For now, return nil or an appropriate error.
	return nil
}
