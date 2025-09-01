package storage

import (
	"context"
	"oidc-example/server/models"
	"oidc-example/server/storage/mysql"
	"time"

	"github.com/jmoiron/sqlx"

	"oidc-example/server/repository"

	_ "github.com/go-sql-driver/mysql"
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

func (s *mysqlStorage) Ping(ctx context.Context) error {
	return s.db.PingContext(ctx)
}

func (s *mysqlStorage) Close() error {
	return s.db.Close()
}

func (s *mysqlStorage) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	tx, err := s.db.BeginTxx(ctx, nil)
	if err != nil {
		return err
	}

	txCtx := context.WithValue(ctx, "tx", tx)

	defer func() {
		if p := recover(); p != nil {
			tx.Rollback()
			panic(p)
		}
	}()

	if err := fn(txCtx); err != nil {
		tx.Rollback()
		return err
	}

	return tx.Commit()
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

// Authorization code management
func (s *mysqlStorage) CreateAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error {
	return s.authCodeRepo.Create(ctx, code)
}

func (s *mysqlStorage) GetAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error) {
	return s.authCodeRepo.FindByCode(ctx, code)
}

func (s *mysqlStorage) InvalidateAuthorizationCode(ctx context.Context, code string) error {
	return s.authCodeRepo.Invalidate(ctx, code)
}

func (s *mysqlStorage) DeleteAuthorizationCode(ctx context.Context, code string) error {
	return s.authCodeRepo.Delete(ctx, code)
}

func (s *mysqlStorage) CleanupExpiredAuthorizationCodes(ctx context.Context) error {
	return s.authCodeRepo.CleanupExpired(ctx)
}

// Session management
func (s *mysqlStorage) CreateSession(ctx context.Context, session *models.Session) error {
	return s.sessionRepo.Create(ctx, session)
}

func (s *mysqlStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	return s.sessionRepo.FindByToken(ctx, token)
}

func (s *mysqlStorage) GetSessionsForUser(ctx context.Context, userID string, limit, offset int) ([]*models.Session, error) {
	return s.sessionRepo.FindByUserID(ctx, userID, limit, offset)
}

func (s *mysqlStorage) UpdateSession(ctx context.Context, session *models.Session) error {
	return s.sessionRepo.Update(ctx, session)
}

func (s *mysqlStorage) DeleteSession(ctx context.Context, token string) error {
	return s.sessionRepo.Delete(ctx, token)
}

func (s *mysqlStorage) DeleteSessionsForUser(ctx context.Context, userID string) error {
	return s.sessionRepo.DeleteByUserID(ctx, userID)
}

func (s *mysqlStorage) CleanupExpiredSessions(ctx context.Context) error {
	return s.sessionRepo.CleanupExpired(ctx)
}

// JWK management
func (s *mysqlStorage) CreateJWK(ctx context.Context, jwk *models.JWK) error {
	return s.jwkRepo.Create(ctx, jwk)
}

func (s *mysqlStorage) GetJWK(ctx context.Context, kid string) (*models.JWK, error) {
	return s.jwkRepo.FindByKID(ctx, kid)
}

func (s *mysqlStorage) GetActiveJWKs(ctx context.Context) ([]*models.JWK, error) {
	return s.jwkRepo.FindActive(ctx)
}

func (s *mysqlStorage) RotateJWK(ctx context.Context, kid string) error {
	return s.jwkRepo.Rotate(ctx, kid)
}

func (s *mysqlStorage) DeleteJWK(ctx context.Context, kid string) error {
	return s.jwkRepo.Delete(ctx, kid)
}

// consent management
func (s *mysqlStorage) CreateConsentSession(ctx context.Context, session *models.ConsentSession) error {
	return s.consentSessionRepo.Create(ctx, session)
}

func (s *mysqlStorage) GetConsentSession(ctx context.Context, id string) (*models.ConsentSession, error) {
	return s.consentSessionRepo.FindByID(ctx, id)
}

func (s *mysqlStorage) GetConsentSessionsForUser(ctx context.Context, userID string, limit, offset int) ([]*models.ConsentSession, error) {
	return s.consentSessionRepo.FindByUserID(ctx, userID, limit, offset)
}

func (s *mysqlStorage) UpdateConsentSession(ctx context.Context, session *models.ConsentSession) error {
	return s.consentSessionRepo.Update(ctx, session)
}

func (s *mysqlStorage) DeleteConsentSession(ctx context.Context, id string) error {
	return s.consentSessionRepo.Delete(ctx, id)
}

func (s *mysqlStorage) CleanupExpiredConsentSessions(ctx context.Context) error {
	return s.consentSessionRepo.CleanupExpired(ctx)
}

// device code management
func (s *mysqlStorage) CreateDeviceCode(ctx context.Context, deviceCode *models.DeviceCode) error {
	return s.deviceCodeRepo.Create(ctx, deviceCode)
}

func (s *mysqlStorage) GetDeviceCodeByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error) {
	return s.deviceCodeRepo.FindByDeviceCode(ctx, deviceCode)
}

func (s *mysqlStorage) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error) {
	return s.deviceCodeRepo.FindByUserCode(ctx, userCode)
}

func (s *mysqlStorage) UpdateDeviceCode(ctx context.Context, deviceCode *models.DeviceCode) error {
	return s.deviceCodeRepo.Update(ctx, deviceCode)
}

func (s *mysqlStorage) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	return s.deviceCodeRepo.Delete(ctx, deviceCode)
}

func (s *mysqlStorage) CleanupExpiredDeviceCodes(ctx context.Context) error {
	return s.deviceCodeRepo.CleanupExpired(ctx)
}

// audit logging management
func (s *mysqlStorage) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	return s.auditLogRepo.Create(ctx, log)
}

func (s *mysqlStorage) GetAuditLogs(ctx context.Context, filter repository.AuditLogFilter, limit, offset int) ([]*models.AuditLog, error) {
	return s.auditLogRepo.Find(ctx, filter, limit, offset)
}

func (s *mysqlStorage) CountAuditLogs(ctx context.Context, filter repository.AuditLogFilter) (int64, error) {
	return s.auditLogRepo.Count(ctx, filter)
}
