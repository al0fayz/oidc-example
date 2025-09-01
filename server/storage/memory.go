package storage

import (
	"context"
	"oidc-example/server/models"
	"oidc-example/server/utils"
	"sync"
	"time"
)

type MemoryStorage struct {
	mu                 sync.RWMutex
	users              map[string]*models.User
	clients            map[string]*models.Client
	authorizationCodes map[string]*models.AuthorizationCode
	refreshTokens      map[string]*models.RefreshToken
	accessTokens       map[string]*models.AccessToken
	sessions           map[string]*models.Session
	jwks               map[string]*models.JWK
	consentSessions    map[string]*models.ConsentSession
	deviceCodes        map[string]*models.DeviceCode
	auditLogs          map[string]*models.AuditLog
	userCodes          map[string]string // user_code -> device_code mapping
}

func NewMemoryStorage() (*MemoryStorage, error) {
	return &MemoryStorage{
		users:              make(map[string]*models.User),
		clients:            make(map[string]*models.Client),
		authorizationCodes: make(map[string]*models.AuthorizationCode),
		refreshTokens:      make(map[string]*models.RefreshToken),
		accessTokens:       make(map[string]*models.AccessToken),
		sessions:           make(map[string]*models.Session),
		jwks:               make(map[string]*models.JWK),
		consentSessions:    make(map[string]*models.ConsentSession),
		deviceCodes:        make(map[string]*models.DeviceCode),
		auditLogs:          make(map[string]*models.AuditLog),
		userCodes:          make(map[string]string),
	}, nil
}

func (s *MemoryStorage) Ping(ctx context.Context) error {
	return nil
}

func (s *MemoryStorage) Close() error {
	return nil
}

func (s *MemoryStorage) WithTransaction(ctx context.Context, fn func(ctx context.Context) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return fn(ctx)
}

// User Management
func (s *MemoryStorage) CreateUser(ctx context.Context, user *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; exists {
		return utils.ErrAlreadyExists
	}

	s.users[user.ID] = user
	return nil
}

func (s *MemoryStorage) GetUserByID(ctx context.Context, id string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	user, exists := s.users[id]
	if !exists {
		return nil, utils.ErrNotFound
	}
	return user, nil
}

func (s *MemoryStorage) GetUserByEmail(ctx context.Context, email string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Email == email {
			return user, nil
		}
	}
	return nil, utils.ErrNotFound
}

func (s *MemoryStorage) GetUserByUsername(ctx context.Context, username string) (*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, user := range s.users {
		if user.Username == username {
			return user, nil
		}
	}
	return nil, utils.ErrNotFound
}

func (s *MemoryStorage) UpdateUser(ctx context.Context, user *models.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[user.ID]; !exists {
		return utils.ErrNotFound
	}

	s.users[user.ID] = user
	return nil
}

func (s *MemoryStorage) DeleteUser(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.users[id]; !exists {
		return utils.ErrNotFound
	}

	delete(s.users, id)
	return nil
}

func (s *MemoryStorage) ListUsers(ctx context.Context, limit, offset int) ([]*models.User, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	users := make([]*models.User, 0, len(s.users))
	for _, user := range s.users {
		users = append(users, user)
	}

	// Simple pagination
	start := offset
	end := offset + limit
	if end > len(users) {
		end = len(users)
	}
	if start > len(users) {
		return []*models.User{}, nil
	}

	return users[start:end], nil
}

func (s *MemoryStorage) CountUsers(ctx context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return int64(len(s.users)), nil
}

// Client Management
func (s *MemoryStorage) CreateClient(ctx context.Context, client *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ID]; exists {
		return utils.ErrAlreadyExists
	}

	s.clients[client.ID] = client
	return nil
}

func (s *MemoryStorage) GetClientByID(ctx context.Context, id string) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[id]
	if !exists {
		return nil, utils.ErrNotFound
	}
	return client, nil
}

func (s *MemoryStorage) GetClientByCredentials(ctx context.Context, clientID, clientSecret string) (*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists || client.Secret != clientSecret {
		return nil, utils.ErrNotFound
	}
	return client, nil
}

func (s *MemoryStorage) ValidateClientRedirectURI(ctx context.Context, clientID, redirectURI string) (bool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	client, exists := s.clients[clientID]
	if !exists {
		return false, utils.ErrNotFound
	}

	for _, uri := range client.RedirectURIs {
		if uri == redirectURI {
			return true, nil
		}
	}
	return false, nil
}

func (s *MemoryStorage) UpdateClient(ctx context.Context, client *models.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[client.ID]; !exists {
		return utils.ErrNotFound
	}

	s.clients[client.ID] = client
	return nil
}

func (s *MemoryStorage) DeleteClient(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.clients[id]; !exists {
		return utils.ErrNotFound
	}

	delete(s.clients, id)
	return nil
}

func (s *MemoryStorage) ListClients(ctx context.Context, limit, offset int) ([]*models.Client, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	clients := make([]*models.Client, 0, len(s.clients))
	for _, client := range s.clients {
		clients = append(clients, client)
	}

	// Simple pagination
	start := offset
	end := offset + limit
	if end > len(clients) {
		end = len(clients)
	}
	if start > len(clients) {
		return []*models.Client{}, nil
	}

	return clients[start:end], nil
}

func (s *MemoryStorage) CountClients(ctx context.Context) (int64, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	return int64(len(s.clients)), nil
}

// Authorization Code Management
func (s *MemoryStorage) CreateAuthorizationCode(ctx context.Context, code *models.AuthorizationCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.authorizationCodes[code.Code]; exists {
		return utils.ErrAlreadyExists
	}

	s.authorizationCodes[code.Code] = code
	return nil
}

func (s *MemoryStorage) GetAuthorizationCode(ctx context.Context, code string) (*models.AuthorizationCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	authCode, exists := s.authorizationCodes[code]
	if !exists || authCode.ExpiresAt.Before(time.Now()) || authCode.Used {
		return nil, utils.ErrNotFound
	}
	return authCode, nil
}

func (s *MemoryStorage) InvalidateAuthorizationCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	authCode, exists := s.authorizationCodes[code]
	if !exists {
		return utils.ErrNotFound
	}

	authCode.Used = true
	s.authorizationCodes[code] = authCode
	return nil
}

func (s *MemoryStorage) DeleteAuthorizationCode(ctx context.Context, code string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.authorizationCodes, code)
	return nil
}

func (s *MemoryStorage) CleanupExpiredAuthorizationCodes(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for code, authCode := range s.authorizationCodes {
		if authCode.ExpiresAt.Before(time.Now()) || authCode.Used {
			delete(s.authorizationCodes, code)
		}
	}
	return nil
}

// Refresh Token Management
func (s *MemoryStorage) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.refreshTokens[token.Token]; exists {
		return utils.ErrAlreadyExists
	}

	s.refreshTokens[token.Token] = token
	return nil
}

func (s *MemoryStorage) GetRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	refreshToken, exists := s.refreshTokens[token]
	if !exists {
		return nil, utils.ErrNotFound
	}
	return refreshToken, nil
}

func (s *MemoryStorage) ValidateRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	refreshToken, exists := s.refreshTokens[token]
	if !exists || refreshToken.ExpiresAt.Before(time.Now()) || refreshToken.Revoked {
		return nil, utils.ErrNotFound
	}
	return refreshToken, nil
}

func (s *MemoryStorage) RevokeRefreshToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	refreshToken, exists := s.refreshTokens[token]
	if !exists {
		return utils.ErrNotFound
	}

	now := time.Now()
	refreshToken.Revoked = true
	refreshToken.RevokedAt = &now
	s.refreshTokens[token] = refreshToken
	return nil
}

func (s *MemoryStorage) RevokeRefreshTokensForUserClient(ctx context.Context, userID, clientID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, refreshToken := range s.refreshTokens {
		if refreshToken.UserID == userID && refreshToken.ClientID == clientID {
			now := time.Now()
			refreshToken.Revoked = true
			refreshToken.RevokedAt = &now
			s.refreshTokens[token] = refreshToken
		}
	}
	return nil
}

func (s *MemoryStorage) CleanupExpiredRefreshTokens(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, refreshToken := range s.refreshTokens {
		if refreshToken.ExpiresAt.Before(time.Now()) || refreshToken.Revoked {
			delete(s.refreshTokens, token)
		}
	}
	return nil
}

// Access Token Management
func (s *MemoryStorage) CreateAccessToken(ctx context.Context, token *models.AccessToken) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.accessTokens[token.Token]; exists {
		return utils.ErrAlreadyExists
	}

	s.accessTokens[token.Token] = token
	return nil
}

func (s *MemoryStorage) GetAccessToken(ctx context.Context, token string) (*models.AccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	accessToken, exists := s.accessTokens[token]
	if !exists {
		return nil, utils.ErrNotFound
	}
	return accessToken, nil
}

func (s *MemoryStorage) ValidateAccessToken(ctx context.Context, token string) (*models.AccessToken, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	accessToken, exists := s.accessTokens[token]
	if !exists || accessToken.ExpiresAt.Before(time.Now()) || accessToken.Revoked {
		return nil, utils.ErrNotFound
	}
	return accessToken, nil
}

func (s *MemoryStorage) RevokeAccessToken(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	accessToken, exists := s.accessTokens[token]
	if !exists {
		return utils.ErrNotFound
	}

	now := time.Now()
	accessToken.Revoked = true
	accessToken.RevokedAt = &now
	s.accessTokens[token] = accessToken
	return nil
}

func (s *MemoryStorage) CleanupExpiredAccessTokens(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, accessToken := range s.accessTokens {
		if accessToken.ExpiresAt.Before(time.Now()) || accessToken.Revoked {
			delete(s.accessTokens, token)
		}
	}
	return nil
}

// Session Management
func (s *MemoryStorage) CreateSession(ctx context.Context, session *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.Token]; exists {
		return utils.ErrAlreadyExists
	}

	s.sessions[session.Token] = session
	return nil
}

func (s *MemoryStorage) GetSession(ctx context.Context, token string) (*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.sessions[token]
	if !exists || session.ExpiresAt.Before(time.Now()) {
		return nil, utils.ErrNotFound
	}
	return session, nil
}

func (s *MemoryStorage) GetSessionsForUser(ctx context.Context, userID string, limit, offset int) ([]*models.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sessions []*models.Session
	for _, session := range s.sessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}

	// Simple pagination
	start := offset
	end := offset + limit
	if end > len(sessions) {
		end = len(sessions)
	}
	if start > len(sessions) {
		return []*models.Session{}, nil
	}

	return sessions[start:end], nil
}

func (s *MemoryStorage) UpdateSession(ctx context.Context, session *models.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.sessions[session.Token]; !exists {
		return utils.ErrNotFound
	}

	s.sessions[session.Token] = session
	return nil
}

func (s *MemoryStorage) DeleteSession(ctx context.Context, token string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.sessions, token)
	return nil
}

func (s *MemoryStorage) DeleteSessionsForUser(ctx context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, session := range s.sessions {
		if session.UserID == userID {
			delete(s.sessions, token)
		}
	}
	return nil
}

func (s *MemoryStorage) CleanupExpiredSessions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for token, session := range s.sessions {
		if session.ExpiresAt.Before(time.Now()) {
			delete(s.sessions, token)
		}
	}
	return nil
}

// JWK Management
func (s *MemoryStorage) CreateJWK(ctx context.Context, jwk *models.JWK) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.jwks[jwk.KID]; exists {
		return utils.ErrAlreadyExists
	}

	s.jwks[jwk.KID] = jwk
	return nil
}

func (s *MemoryStorage) GetJWK(ctx context.Context, kid string) (*models.JWK, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	jwk, exists := s.jwks[kid]
	if !exists || (jwk.ExpiresAt != nil && jwk.ExpiresAt.Before(time.Now())) {
		return nil, utils.ErrNotFound
	}
	return jwk, nil
}

func (s *MemoryStorage) GetActiveJWKs(ctx context.Context) ([]*models.JWK, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var jwks []*models.JWK
	for _, jwk := range s.jwks {
		if jwk.ExpiresAt == nil || !jwk.ExpiresAt.Before(time.Now()) {
			jwks = append(jwks, jwk)
		}
	}
	return jwks, nil
}

func (s *MemoryStorage) RotateJWK(ctx context.Context, kid string) error {
	// Not implemented in memory storage
	return nil
}

func (s *MemoryStorage) DeleteJWK(ctx context.Context, kid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.jwks, kid)
	return nil
}

// Consent Session Management
func (s *MemoryStorage) CreateConsentSession(ctx context.Context, session *models.ConsentSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.consentSessions[session.ID]; exists {
		return utils.ErrAlreadyExists
	}

	s.consentSessions[session.ID] = session
	return nil
}

func (s *MemoryStorage) GetConsentSession(ctx context.Context, id string) (*models.ConsentSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	session, exists := s.consentSessions[id]
	if !exists || session.ExpiresAt.Before(time.Now()) {
		return nil, utils.ErrNotFound
	}
	return session, nil
}

func (s *MemoryStorage) GetConsentSessionsForUser(ctx context.Context, userID string, limit, offset int) ([]*models.ConsentSession, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var sessions []*models.ConsentSession
	for _, session := range s.consentSessions {
		if session.UserID == userID {
			sessions = append(sessions, session)
		}
	}

	// Simple pagination
	start := offset
	end := offset + limit
	if end > len(sessions) {
		end = len(sessions)
	}
	if start > len(sessions) {
		return []*models.ConsentSession{}, nil
	}

	return sessions[start:end], nil
}

func (s *MemoryStorage) UpdateConsentSession(ctx context.Context, session *models.ConsentSession) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.consentSessions[session.ID]; !exists {
		return utils.ErrNotFound
	}

	s.consentSessions[session.ID] = session
	return nil
}

func (s *MemoryStorage) DeleteConsentSession(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.consentSessions, id)
	return nil
}

func (s *MemoryStorage) CleanupExpiredConsentSessions(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for id, session := range s.consentSessions {
		if session.ExpiresAt.Before(time.Now()) || session.Rejected {
			delete(s.consentSessions, id)
		}
	}
	return nil
}

// Device Code Management
func (s *MemoryStorage) CreateDeviceCode(ctx context.Context, deviceCode *models.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.deviceCodes[deviceCode.DeviceCode]; exists {
		return utils.ErrAlreadyExists
	}
	if _, exists := s.userCodes[deviceCode.UserCode]; exists {
		return utils.ErrAlreadyExists
	}

	s.deviceCodes[deviceCode.DeviceCode] = deviceCode
	s.userCodes[deviceCode.UserCode] = deviceCode.DeviceCode
	return nil
}

func (s *MemoryStorage) GetDeviceCodeByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	code, exists := s.deviceCodes[deviceCode]
	if !exists || code.ExpiresAt.Before(time.Now()) {
		return nil, utils.ErrNotFound
	}
	return code, nil
}

func (s *MemoryStorage) GetDeviceCodeByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	deviceCode, exists := s.userCodes[userCode]
	if !exists {
		return nil, utils.ErrNotFound
	}

	code, exists := s.deviceCodes[deviceCode]
	if !exists || code.ExpiresAt.Before(time.Now()) {
		return nil, utils.ErrNotFound
	}
	return code, nil
}

func (s *MemoryStorage) UpdateDeviceCode(ctx context.Context, deviceCode *models.DeviceCode) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.deviceCodes[deviceCode.DeviceCode]; !exists {
		return utils.ErrNotFound
	}

	s.deviceCodes[deviceCode.DeviceCode] = deviceCode
	return nil
}

func (s *MemoryStorage) DeleteDeviceCode(ctx context.Context, deviceCode string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	code, exists := s.deviceCodes[deviceCode]
	if exists {
		delete(s.userCodes, code.UserCode)
	}
	delete(s.deviceCodes, deviceCode)
	return nil
}

func (s *MemoryStorage) CleanupExpiredDeviceCodes(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for deviceCode, code := range s.deviceCodes {
		if code.ExpiresAt.Before(time.Now()) || code.Approved || code.Denied {
			delete(s.userCodes, code.UserCode)
			delete(s.deviceCodes, deviceCode)
		}
	}
	return nil
}

// Audit Log Management
func (s *MemoryStorage) CreateAuditLog(ctx context.Context, log *models.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.auditLogs[log.ID]; exists {
		return utils.ErrAlreadyExists
	}

	s.auditLogs[log.ID] = log
	return nil
}

func (s *MemoryStorage) GetAuditLogs(ctx context.Context, filter AuditLogFilter, limit, offset int) ([]*models.AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var logs []*models.AuditLog
	for _, log := range s.auditLogs {
		// Apply filters
		if filter.EventType != "" && log.EventType != filter.EventType {
			continue
		}
		if filter.ClientID != "" && log.ClientID != filter.ClientID {
			continue
		}
		if filter.UserID != "" && log.UserID != filter.UserID {
			continue
		}
		if filter.IPAddress != "" && log.IPAddress != filter.IPAddress {
			continue
		}
		if !filter.StartTime.IsZero() && log.CreatedAt.Before(filter.StartTime) {
			continue
		}
		if !filter.EndTime.IsZero() && log.CreatedAt.After(filter.EndTime) {
			continue
		}
		if filter.WithErrors && log.Error == "" {
			continue
		}

		logs = append(logs, log)
	}

	// Simple pagination
	start := offset
	end := offset + limit
	if end > len(logs) {
		end = len(logs)
	}
	if start > len(logs) {
		return []*models.AuditLog{}, nil
	}

	return logs[start:end], nil
}

func (s *MemoryStorage) CountAuditLogs(ctx context.Context, filter AuditLogFilter) (int64, error) {
	logs, err := s.GetAuditLogs(ctx, filter, 0, 0)
	if err != nil {
		return 0, err
	}
	return int64(len(logs)), nil
}
