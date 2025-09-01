package mysql

import (
	"context"
	"database/sql"
	"errors"
	"oidc-example/server/models"
	"oidc-example/server/repository"
	"oidc-example/server/utils"

	"github.com/jmoiron/sqlx"
)

type TokenRepository struct {
	db *sqlx.DB
}

func NewTokenRepository(db *sqlx.DB) repository.TokenRepository {
	return &TokenRepository{db: db}
}

func (r *TokenRepository) CreateAccessToken(ctx context.Context, token *models.AccessToken) error {
	query := `
		INSERT INTO access_tokens (token, client_id, user_id, scope, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, NOW())
	`

	_, err := r.db.ExecContext(ctx, query,
		token.Token, token.ClientID, token.UserID, token.Scope, token.ExpiresAt,
	)
	return err
}

func (r *TokenRepository) FindAccessToken(ctx context.Context, token string) (*models.AccessToken, error) {
	query := `SELECT * FROM access_tokens WHERE token = ?`
	var accessToken models.AccessToken
	err := r.db.GetContext(ctx, &accessToken, query, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &accessToken, nil
}

func (r *TokenRepository) ValidateAccessToken(ctx context.Context, token string) (*models.AccessToken, error) {
	query := `
		SELECT * FROM access_tokens 
		WHERE token = ? AND expires_at > NOW() AND revoked = 0
	`
	var accessToken models.AccessToken
	err := r.db.GetContext(ctx, &accessToken, query, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &accessToken, nil
}

func (r *TokenRepository) RevokeAccessToken(ctx context.Context, token string) error {
	query := `UPDATE access_tokens SET revoked = 1, revoked_at = NOW() WHERE token = ?`
	_, err := r.db.ExecContext(ctx, query, token)
	return err
}

func (r *TokenRepository) CleanupExpiredAccessTokens(ctx context.Context) error {
	query := `DELETE FROM access_tokens WHERE expires_at <= NOW() OR revoked = 1`
	_, err := r.db.ExecContext(ctx, query)
	return err
}

// Refresh token methods
func (r *TokenRepository) CreateRefreshToken(ctx context.Context, token *models.RefreshToken) error {
	query := `
		INSERT INTO refresh_tokens (token, client_id, user_id, scope, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, NOW())
	`

	_, err := r.db.ExecContext(ctx, query,
		token.Token, token.ClientID, token.UserID, token.Scope, token.ExpiresAt,
	)
	return err
}

func (r *TokenRepository) FindRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	query := `SELECT * FROM refresh_tokens WHERE token = ?`
	var refreshToken models.RefreshToken
	err := r.db.GetContext(ctx, &refreshToken, query, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &refreshToken, nil
}

func (r *TokenRepository) ValidateRefreshToken(ctx context.Context, token string) (*models.RefreshToken, error) {
	query := `
		SELECT * FROM refresh_tokens 
		WHERE token = ? AND expires_at > NOW() AND revoked = 0
	`
	var refreshToken models.RefreshToken
	err := r.db.GetContext(ctx, &refreshToken, query, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &refreshToken, nil
}

func (r *TokenRepository) RevokeRefreshToken(ctx context.Context, token string) error {
	query := `UPDATE refresh_tokens SET revoked = 1, revoked_at = NOW() WHERE token = ?`
	_, err := r.db.ExecContext(ctx, query, token)
	return err
}

func (r *TokenRepository) RevokeRefreshTokensForUserClient(ctx context.Context, userID, clientID string) error {
	query := `UPDATE refresh_tokens SET revoked = 1, revoked_at = NOW() WHERE user_id = ? AND client_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID, clientID)
	return err
}

func (r *TokenRepository) CleanupExpiredRefreshTokens(ctx context.Context) error {
	query := `DELETE FROM refresh_tokens WHERE expires_at <= NOW() OR revoked = 1`
	_, err := r.db.ExecContext(ctx, query)
	return err
}
