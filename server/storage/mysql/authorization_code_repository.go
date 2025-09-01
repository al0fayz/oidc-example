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

type AuthorizationCodeRepository struct {
	db *sqlx.DB
}

func NewAuthorizationCodeRepository(db *sqlx.DB) repository.AuthorizationCodeRepository {
	return &AuthorizationCodeRepository{db: db}
}

func (r *AuthorizationCodeRepository) Create(ctx context.Context, code *models.AuthorizationCode) error {
	query := `
		INSERT INTO authorization_codes (code, client_id, redirect_uri, scope, user_id, nonce, code_challenge, code_challenge_method, expires_at, used, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
	`

	_, err := r.db.ExecContext(ctx, query,
		code.Code,
		code.ClientID,
		code.RedirectURI,
		code.Scope,
		code.UserID,
		code.Nonce,
		code.CodeChallenge,
		code.CodeChallengeMethod,
		code.ExpiresAt,
		code.Used,
	)

	return err
}

func (r *AuthorizationCodeRepository) FindByCode(ctx context.Context, code string) (*models.AuthorizationCode, error) {
	query := `SELECT * FROM authorization_codes WHERE code = ? AND expires_at > NOW() AND used = 0`
	var authCode models.AuthorizationCode
	err := r.db.GetContext(ctx, &authCode, query, code)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &authCode, nil
}

func (r *AuthorizationCodeRepository) Invalidate(ctx context.Context, code string) error {
	query := `UPDATE authorization_codes SET used = 1 WHERE code = ?`
	_, err := r.db.ExecContext(ctx, query, code)
	return err
}

func (r *AuthorizationCodeRepository) Delete(ctx context.Context, code string) error {
	query := `DELETE FROM authorization_codes WHERE code = ?`
	_, err := r.db.ExecContext(ctx, query, code)
	return err
}

func (r *AuthorizationCodeRepository) CleanupExpired(ctx context.Context) error {
	query := `DELETE FROM authorization_codes WHERE expires_at <= NOW() OR used = 1`
	_, err := r.db.ExecContext(ctx, query)
	return err
}
