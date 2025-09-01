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

type SessionRepository struct {
	db *sqlx.DB
}

func NewSessionRepository(db *sqlx.DB) repository.SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) Create(ctx context.Context, session *models.Session) error {
	query := `
		INSERT INTO sessions (token, user_id, client_id, user_agent, ip_address, expires_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, NOW())
	`

	_, err := r.db.ExecContext(ctx, query,
		session.Token,
		session.UserID,
		session.ClientID,
		session.UserAgent,
		session.IPAddress,
		session.ExpiresAt,
	)

	return err
}

func (r *SessionRepository) FindByToken(ctx context.Context, token string) (*models.Session, error) {
	query := `SELECT * FROM sessions WHERE token = ? AND expires_at > NOW()`
	var session models.Session
	err := r.db.GetContext(ctx, &session, query, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &session, nil
}

func (r *SessionRepository) FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.Session, error) {
	query := `SELECT * FROM sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
	var sessions []*models.Session
	err := r.db.SelectContext(ctx, &sessions, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}
	return sessions, nil
}

func (r *SessionRepository) Update(ctx context.Context, session *models.Session) error {
	query := `
		UPDATE sessions SET 
			client_id = ?, user_agent = ?, ip_address = ?, expires_at = ?
		WHERE token = ?
	`

	_, err := r.db.ExecContext(ctx, query,
		session.ClientID,
		session.UserAgent,
		session.IPAddress,
		session.ExpiresAt,
		session.Token,
	)

	return err
}

func (r *SessionRepository) Delete(ctx context.Context, token string) error {
	query := `DELETE FROM sessions WHERE token = ?`
	_, err := r.db.ExecContext(ctx, query, token)
	return err
}

func (r *SessionRepository) DeleteByUserID(ctx context.Context, userID string) error {
	query := `DELETE FROM sessions WHERE user_id = ?`
	_, err := r.db.ExecContext(ctx, query, userID)
	return err
}

func (r *SessionRepository) CleanupExpired(ctx context.Context) error {
	query := `DELETE FROM sessions WHERE expires_at <= NOW()`
	_, err := r.db.ExecContext(ctx, query)
	return err
}
