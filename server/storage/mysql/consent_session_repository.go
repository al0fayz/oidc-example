package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"oidc-example/server/models"
	"oidc-example/server/repository"
	"oidc-example/server/utils"

	"github.com/jmoiron/sqlx"
)

type ConsentSessionRepository struct {
	db *sqlx.DB
}

func NewConsentSessionRepository(db *sqlx.DB) repository.ConsentSessionRepository {
	return &ConsentSessionRepository{db: db}
}

func (r *ConsentSessionRepository) Create(ctx context.Context, session *models.ConsentSession) error {
	accessTokenExtraJSON, err := json.Marshal(session.AccessTokenExtra)
	if err != nil {
		return err
	}

	idTokenExtraJSON, err := json.Marshal(session.IDTokenExtra)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO consent_sessions (id, client_id, user_id, scope, granted_scope, 
			access_token_extra, id_token_extra, rejected, rejected_reason, 
			expires_at, challenged_at, granted_at, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
	`

	_, err = r.db.ExecContext(ctx, query,
		session.ID,
		session.ClientID,
		session.UserID,
		session.Scope,
		session.GrantedScope,
		accessTokenExtraJSON,
		idTokenExtraJSON,
		session.Rejected,
		session.RejectedReason,
		session.ExpiresAt,
		session.ChallengedAt,
		session.GrantedAt,
	)

	return err
}

func (r *ConsentSessionRepository) FindByID(ctx context.Context, id string) (*models.ConsentSession, error) {
	query := `SELECT * FROM consent_sessions WHERE id = ?`
	var session models.ConsentSession
	err := r.db.GetContext(ctx, &session, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}

	return &session, nil
}

func (r *ConsentSessionRepository) FindByUserID(ctx context.Context, userID string, limit, offset int) ([]*models.ConsentSession, error) {
	query := `SELECT * FROM consent_sessions WHERE user_id = ? ORDER BY created_at DESC LIMIT ? OFFSET ?`
	var sessions []*models.ConsentSession
	err := r.db.SelectContext(ctx, &sessions, query, userID, limit, offset)
	if err != nil {
		return nil, err
	}

	return sessions, nil
}

func (r *ConsentSessionRepository) Update(ctx context.Context, session *models.ConsentSession) error {
	accessTokenExtraJSON, err := json.Marshal(session.AccessTokenExtra)
	if err != nil {
		return err
	}

	idTokenExtraJSON, err := json.Marshal(session.IDTokenExtra)
	if err != nil {
		return err
	}

	query := `
		UPDATE consent_sessions SET 
			granted_scope = ?, access_token_extra = ?, id_token_extra = ?, 
			rejected = ?, rejected_reason = ?, challenged_at = ?, granted_at = ?
		WHERE id = ?
	`

	_, err = r.db.ExecContext(ctx, query,
		session.GrantedScope,
		accessTokenExtraJSON,
		idTokenExtraJSON,
		session.Rejected,
		session.RejectedReason,
		session.ChallengedAt,
		session.GrantedAt,
		session.ID,
	)

	return err
}

func (r *ConsentSessionRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM consent_sessions WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *ConsentSessionRepository) CleanupExpired(ctx context.Context) error {
	query := `DELETE FROM consent_sessions WHERE expires_at <= NOW() OR rejected = 1`
	_, err := r.db.ExecContext(ctx, query)
	return err
}
