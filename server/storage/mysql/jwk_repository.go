package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"oidc-example/server/models"
	"oidc-example/server/repository"
	"oidc-example/server/utils"
	"time"

	"github.com/jmoiron/sqlx"
)

type JWKRepository struct {
	db *sqlx.DB
}

func NewJWKRepository(db *sqlx.DB) repository.JWKRepository {
	return &JWKRepository{db: db}
}

func (r *JWKRepository) Create(ctx context.Context, jwk *models.JWK) error {
	operationsJSON, err := json.Marshal(jwk.Operations)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO jwks (kid, kty, key_use, alg, n, e, d, p, q, dp, dq, qi, operations, expires_at, created_at, rotated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), ?)
	`

	_, err = r.db.ExecContext(ctx, query,
		jwk.KID,
		jwk.Kty,
		jwk.Use,
		jwk.Alg,
		jwk.N,
		jwk.E,
		jwk.D,
		jwk.P,
		jwk.Q,
		jwk.Dp,
		jwk.Dq,
		jwk.Qi,
		operationsJSON,
		jwk.ExpiresAt,
		jwk.RotatedAt,
	)

	return err
}

func (r *JWKRepository) FindByKID(ctx context.Context, kid string) (*models.JWK, error) {
	query := `SELECT * FROM jwks WHERE kid = ? AND (expires_at IS NULL OR expires_at > NOW())`
	var jwk models.JWK
	err := r.db.GetContext(ctx, &jwk, query, kid)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &jwk, nil
}

func (r *JWKRepository) FindActive(ctx context.Context) ([]*models.JWK, error) {
	query := `SELECT * FROM jwks WHERE expires_at IS NULL OR expires_at > NOW() ORDER BY created_at DESC`
	var jwks []*models.JWK
	err := r.db.SelectContext(ctx, &jwks, query)
	if err != nil {
		return nil, err
	}

	return jwks, nil
}

func (r *JWKRepository) Rotate(ctx context.Context, kid string) error {
	// Get the current JWK
	jwk, err := r.FindByKID(ctx, kid)
	if err != nil {
		return err
	}

	// Set expiration for the old key
	now := time.Now()
	jwk.ExpiresAt = &now
	jwk.RotatedAt = &now

	// Update the existing JWK
	operationsJSON, err := json.Marshal(jwk.Operations)
	if err != nil {
		return err
	}

	query := `
		UPDATE jwks SET 
			expires_at = ?, rotated_at = ?, operations = ?
		WHERE kid = ?
	`

	_, err = r.db.ExecContext(ctx, query,
		jwk.ExpiresAt,
		jwk.RotatedAt,
		operationsJSON,
		kid,
	)

	return err
}

func (r *JWKRepository) Delete(ctx context.Context, kid string) error {
	query := `DELETE FROM jwks WHERE kid = ?`
	_, err := r.db.ExecContext(ctx, query, kid)
	return err
}
