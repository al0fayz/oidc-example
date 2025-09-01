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

type DeviceCodeRepository struct {
	db *sqlx.DB
}

func NewDeviceCodeRepository(db *sqlx.DB) repository.DeviceCodeRepository {
	return &DeviceCodeRepository{db: db}
}

func (r *DeviceCodeRepository) Create(ctx context.Context, deviceCode *models.DeviceCode) error {
	query := `
		INSERT INTO device_codes (device_code, user_code, client_id, user_id, scope, expires_at, approved, denied, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, NOW())
	`

	_, err := r.db.ExecContext(ctx, query,
		deviceCode.DeviceCode,
		deviceCode.UserCode,
		deviceCode.ClientID,
		deviceCode.UserID,
		deviceCode.Scope,
		deviceCode.ExpiresAt,
		deviceCode.Approved,
		deviceCode.Denied,
	)

	return err
}

func (r *DeviceCodeRepository) FindByDeviceCode(ctx context.Context, deviceCode string) (*models.DeviceCode, error) {
	query := `SELECT * FROM device_codes WHERE device_code = ?`
	var code models.DeviceCode
	err := r.db.GetContext(ctx, &code, query, deviceCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &code, nil
}

func (r *DeviceCodeRepository) FindByUserCode(ctx context.Context, userCode string) (*models.DeviceCode, error) {
	query := `SELECT * FROM device_codes WHERE user_code = ?`
	var code models.DeviceCode
	err := r.db.GetContext(ctx, &code, query, userCode)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &code, nil
}

func (r *DeviceCodeRepository) Update(ctx context.Context, deviceCode *models.DeviceCode) error {
	query := `
		UPDATE device_codes SET 
			user_id = ?, approved = ?, denied = ?, expires_at = ?
		WHERE device_code = ?
	`

	_, err := r.db.ExecContext(ctx, query,
		deviceCode.UserID,
		deviceCode.Approved,
		deviceCode.Denied,
		deviceCode.ExpiresAt,
		deviceCode.DeviceCode,
	)

	return err
}

func (r *DeviceCodeRepository) Delete(ctx context.Context, deviceCode string) error {
	query := `DELETE FROM device_codes WHERE device_code = ?`
	_, err := r.db.ExecContext(ctx, query, deviceCode)
	return err
}

func (r *DeviceCodeRepository) CleanupExpired(ctx context.Context) error {
	query := `DELETE FROM device_codes WHERE expires_at <= NOW() OR approved = 1 OR denied = 1`
	_, err := r.db.ExecContext(ctx, query)
	return err
}
