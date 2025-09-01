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

type UserRepository struct {
	db *sqlx.DB
}

func NewUserRepository(db *sqlx.DB) repository.UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) Create(ctx context.Context, user *models.User) error {
	query := `
		INSERT INTO users (id, username, email, email_verified, password_hash, name, 
			given_name, family_name, middle_name, nickname, profile, picture, website, 
			gender, birthdate, zoneinfo, locale, phone_number, phone_number_verified, 
			address, last_ip, login_count, blocked, mfa_enabled, mfa_secret, 
			recovery_codes, metadata, created_at, updated_at, last_login)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
		        ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW(), ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID, user.Username, user.Email, user.EmailVerified, user.PasswordHash, user.Name,
		user.GivenName, user.FamilyName, user.MiddleName, user.Nickname, user.Profile, user.Picture, user.Website,
		user.Gender, user.Birthdate, user.Zoneinfo, user.Locale, user.PhoneNumber, user.PhoneNumberVerified,
		user.Address, user.LastIP, user.LoginCount, user.Blocked, user.MFAEnabled, user.MFASecret,
		user.RecoveryCodes, user.Metadata, user.LastLogin,
	)

	return err
}

func (r *UserRepository) FindByID(ctx context.Context, id string) (*models.User, error) {
	query := `SELECT * FROM users WHERE id = ?`
	var user models.User
	err := r.db.GetContext(ctx, &user, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByEmail(ctx context.Context, email string) (*models.User, error) {
	query := `SELECT * FROM users WHERE email = ?`
	var user models.User
	err := r.db.GetContext(ctx, &user, query, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByUsername(ctx context.Context, username string) (*models.User, error) {
	query := `SELECT * FROM users WHERE username = ?`
	var user models.User
	err := r.db.GetContext(ctx, &user, query, username)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) Update(ctx context.Context, user *models.User) error {
	query := `
		UPDATE users SET 
			username = ?, email = ?, email_verified = ?, name = ?,
			given_name = ?, family_name = ?, middle_name = ?, nickname = ?,
			profile = ?, picture = ?, website = ?, gender = ?, birthdate = ?,
			zoneinfo = ?, locale = ?, phone_number = ?, phone_number_verified = ?,
			address = ?, last_ip = ?, login_count = ?, blocked = ?,
			mfa_enabled = ?, mfa_secret = ?, recovery_codes = ?, metadata = ?,
			last_login = ?, updated_at = NOW()
		WHERE id = ?
	`

	_, err := r.db.ExecContext(ctx, query,
		user.Username, user.Email, user.EmailVerified, user.Name,
		user.GivenName, user.FamilyName, user.MiddleName, user.Nickname,
		user.Profile, user.Picture, user.Website, user.Gender, user.Birthdate,
		user.Zoneinfo, user.Locale, user.PhoneNumber, user.PhoneNumberVerified,
		user.Address, user.LastIP, user.LoginCount, user.Blocked,
		user.MFAEnabled, user.MFASecret, user.RecoveryCodes, user.Metadata,
		user.LastLogin, user.ID,
	)

	return err
}

func (r *UserRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM users WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *UserRepository) List(ctx context.Context, limit, offset int) ([]*models.User, error) {
	query := `SELECT * FROM users ORDER BY created_at DESC LIMIT ? OFFSET ?`
	var users []*models.User
	err := r.db.SelectContext(ctx, &users, query, limit, offset)
	return users, err
}

func (r *UserRepository) Count(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM users`
	var count int64
	err := r.db.GetContext(ctx, &count, query)
	return count, err
}
