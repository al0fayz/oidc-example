package models

import (
	"time"
)

// User model
type User struct {
	ID                  string      `db:"id" json:"id"`
	Username            string      `db:"username" json:"username"`
	Email               string      `db:"email" json:"email"`
	EmailVerified       bool        `db:"email_verified" json:"email_verified"`
	PasswordHash        string      `db:"password_hash" json:"-"`
	Name                string      `db:"name" json:"name"`
	GivenName           string      `db:"given_name" json:"given_name"`
	FamilyName          string      `db:"family_name" json:"family_name"`
	MiddleName          string      `db:"middle_name" json:"middle_name"`
	Nickname            string      `db:"nickname" json:"nickname"`
	Profile             string      `db:"profile" json:"profile"`
	Picture             string      `db:"picture" json:"picture"`
	Website             string      `db:"website" json:"website"`
	Gender              string      `db:"gender" json:"gender"`
	Birthdate           *time.Time  `db:"birthdate" json:"birthdate,omitempty"`
	Zoneinfo            string      `db:"zoneinfo" json:"zoneinfo"`
	Locale              string      `db:"locale" json:"locale"`
	PhoneNumber         string      `db:"phone_number" json:"phone_number"`
	PhoneNumberVerified bool        `db:"phone_number_verified" json:"phone_number_verified"`
	Address             JSONMap     `db:"address" json:"address"`
	CreatedAt           time.Time   `db:"created_at" json:"created_at"`
	UpdatedAt           time.Time   `db:"updated_at" json:"updated_at"`
	LastLogin           *time.Time  `db:"last_login" json:"last_login,omitempty"`
	LastIP              string      `db:"last_ip" json:"last_ip"`
	LoginCount          int         `db:"login_count" json:"login_count"`
	Blocked             bool        `db:"blocked" json:"blocked"`
	MFAEnabled          bool        `db:"mfa_enabled" json:"mfa_enabled"`
	MFASecret           string      `db:"mfa_secret" json:"-"`
	RecoveryCodes       StringArray `db:"recovery_codes" json:"-"`
	Metadata            JSONMap     `db:"metadata" json:"metadata"`
}
