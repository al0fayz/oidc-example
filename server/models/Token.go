package models

import "time"

// AuthorizationCode model
type AuthorizationCode struct {
	Code                string    `db:"code" json:"code"`
	ClientID            string    `db:"client_id" json:"client_id"`
	RedirectURI         string    `db:"redirect_uri" json:"redirect_uri"`
	Scope               string    `db:"scope" json:"scope"`
	UserID              string    `db:"user_id" json:"user_id"`
	Nonce               string    `db:"nonce" json:"nonce,omitempty"`
	CodeChallenge       string    `db:"code_challenge" json:"code_challenge,omitempty"`
	CodeChallengeMethod string    `db:"code_challenge_method" json:"code_challenge_method,omitempty"`
	ExpiresAt           time.Time `db:"expires_at" json:"expires_at"`
	Used                bool      `db:"used" json:"used"`
	CreatedAt           time.Time `db:"created_at" json:"created_at"`
}

// RefreshToken model
type RefreshToken struct {
	Token     string     `db:"token" json:"token"`
	ClientID  string     `db:"client_id" json:"client_id"`
	UserID    string     `db:"user_id" json:"user_id"`
	Scope     string     `db:"scope" json:"scope"`
	ExpiresAt time.Time  `db:"expires_at" json:"expires_at"`
	Revoked   bool       `db:"revoked" json:"revoked"`
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}

// AccessToken model
type AccessToken struct {
	Token     string     `db:"token" json:"token"`
	ClientID  string     `db:"client_id" json:"client_id"`
	UserID    string     `db:"user_id" json:"user_id,omitempty"`
	Scope     string     `db:"scope" json:"scope"`
	ExpiresAt time.Time  `db:"expires_at" json:"expires_at"`
	Revoked   bool       `db:"revoked" json:"revoked"`
	RevokedAt *time.Time `db:"revoked_at" json:"revoked_at,omitempty"`
	CreatedAt time.Time  `db:"created_at" json:"created_at"`
}
