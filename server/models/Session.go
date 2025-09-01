package models

import "time"

// Session model
type Session struct {
	Token     string    `db:"token" json:"token"`
	UserID    string    `db:"user_id" json:"user_id"`
	ClientID  string    `db:"client_id" json:"client_id,omitempty"`
	UserAgent string    `db:"user_agent" json:"user_agent,omitempty"`
	IPAddress string    `db:"ip_address" json:"ip_address,omitempty"`
	ExpiresAt time.Time `db:"expires_at" json:"expires_at"`
	CreatedAt time.Time `db:"created_at" json:"created_at"`
}

// ConsentSession model
type ConsentSession struct {
	ID               string     `db:"id" json:"id"`
	ClientID         string     `db:"client_id" json:"client_id"`
	UserID           string     `db:"user_id" json:"user_id"`
	Scope            string     `db:"scope" json:"scope"`
	GrantedScope     string     `db:"granted_scope" json:"granted_scope,omitempty"`
	AccessTokenExtra JSONMap    `db:"access_token_extra" json:"access_token_extra,omitempty"`
	IDTokenExtra     JSONMap    `db:"id_token_extra" json:"id_token_extra,omitempty"`
	Rejected         bool       `db:"rejected" json:"rejected"`
	RejectedReason   string     `db:"rejected_reason" json:"rejected_reason,omitempty"`
	ExpiresAt        time.Time  `db:"expires_at" json:"expires_at"`
	ChallengedAt     *time.Time `db:"challenged_at" json:"challenged_at,omitempty"`
	GrantedAt        *time.Time `db:"granted_at" json:"granted_at,omitempty"`
	CreatedAt        time.Time  `db:"created_at" json:"created_at"`
}
