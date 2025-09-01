package models

import "time"

// DeviceCode model
type DeviceCode struct {
	DeviceCode string    `db:"device_code" json:"device_code"`
	UserCode   string    `db:"user_code" json:"user_code"`
	ClientID   string    `db:"client_id" json:"client_id"`
	UserID     string    `db:"user_id" json:"user_id,omitempty"`
	Scope      string    `db:"scope" json:"scope"`
	ExpiresAt  time.Time `db:"expires_at" json:"expires_at"`
	Approved   bool      `db:"approved" json:"approved"`
	Denied     bool      `db:"denied" json:"denied"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
}
