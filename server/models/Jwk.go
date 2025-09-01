package models

import "time"

// JWK model
type JWK struct {
	KID        string      `db:"kid" json:"kid"`
	Kty        string      `db:"kty" json:"kty"`
	Use        string      `db:"use" json:"use"`
	Alg        string      `db:"alg" json:"alg"`
	N          string      `db:"n" json:"n"`
	E          string      `db:"e" json:"e"`
	D          string      `db:"d" json:"d,omitempty"`
	P          string      `db:"p" json:"p,omitempty"`
	Q          string      `db:"q" json:"q,omitempty"`
	Dp         string      `db:"dp" json:"dp,omitempty"`
	Dq         string      `db:"dq" json:"dq,omitempty"`
	Qi         string      `db:"qi" json:"qi,omitempty"`
	Operations StringArray `db:"operations" json:"operations,omitempty"`
	ExpiresAt  *time.Time  `db:"expires_at" json:"expires_at,omitempty"`
	CreatedAt  time.Time   `db:"created_at" json:"created_at"`
	RotatedAt  *time.Time  `db:"rotated_at" json:"rotated_at,omitempty"`
}
