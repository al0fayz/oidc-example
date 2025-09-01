package models

import "time"

// AuditLog model
type AuditLog struct {
	ID           string    `db:"id" json:"id"`
	EventType    string    `db:"event_type" json:"event_type"`
	EventSubtype string    `db:"event_subtype" json:"event_subtype,omitempty"`
	ClientID     string    `db:"client_id" json:"client_id,omitempty"`
	UserID       string    `db:"user_id" json:"user_id,omitempty"`
	IPAddress    string    `db:"ip_address" json:"ip_address,omitempty"`
	UserAgent    string    `db:"user_agent" json:"user_agent,omitempty"`
	Error        string    `db:"error" json:"error,omitempty"`
	Metadata     JSONMap   `db:"metadata" json:"metadata,omitempty"`
	CreatedAt    time.Time `db:"created_at" json:"created_at"`
}
