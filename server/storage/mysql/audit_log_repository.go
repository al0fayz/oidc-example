package mysql

import (
	"context"
	"encoding/json"
	"oidc-example/server/models"
	"oidc-example/server/repository"

	"github.com/jmoiron/sqlx"
)

type AuditLogRepository struct {
	db *sqlx.DB
}

func NewAuditLogRepository(db *sqlx.DB) repository.AuditLogRepository {
	return &AuditLogRepository{db: db}
}

func (r *AuditLogRepository) Create(ctx context.Context, log *models.AuditLog) error {
	metadataJSON, err := json.Marshal(log.Metadata)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO audit_logs (id, event_type, event_subtype, client_id, user_id, 
			ip_address, user_agent, error, metadata, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, NOW())
	`

	_, err = r.db.ExecContext(ctx, query,
		log.ID,
		log.EventType,
		log.EventSubtype,
		log.ClientID,
		log.UserID,
		log.IPAddress,
		log.UserAgent,
		log.Error,
		metadataJSON,
	)

	return err
}

func (r *AuditLogRepository) Find(ctx context.Context, filter repository.AuditLogFilter, limit, offset int) ([]*models.AuditLog, error) {
	query := `SELECT * FROM audit_logs WHERE 1=1`
	args := []interface{}{}

	if filter.EventType != "" {
		query += " AND event_type = ?"
		args = append(args, filter.EventType)
	}
	if filter.ClientID != "" {
		query += " AND client_id = ?"
		args = append(args, filter.ClientID)
	}
	if filter.UserID != "" {
		query += " AND user_id = ?"
		args = append(args, filter.UserID)
	}
	if filter.IPAddress != "" {
		query += " AND ip_address = ?"
		args = append(args, filter.IPAddress)
	}
	if !filter.StartTime.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		query += " AND created_at <= ?"
		args = append(args, filter.EndTime)
	}
	if filter.WithErrors {
		query += " AND error IS NOT NULL"
	}

	query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
	args = append(args, limit, offset)

	var logs []*models.AuditLog
	err := r.db.SelectContext(ctx, &logs, query, args...)
	if err != nil {
		return nil, err
	}

	return logs, nil
}

func (r *AuditLogRepository) Count(ctx context.Context, filter repository.AuditLogFilter) (int64, error) {
	query := `SELECT COUNT(*) FROM audit_logs WHERE 1=1`
	args := []interface{}{}

	if filter.EventType != "" {
		query += " AND event_type = ?"
		args = append(args, filter.EventType)
	}
	if filter.ClientID != "" {
		query += " AND client_id = ?"
		args = append(args, filter.ClientID)
	}
	if filter.UserID != "" {
		query += " AND user_id = ?"
		args = append(args, filter.UserID)
	}
	if filter.IPAddress != "" {
		query += " AND ip_address = ?"
		args = append(args, filter.IPAddress)
	}
	if !filter.StartTime.IsZero() {
		query += " AND created_at >= ?"
		args = append(args, filter.StartTime)
	}
	if !filter.EndTime.IsZero() {
		query += " AND created_at <= ?"
		args = append(args, filter.EndTime)
	}
	if filter.WithErrors {
		query += " AND error IS NOT NULL"
	}

	var count int64
	err := r.db.GetContext(ctx, &count, query, args...)
	return count, err
}
