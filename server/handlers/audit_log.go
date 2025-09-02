package handlers

import (
	"context"
	"fmt"
	"net/http"
	"oidc-example/server/models"
	"oidc-example/server/repository"
	"oidc-example/server/storage"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
)

type AuditLogHandler struct {
	store storage.Storage
}

func NewAuditLogHandler(store storage.Storage) *AuditLogHandler {
	return &AuditLogHandler{store: store}
}

// GetAuditLogs retrieves audit logs with filtering and pagination
func (h *AuditLogHandler) GetAuditLogs(c *gin.Context) {
	// Parse query parameters
	eventType := c.Query("event_type")
	clientID := c.Query("client_id")
	userID := c.Query("user_id")
	ipAddress := c.Query("ip_address")
	withErrors := c.Query("with_errors") == "true"

	// Parse date filters
	var startTime, endTime time.Time
	if startStr := c.Query("start_time"); startStr != "" {
		if t, err := time.Parse(time.RFC3339, startStr); err == nil {
			startTime = t
		}
	}
	if endStr := c.Query("end_time"); endStr != "" {
		if t, err := time.Parse(time.RFC3339, endStr); err == nil {
			endTime = t
		}
	}

	// Parse pagination
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))

	if limit > 1000 {
		limit = 1000
	}
	if limit < 1 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	filter := repository.AuditLogFilter{
		EventType:  eventType,
		ClientID:   clientID,
		UserID:     userID,
		IPAddress:  ipAddress,
		StartTime:  startTime,
		EndTime:    endTime,
		WithErrors: withErrors,
	}

	logs, err := h.store.GetAuditLogs(c.Request.Context(), filter, limit, offset)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to retrieve audit logs",
		})
		return
	}

	count, err := h.store.CountAuditLogs(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to count audit logs",
		})
		return
	}

	// Convert to response format
	response := make([]map[string]interface{}, 0, len(logs))
	for _, log := range logs {
		response = append(response, h.auditLogToMap(log))
	}

	c.JSON(http.StatusOK, gin.H{
		"logs":     response,
		"total":    count,
		"limit":    limit,
		"offset":   offset,
		"has_more": count > int64(offset+limit),
	})
}

// GetAuditLog retrieves a specific audit log by ID
func (h *AuditLogHandler) GetAuditLog(c *gin.Context) {
	id := c.Param("id")

	// For simplicity, we'll get all logs and filter by ID
	// In production, you'd want a specific GetAuditLog method in storage
	filter := repository.AuditLogFilter{}
	logs, err := h.store.GetAuditLogs(c.Request.Context(), filter, 1000, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to retrieve audit logs",
		})
		return
	}

	for _, log := range logs {
		if log.ID == id {
			c.JSON(http.StatusOK, h.auditLogToMap(log))
			return
		}
	}

	c.JSON(http.StatusNotFound, gin.H{
		"error":   "not_found",
		"message": "Audit log not found",
	})
}

// CreateAuditLog creates a new audit log entry
func (h *AuditLogHandler) CreateAuditLog(c *gin.Context) {
	var req struct {
		EventType    string                 `json:"event_type" binding:"required"`
		EventSubtype string                 `json:"event_subtype"`
		ClientID     string                 `json:"client_id"`
		UserID       string                 `json:"user_id"`
		IPAddress    string                 `json:"ip_address"`
		UserAgent    string                 `json:"user_agent"`
		Error        string                 `json:"error"`
		Metadata     map[string]interface{} `json:"metadata"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"error":   "invalid_request",
			"message": err.Error(),
		})
		return
	}

	auditLog := &models.AuditLog{
		ID:           generateID(),
		EventType:    req.EventType,
		EventSubtype: req.EventSubtype,
		ClientID:     req.ClientID,
		UserID:       req.UserID,
		IPAddress:    req.IPAddress,
		UserAgent:    req.UserAgent,
		Error:        req.Error,
		Metadata:     req.Metadata,
		CreatedAt:    time.Now(),
	}

	if err := h.store.CreateAuditLog(c.Request.Context(), auditLog); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to create audit log",
		})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"message":   "Audit log created successfully",
		"audit_log": h.auditLogToMap(auditLog),
	})
}

// GetAuditStats returns statistics about audit logs
func (h *AuditLogHandler) GetAuditStats(c *gin.Context) {
	// Get time range from query params
	days, _ := strconv.Atoi(c.DefaultQuery("days", "7"))
	if days > 365 {
		days = 365
	}
	if days < 1 {
		days = 7
	}

	startTime := time.Now().AddDate(0, 0, -days)
	endTime := time.Now()

	// Get logs for the time period
	filter := repository.AuditLogFilter{
		StartTime: startTime,
		EndTime:   endTime,
	}

	logs, err := h.store.GetAuditLogs(c.Request.Context(), filter, 10000, 0)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"error":   "internal_server_error",
			"message": "Failed to retrieve audit logs",
		})
		return
	}

	// Calculate statistics
	stats := h.calculateStats(logs, startTime, endTime)

	c.JSON(http.StatusOK, gin.H{
		"period": gin.H{
			"start_time": startTime,
			"end_time":   endTime,
			"days":       days,
		},
		"stats": stats,
	})
}

// Helper methods
func (h *AuditLogHandler) auditLogToMap(log *models.AuditLog) map[string]interface{} {
	return map[string]interface{}{
		"id":            log.ID,
		"event_type":    log.EventType,
		"event_subtype": log.EventSubtype,
		"client_id":     log.ClientID,
		"user_id":       log.UserID,
		"ip_address":    log.IPAddress,
		"user_agent":    log.UserAgent,
		"error":         log.Error,
		"metadata":      log.Metadata,
		"created_at":    log.CreatedAt,
	}
}

func (h *AuditLogHandler) calculateStats(logs []*models.AuditLog, startTime, endTime time.Time) map[string]interface{} {
	stats := map[string]interface{}{
		"total_events":     len(logs),
		"error_count":      0,
		"events_by_type":   make(map[string]int),
		"events_by_client": make(map[string]int),
		"events_by_user":   make(map[string]int),
		"events_by_day":    make(map[string]int),
	}

	for _, log := range logs {
		// Count errors
		if log.Error != "" {
			stats["error_count"] = stats["error_count"].(int) + 1
		}

		// Count by event type
		stats["events_by_type"].(map[string]int)[log.EventType]++

		// Count by client
		if log.ClientID != "" {
			stats["events_by_client"].(map[string]int)[log.ClientID]++
		}

		// Count by user
		if log.UserID != "" {
			stats["events_by_user"].(map[string]int)[log.UserID]++
		}

		// Count by day
		day := log.CreatedAt.Format("2006-01-02")
		stats["events_by_day"].(map[string]int)[day]++
	}

	return stats
}

// LogEvent is a helper method to log events from other handlers
func (h *AuditLogHandler) LogEvent(ctx context.Context, eventType, eventSubtype, clientID, userID, ipAddress, userAgent, errorMsg string, metadata map[string]interface{}) {
	auditLog := &models.AuditLog{
		ID:           generateID(),
		EventType:    eventType,
		EventSubtype: eventSubtype,
		ClientID:     clientID,
		UserID:       userID,
		IPAddress:    ipAddress,
		UserAgent:    userAgent,
		Error:        errorMsg,
		Metadata:     metadata,
		CreatedAt:    time.Now(),
	}

	// Use background context to avoid request cancellation
	go func() {
		ctx := context.Background()
		if err := h.store.CreateAuditLog(ctx, auditLog); err != nil {
			fmt.Printf("Failed to create audit log: %v\n", err)
		}
	}()
}
