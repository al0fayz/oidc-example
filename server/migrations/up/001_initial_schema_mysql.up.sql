-- MySQL compatible schema for OIDC server
-- Enable strict mode for better data integrity
SET sql_mode = 'ONLY_FULL_GROUP_BY,STRICT_TRANS_TABLES,NO_ZERO_IN_DATE,NO_ZERO_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION';

-- Create database
CREATE DATABASE IF NOT EXISTS oidc CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE oidc;

-- Users table
CREATE TABLE users (
    id CHAR(36) PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    password_hash TEXT NOT NULL,
    name VARCHAR(255),
    given_name VARCHAR(255),
    family_name VARCHAR(255),
    middle_name VARCHAR(255),
    nickname VARCHAR(255),
    profile TEXT,
    picture TEXT,
    website TEXT,
    gender VARCHAR(50),
    birthdate DATE NULL,
    zoneinfo VARCHAR(100),
    locale VARCHAR(10),
    phone_number VARCHAR(50),
    phone_number_verified BOOLEAN DEFAULT FALSE,
    address JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    last_ip VARCHAR(45),
    login_count INT DEFAULT 0,
    blocked BOOLEAN DEFAULT FALSE,
    mfa_enabled BOOLEAN DEFAULT FALSE,
    mfa_secret TEXT,
    recovery_codes JSON,
    metadata JSON,
    INDEX idx_users_email (email),
    INDEX idx_users_username (username),
    INDEX idx_users_created_at (created_at),
    INDEX idx_users_blocked (blocked)
) ENGINE=InnoDB;

-- Clients table
CREATE TABLE clients (
    id VARCHAR(255) PRIMARY KEY,
    secret TEXT NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    redirect_uris JSON NOT NULL,
    grant_types JSON NOT NULL,
    response_types JSON NOT NULL,
    scope TEXT NOT NULL,
    token_endpoint_auth_method VARCHAR(50) DEFAULT 'client_secret_basic',
    allowed_cors_origins JSON,
    logo_uri TEXT,
    client_uri TEXT,
    policy_uri TEXT,
    tos_uri TEXT,
    contacts JSON,
    jwks JSON,
    jwks_uri TEXT,
    sector_identifier_uri TEXT,
    subject_type VARCHAR(50) DEFAULT 'public',
    token_lifetimes JSON,
    backchannel_logout_uri TEXT,
    backchannel_logout_session_required BOOLEAN DEFAULT FALSE,
    frontchannel_logout_uri TEXT,
    frontchannel_logout_session_required BOOLEAN DEFAULT FALSE,
    post_logout_redirect_uris JSON,
    require_auth_time BOOLEAN DEFAULT FALSE,
    default_max_age INT,
    require_signed_request_object BOOLEAN DEFAULT FALSE,
    userinfo_signed_response_alg VARCHAR(50),
    id_token_signed_response_alg VARCHAR(50) DEFAULT 'RS256',
    id_token_encrypted_response_alg VARCHAR(50),
    id_token_encrypted_response_enc VARCHAR(50),
    request_uris JSON,
    software_id VARCHAR(255),
    software_version VARCHAR(255),
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    INDEX idx_clients_created_at (created_at)
) ENGINE=InnoDB;

-- Authorization codes table
CREATE TABLE authorization_codes (
    code VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    user_id CHAR(36) NOT NULL,
    nonce TEXT,
    code_challenge TEXT,
    code_challenge_method VARCHAR(50),
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_auth_codes_client_id (client_id),
    INDEX idx_auth_codes_user_id (user_id),
    INDEX idx_auth_codes_expires_at (expires_at),
    INDEX idx_auth_codes_used (used),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Refresh tokens table
CREATE TABLE refresh_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id CHAR(36) NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_refresh_tokens_client_id (client_id),
    INDEX idx_refresh_tokens_user_id (user_id),
    INDEX idx_refresh_tokens_expires_at (expires_at),
    INDEX idx_refresh_tokens_revoked (revoked),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Access tokens table
CREATE TABLE access_tokens (
    token VARCHAR(255) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id CHAR(36),
    scope TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    revoked BOOLEAN DEFAULT FALSE,
    revoked_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_access_tokens_client_id (client_id),
    INDEX idx_access_tokens_user_id (user_id),
    INDEX idx_access_tokens_expires_at (expires_at),
    INDEX idx_access_tokens_revoked (revoked),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Sessions table
CREATE TABLE sessions (
    token VARCHAR(255) PRIMARY KEY,
    user_id CHAR(36) NOT NULL,
    client_id VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_sessions_user_id (user_id),
    INDEX idx_sessions_client_id (client_id),
    INDEX idx_sessions_expires_at (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- JWKS table
CREATE TABLE jwks (
    kid VARCHAR(255) PRIMARY KEY,
    kty VARCHAR(50) NOT NULL,
    key_use VARCHAR(50) NOT NULL DEFAULT 'sig',
    alg VARCHAR(50) NOT NULL DEFAULT 'RS256',
    n TEXT NOT NULL,
    e TEXT NOT NULL,
    d TEXT,
    p TEXT,
    q TEXT,
    dp TEXT,
    dq TEXT,
    qi TEXT,
    operations JSON,
    expires_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    rotated_at TIMESTAMP NULL,
    INDEX idx_jwks_expires_at (expires_at),
    INDEX idx_jwks_key_use (key_use),
    INDEX idx_jwks_alg (alg)
) ENGINE=InnoDB;

-- Consent sessions table
CREATE TABLE consent_sessions (
    id CHAR(36) PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    user_id CHAR(36) NOT NULL,
    scope TEXT NOT NULL,
    granted_scope TEXT,
    access_token_extra JSON,
    id_token_extra JSON,
    rejected BOOLEAN DEFAULT FALSE,
    rejected_reason TEXT,
    expires_at TIMESTAMP NOT NULL,
    challenged_at TIMESTAMP NULL,
    granted_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_consent_sessions_client_id (client_id),
    INDEX idx_consent_sessions_user_id (user_id),
    INDEX idx_consent_sessions_expires_at (expires_at),
    INDEX idx_consent_sessions_rejected (rejected),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Device codes table
CREATE TABLE device_codes (
    device_code VARCHAR(255) PRIMARY KEY,
    user_code VARCHAR(255) UNIQUE NOT NULL,
    client_id VARCHAR(255) NOT NULL,
    user_id CHAR(36),
    scope TEXT NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    approved BOOLEAN DEFAULT FALSE,
    denied BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_device_codes_user_code (user_code),
    INDEX idx_device_codes_client_id (client_id),
    INDEX idx_device_codes_expires_at (expires_at),
    INDEX idx_device_codes_approved (approved),
    INDEX idx_device_codes_denied (denied),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
) ENGINE=InnoDB;

-- Audit logs table
CREATE TABLE audit_logs (
    id CHAR(36) PRIMARY KEY,
    event_type VARCHAR(100) NOT NULL,
    event_subtype VARCHAR(100),
    client_id VARCHAR(255),
    user_id CHAR(36),
    ip_address VARCHAR(45),
    user_agent TEXT,
    error TEXT,
    metadata JSON,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_audit_logs_event_type (event_type),
    INDEX idx_audit_logs_client_id (client_id),
    INDEX idx_audit_logs_user_id (user_id),
    INDEX idx_audit_logs_created_at (created_at),
    INDEX idx_audit_logs_ip_address (ip_address),
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
) ENGINE=InnoDB;

-- Insert default test client
INSERT INTO clients (
    id, secret, name, description, 
    redirect_uris, grant_types, response_types, scope,
    token_endpoint_auth_method
) VALUES (
    'test-client',
    'test-secret',
    'Test Client',
    'Test client for development',
    '["http://localhost:3000/callback", "http://localhost:3000/auth/callback"]',
    '["authorization_code", "refresh_token", "client_credentials"]',
    '["code"]',
    'openid profile email offline_access',
    'client_secret_basic'
);

-- Insert test user (password: "password123")
INSERT INTO users (
    id, username, email, email_verified, password_hash, name,
    created_at, updated_at
) VALUES (
    '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
    'testuser',
    'test@example.com',
    TRUE,
    '$2a$10$92IXUNpkjO0rOQ5byMi.Ye4oKoEa3Ro9llC/.og/at2.uheWG/igi', -- password123
    'Test User',
    NOW(),
    NOW()
);

-- Insert test RSA key for JWKS
INSERT INTO jwks (
    kid, kty, key_use, alg, n, e, created_at
) VALUES (
    '1',
    'RSA',
    'sig',
    'RS256',
    'qFZ9...long_rsa_modulus...', -- This should be a real RSA modulus
    'AQAB',
    NOW()
);

-- Create procedures for cleanup
DELIMITER //

CREATE PROCEDURE CleanupExpiredData()
BEGIN
    -- Cleanup expired authorization codes
    DELETE FROM authorization_codes WHERE expires_at <= NOW() OR used = TRUE;
    
    -- Cleanup expired access tokens
    DELETE FROM access_tokens WHERE expires_at <= NOW() OR revoked = TRUE;
    
    -- Cleanup expired refresh tokens
    DELETE FROM refresh_tokens WHERE expires_at <= NOW() OR revoked = TRUE;
    
    -- Cleanup expired sessions
    DELETE FROM sessions WHERE expires_at <= NOW();
    
    -- Cleanup expired device codes
    DELETE FROM device_codes WHERE expires_at <= NOW() OR approved = TRUE OR denied = TRUE;
    
    -- Cleanup expired consent sessions
    DELETE FROM consent_sessions WHERE expires_at <= NOW() OR rejected = TRUE;
    
    -- Cleanup expired JWKS (optional)
    DELETE FROM jwks WHERE expires_at IS NOT NULL AND expires_at <= NOW();
END//

DELIMITER ;

-- Create events for automatic cleanup
SET GLOBAL event_scheduler = ON;

CREATE EVENT IF NOT EXISTS CleanupExpiredDataEvent
ON SCHEDULE EVERY 1 HOUR
DO
    CALL CleanupExpiredData();

-- Create views for easier querying
CREATE VIEW active_sessions AS
SELECT * FROM sessions WHERE expires_at > NOW();

CREATE VIEW valid_tokens AS
SELECT 
    'access' as token_type,
    token,
    client_id,
    user_id,
    scope,
    expires_at
FROM access_tokens 
WHERE expires_at > NOW() AND revoked = FALSE
UNION ALL
SELECT 
    'refresh' as token_type,
    token,
    client_id,
    user_id,
    scope,
    expires_at
FROM refresh_tokens 
WHERE expires_at > NOW() AND revoked = FALSE;

CREATE VIEW user_clients AS
SELECT 
    u.id as user_id,
    u.username,
    u.email,
    c.id as client_id,
    c.name as client_name,
    cs.granted_scope,
    cs.created_at as consent_given_at
FROM users u
JOIN consent_sessions cs ON u.id = cs.user_id
JOIN clients c ON cs.client_id = c.id
WHERE cs.rejected = FALSE AND cs.expires_at > NOW();

-- Insert sample audit log
INSERT INTO audit_logs (
    id, event_type, event_subtype, client_id, user_id,
    ip_address, user_agent, created_at
) VALUES (
    UUID(),
    'user_login',
    'success',
    'test-client',
    '6ba7b810-9dad-11d1-80b4-00c04fd430c8',
    '127.0.0.1',
    'Mozilla/5.0 (Test Browser)',
    NOW()
);