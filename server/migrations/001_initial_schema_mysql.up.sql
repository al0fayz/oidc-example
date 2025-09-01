-- MySQL compatible schema for OIDC server

-- Users table
CREATE TABLE users (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
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
    birthdate DATE,
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
    INDEX idx_users_created_at (created_at)
);

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
);

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
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

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
);

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
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

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
    INDEX idx_sessions_expires_at (expires_at),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE
);

-- JWKS table
CREATE TABLE jwks (
    kid VARCHAR(255) PRIMARY KEY,
    kty VARCHAR(50) NOT NULL,
    use VARCHAR(50) NOT NULL DEFAULT 'sig',
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
    INDEX idx_jwks_expires_at (expires_at)
);

-- Consent sessions table
CREATE TABLE consent_sessions (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
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
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

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
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- Audit logs table
CREATE TABLE audit_logs (
    id CHAR(36) PRIMARY KEY DEFAULT (UUID()),
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
    FOREIGN KEY (client_id) REFERENCES clients(id) ON DELETE SET NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
);

-- Insert default test client
INSERT INTO clients (id, secret, name, redirect_uris, grant_types, response_types, scope) VALUES
(
    'test-client',
    'test-secret',
    'Test Client',
    '["http://localhost:3000/callback", "http://localhost:3000"]',
    '["authorization_code", "refresh_token", "client_credentials"]',
    '["code"]',
    'openid profile email offline_access'
);