package models

import "time"

// Client model
type Client struct {
	ID                                string      `db:"id" json:"client_id"`
	Secret                            string      `db:"secret" json:"client_secret,omitempty"`
	Name                              string      `db:"name" json:"client_name"`
	Description                       string      `db:"description" json:"description,omitempty"`
	RedirectURIs                      StringArray `db:"redirect_uris" json:"redirect_uris"`
	GrantTypes                        StringArray `db:"grant_types" json:"grant_types"`
	ResponseTypes                     StringArray `db:"response_types" json:"response_types"`
	Scope                             string      `db:"scope" json:"scope"`
	TokenEndpointAuthMethod           string      `db:"token_endpoint_auth_method" json:"token_endpoint_auth_method"`
	AllowedCORSOrigins                StringArray `db:"allowed_cors_origins" json:"allowed_cors_origins,omitempty"`
	LogoURI                           string      `db:"logo_uri" json:"logo_uri,omitempty"`
	ClientURI                         string      `db:"client_uri" json:"client_uri,omitempty"`
	PolicyURI                         string      `db:"policy_uri" json:"policy_uri,omitempty"`
	TosURI                            string      `db:"tos_uri" json:"tos_uri,omitempty"`
	Contacts                          StringArray `db:"contacts" json:"contacts,omitempty"`
	JWKS                              JSONMap     `db:"jwks" json:"jwks,omitempty"`
	JWKSURI                           string      `db:"jwks_uri" json:"jwks_uri,omitempty"`
	SectorIdentifierURI               string      `db:"sector_identifier_uri" json:"sector_identifier_uri,omitempty"`
	SubjectType                       string      `db:"subject_type" json:"subject_type"`
	TokenLifetimes                    JSONMap     `db:"token_lifetimes" json:"token_lifetimes,omitempty"`
	BackchannelLogoutURI              string      `db:"backchannel_logout_uri" json:"backchannel_logout_uri,omitempty"`
	BackchannelLogoutSessionRequired  bool        `db:"backchannel_logout_session_required" json:"backchannel_logout_session_required"`
	FrontchannelLogoutURI             string      `db:"frontchannel_logout_uri" json:"frontchannel_logout_uri,omitempty"`
	FrontchannelLogoutSessionRequired bool        `db:"frontchannel_logout_session_required" json:"frontchannel_logout_session_required"`
	PostLogoutRedirectURIs            StringArray `db:"post_logout_redirect_uris" json:"post_logout_redirect_uris,omitempty"`
	RequireAuthTime                   bool        `db:"require_auth_time" json:"require_auth_time"`
	DefaultMaxAge                     int         `db:"default_max_age" json:"default_max_age,omitempty"`
	RequireSignedRequestObject        bool        `db:"require_signed_request_object" json:"require_signed_request_object"`
	UserinfoSignedResponseAlg         string      `db:"userinfo_signed_response_alg" json:"userinfo_signed_response_alg,omitempty"`
	IDTokenSignedResponseAlg          string      `db:"id_token_signed_response_alg" json:"id_token_signed_response_alg"`
	IDTokenEncryptedResponseAlg       string      `db:"id_token_encrypted_response_alg" json:"id_token_encrypted_response_alg,omitempty"`
	IDTokenEncryptedResponseEnc       string      `db:"id_token_encrypted_response_enc" json:"id_token_encrypted_response_enc,omitempty"`
	RequestURIs                       StringArray `db:"request_uris" json:"request_uris,omitempty"`
	SoftwareID                        string      `db:"software_id" json:"software_id,omitempty"`
	SoftwareVersion                   string      `db:"software_version" json:"software_version,omitempty"`
	Metadata                          JSONMap     `db:"metadata" json:"metadata,omitempty"`
	CreatedAt                         time.Time   `db:"created_at" json:"created_at"`
	UpdatedAt                         time.Time   `db:"updated_at" json:"updated_at"`
}
