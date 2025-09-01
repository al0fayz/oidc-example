package mysql

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/jmoiron/sqlx"

	"oidc-example/server/models"
	"oidc-example/server/repository"
	"oidc-example/server/utils"
)

type ClientRepository struct {
	db *sqlx.DB
}

func NewClientRepository(db *sqlx.DB) repository.ClientRepository {
	return &ClientRepository{db: db}
}

func (r *ClientRepository) Create(ctx context.Context, client *models.Client) error {
	// Convert slices and maps to JSON
	redirectURIsJSON, err := utils.MarshalStringArray(client.RedirectURIs)
	if err != nil {
		return err
	}

	grantTypesJSON, err := utils.MarshalStringArray(client.GrantTypes)
	if err != nil {
		return err
	}

	responseTypesJSON, err := utils.MarshalStringArray(client.ResponseTypes)
	if err != nil {
		return err
	}

	allowedCORSOriginsJSON, err := utils.MarshalStringArray(client.AllowedCORSOrigins)
	if err != nil {
		return err
	}

	contactsJSON, err := utils.MarshalStringArray(client.Contacts)
	if err != nil {
		return err
	}

	jwksJSON, err := utils.MarshalJSON(client.JWKS)
	if err != nil {
		return err
	}

	tokenLifetimesJSON, err := utils.MarshalJSON(client.TokenLifetimes)
	if err != nil {
		return err
	}

	postLogoutRedirectURIsJSON, err := utils.MarshalStringArray(client.PostLogoutRedirectURIs)
	if err != nil {
		return err
	}

	requestURIsJSON, err := utils.MarshalStringArray(client.RequestURIs)
	if err != nil {
		return err
	}

	metadataJSON, err := utils.MarshalJSON(client.Metadata)
	if err != nil {
		return err
	}

	query := `
		INSERT INTO clients (id, secret, name, description, redirect_uris, grant_types, 
			response_types, scope, token_endpoint_auth_method, allowed_cors_origins, 
			logo_uri, client_uri, policy_uri, tos_uri, contacts, jwks, jwks_uri, 
			sector_identifier_uri, subject_type, token_lifetimes, 
			backchannel_logout_uri, backchannel_logout_session_required, 
			frontchannel_logout_uri, frontchannel_logout_session_required, 
			post_logout_redirect_uris, require_auth_time, default_max_age, 
			require_signed_request_object, userinfo_signed_response_alg, 
			id_token_signed_response_alg, id_token_encrypted_response_alg, 
			id_token_encrypted_response_enc, request_uris, software_id, software_version, 
			metadata, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 
		        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW(), NOW())
	`

	_, err = r.db.ExecContext(ctx, query,
		client.ID, client.Secret, client.Name, client.Description, redirectURIsJSON, grantTypesJSON,
		responseTypesJSON, client.Scope, client.TokenEndpointAuthMethod, allowedCORSOriginsJSON,
		client.LogoURI, client.ClientURI, client.PolicyURI, client.TosURI, contactsJSON, jwksJSON, client.JWKSURI,
		client.SectorIdentifierURI, client.SubjectType, tokenLifetimesJSON,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired,
		client.FrontchannelLogoutURI, client.FrontchannelLogoutSessionRequired,
		postLogoutRedirectURIsJSON, client.RequireAuthTime, client.DefaultMaxAge,
		client.RequireSignedRequestObject, client.UserinfoSignedResponseAlg,
		client.IDTokenSignedResponseAlg, client.IDTokenEncryptedResponseAlg,
		client.IDTokenEncryptedResponseEnc, requestURIsJSON, client.SoftwareID, client.SoftwareVersion,
		metadataJSON,
	)

	return err
}

func (r *ClientRepository) FindByID(ctx context.Context, id string) (*models.Client, error) {
	query := `SELECT * FROM clients WHERE id = ?`
	var client models.Client
	err := r.db.GetContext(ctx, &client, query, id)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &client, nil
}

func (r *ClientRepository) FindByCredentials(ctx context.Context, clientID, clientSecret string) (*models.Client, error) {
	query := `SELECT * FROM clients WHERE id = ? AND secret = ?`
	var client models.Client
	err := r.db.GetContext(ctx, &client, query, clientID, clientSecret)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, utils.ErrNotFound
		}
		return nil, err
	}
	return &client, nil
}

func (r *ClientRepository) ValidateRedirectURI(ctx context.Context, clientID, redirectURI string) (bool, error) {
	query := `SELECT redirect_uris FROM clients WHERE id = ?`
	var redirectURIsJSON string
	err := r.db.GetContext(ctx, &redirectURIsJSON, query, clientID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, utils.ErrNotFound
		}
		return false, err
	}

	var redirectURIs []string
	if err := json.Unmarshal([]byte(redirectURIsJSON), &redirectURIs); err != nil {
		return false, err
	}

	for _, uri := range redirectURIs {
		if uri == redirectURI {
			return true, nil
		}
	}

	return false, nil
}

func (r *ClientRepository) List(ctx context.Context, limit, offset int) ([]*models.Client, error) {
	query := `SELECT * FROM clients ORDER BY created_at DESC LIMIT ? OFFSET ?`
	var clients []*models.Client
	err := r.db.SelectContext(ctx, &clients, query, limit, offset)
	return clients, err
}

func (r *ClientRepository) Update(ctx context.Context, client *models.Client) error {
	redirectURIsJSON, err := utils.MarshalStringArray(client.RedirectURIs)
	if err != nil {
		return err
	}

	grantTypesJSON, err := utils.MarshalStringArray(client.GrantTypes)
	if err != nil {
		return err
	}

	responseTypesJSON, err := utils.MarshalStringArray(client.ResponseTypes)
	if err != nil {
		return err
	}

	allowedCORSOriginsJSON, err := utils.MarshalStringArray(client.AllowedCORSOrigins)
	if err != nil {
		return err
	}

	contactsJSON, err := utils.MarshalStringArray(client.Contacts)
	if err != nil {
		return err
	}

	jwksJSON, err := utils.MarshalJSON(client.JWKS)
	if err != nil {
		return err
	}

	tokenLifetimesJSON, err := utils.MarshalJSON(client.TokenLifetimes)
	if err != nil {
		return err
	}

	postLogoutRedirectURIsJSON, err := utils.MarshalStringArray(client.PostLogoutRedirectURIs)
	if err != nil {
		return err
	}

	requestURIsJSON, err := utils.MarshalStringArray(client.RequestURIs)
	if err != nil {
		return err
	}

	metadataJSON, err := utils.MarshalJSON(client.Metadata)
	if err != nil {
		return err
	}

	query := `
		UPDATE clients SET 
			secret = ?, name = ?, description = ?, redirect_uris = ?, grant_types = ?,
			response_types = ?, scope = ?, token_endpoint_auth_method = ?, allowed_cors_origins = ?,
			logo_uri = ?, client_uri = ?, policy_uri = ?, tos_uri = ?, contacts = ?, jwks = ?,
			jwks_uri = ?, sector_identifier_uri = ?, subject_type = ?, token_lifetimes = ?,
			backchannel_logout_uri = ?, backchannel_logout_session_required = ?,
			frontchannel_logout_uri = ?, frontchannel_logout_session_required = ?,
			post_logout_redirect_uris = ?, require_auth_time = ?, default_max_age = ?,
			require_signed_request_object = ?, userinfo_signed_response_alg = ?,
			id_token_signed_response_alg = ?, id_token_encrypted_response_alg = ?,
			id_token_encrypted_response_enc = ?, request_uris = ?, software_id = ?,
			software_version = ?, metadata = ?, updated_at = NOW()
		WHERE id = ?
	`

	_, err = r.db.ExecContext(ctx, query,
		client.Secret, client.Name, client.Description, redirectURIsJSON, grantTypesJSON,
		responseTypesJSON, client.Scope, client.TokenEndpointAuthMethod, allowedCORSOriginsJSON,
		client.LogoURI, client.ClientURI, client.PolicyURI, client.TosURI, contactsJSON, jwksJSON,
		client.JWKSURI, client.SectorIdentifierURI, client.SubjectType, tokenLifetimesJSON,
		client.BackchannelLogoutURI, client.BackchannelLogoutSessionRequired,
		client.FrontchannelLogoutURI, client.FrontchannelLogoutSessionRequired,
		postLogoutRedirectURIsJSON, client.RequireAuthTime, client.DefaultMaxAge,
		client.RequireSignedRequestObject, client.UserinfoSignedResponseAlg,
		client.IDTokenSignedResponseAlg, client.IDTokenEncryptedResponseAlg,
		client.IDTokenEncryptedResponseEnc, requestURIsJSON, client.SoftwareID, client.SoftwareVersion,
		metadataJSON, client.ID,
	)

	return err
}

func (r *ClientRepository) Delete(ctx context.Context, id string) error {
	query := `DELETE FROM clients WHERE id = ?`
	_, err := r.db.ExecContext(ctx, query, id)
	return err
}

func (r *ClientRepository) Count(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM clients`
	var count int64
	err := r.db.GetContext(ctx, &count, query)
	return count, err
}
