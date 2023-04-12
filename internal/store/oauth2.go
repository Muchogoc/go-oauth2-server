package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ory/fosite"
	"gorm.io/gorm/clause"
)

// CreateAuthorizeCodeSession stores the authorization request for a given authorization code.
func (m Store) CreateAuthorizeCodeSession(ctx context.Context, code string, request fosite.Requester) (err error) {
	client := request.GetClient()

	form, err := json.Marshal(request.GetRequestForm())
	if err != nil {
		return fmt.Errorf("error marshalling authorization code form: %w", err)
	}

	session := request.GetSession().(*Session)
	if err = m.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "id"},
			},
			UpdateAll: true,
		},
	).Create(&session).Error; err != nil {
		return fmt.Errorf("error creating authorization code session: %w", err)
	}

	data := AuthorizationCode{
		ID:                request.GetID(),
		Active:            true,
		Code:              code,
		RequestedAt:       request.GetRequestedAt(),
		ClientID:          client.GetID(),
		RequestedScopes:   StringArray(request.GetRequestedScopes()),
		GrantedScopes:     StringArray(request.GetGrantedScopes()),
		Form:              form,
		SessionID:         session.ID,
		RequestedAudience: StringArray(request.GetRequestedAudience()),
		GrantedAudience:   StringArray(request.GetGrantedAudience()),
	}

	if err = m.db.Create(&data).Error; err != nil {
		return fmt.Errorf("error creating authorization code: %w", err)
	}

	return nil
}

// GetAuthorizeCodeSession hydrates the session based on the given code and returns the authorization request.
// If the authorization code has been invalidated with `InvalidateAuthorizeCodeSession`, this
// method should return the ErrInvalidatedAuthorizeCode error.
//
// Make sure to also return the fosite.Requester value when returning the fosite.ErrInvalidatedAuthorizeCode error!
func (m Store) GetAuthorizeCodeSession(ctx context.Context, code string, session fosite.Session) (request fosite.Requester, err error) {
	var result AuthorizationCode

	if err := m.db.Preload("Session.User").Preload(clause.Associations).Where(AuthorizationCode{Code: code}).First(&result).Error; err != nil {
		return nil, fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	var form url.Values
	err = json.Unmarshal(result.Form, &form)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling authorization code form attributes: %w", err)
	}

	rq := &fosite.Request{
		ID:                result.ID,
		RequestedAt:       result.RequestedAt,
		Client:            result.Client,
		RequestedScope:    fosite.Arguments(result.RequestedScopes),
		GrantedScope:      fosite.Arguments(result.GrantedScopes),
		Form:              form,
		Session:           &result.Session,
		RequestedAudience: fosite.Arguments(result.RequestedAudience),
		GrantedAudience:   fosite.Arguments(result.GrantedAudience),
	}

	if !result.Active {
		return rq, fosite.ErrInvalidatedAuthorizeCode
	}

	return rq, nil
}

// InvalidateAuthorizeCodeSession is called when an authorize code is being used. The state of the authorization
// code should be set to invalid and consecutive requests to GetAuthorizeCodeSession should return the
// ErrInvalidatedAuthorizeCode error.
func (m Store) InvalidateAuthorizeCodeSession(ctx context.Context, code string) (err error) {
	var result AuthorizationCode

	if err := m.db.Where(AuthorizationCode{Code: code}).First(&result).Error; err != nil {
		return fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	result.Active = false
	if err := m.db.Save(result).Error; err != nil {
		return fmt.Errorf("failed to invalidate authorization code: %w", err)
	}

	return nil
}

func (m Store) CreateAccessTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	client := request.GetClient()

	form, err := json.Marshal(request.GetRequestForm())
	if err != nil {
		return fmt.Errorf("error marshalling access token form: %w", err)
	}

	session := request.GetSession().(*Session)
	if err = m.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "id"},
			},
			UpdateAll: true,
		},
	).Create(&session).Error; err != nil {
		return fmt.Errorf("error creating authorization code session: %w", err)
	}

	data := AccessToken{
		ID:                request.GetID(),
		Active:            true,
		Signature:         signature,
		RequestedAt:       request.GetRequestedAt(),
		ClientID:          client.GetID(),
		RequestedScopes:   StringArray(request.GetRequestedScopes()),
		GrantedScopes:     StringArray(request.GetGrantedScopes()),
		Form:              form,
		SessionID:         session.ID,
		RequestedAudience: StringArray(request.GetRequestedAudience()),
		GrantedAudience:   StringArray(request.GetGrantedAudience()),
	}

	if err = m.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "id"},
			},
			UpdateAll: true,
		},
	).Create(&data).Error; err != nil {
		return fmt.Errorf("error creating access token: %w", err)
	}

	return nil
}

func (m Store) GetAccessTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	var result AccessToken

	if err := m.db.Preload("Session.User").Preload(clause.Associations).Where(AccessToken{Signature: signature}).First(&result).Error; err != nil {
		return nil, fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	var form url.Values
	err = json.Unmarshal(result.Form, &form)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling access token form attributes: %w", err)
	}

	rq := &fosite.Request{
		ID:                result.ID,
		RequestedAt:       result.RequestedAt,
		Client:            result.Client,
		RequestedScope:    fosite.Arguments(result.RequestedScopes),
		GrantedScope:      fosite.Arguments(result.GrantedScopes),
		Form:              form,
		Session:           &result.Session,
		RequestedAudience: fosite.Arguments(result.RequestedAudience),
		GrantedAudience:   fosite.Arguments(result.GrantedAudience),
	}

	return rq, nil
}

func (m Store) DeleteAccessTokenSession(ctx context.Context, signature string) (err error) {
	if err := m.db.Where(&AccessToken{Signature: signature}).Delete(&AccessToken{}).Error; err != nil {
		return fmt.Errorf("failed to delete access token: %w", err)
	}

	return nil
}

func (m Store) CreateRefreshTokenSession(ctx context.Context, signature string, request fosite.Requester) (err error) {
	client := request.GetClient()

	form, err := json.Marshal(request.GetRequestForm())
	if err != nil {
		return fmt.Errorf("error marshalling refresh token form: %w", err)
	}

	session := request.GetSession().(*Session)
	if err = m.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "id"},
			},
			UpdateAll: true,
		},
	).Create(&session).Error; err != nil {
		return fmt.Errorf("error creating refresh token session: %w", err)
	}

	data := RefreshToken{
		ID:                request.GetID(),
		Active:            true,
		Signature:         signature,
		RequestedAt:       request.GetRequestedAt(),
		ClientID:          client.GetID(),
		RequestedScopes:   StringArray(request.GetRequestedScopes()),
		GrantedScopes:     StringArray(request.GetGrantedScopes()),
		Form:              form,
		SessionID:         session.ID,
		RequestedAudience: StringArray(request.GetRequestedAudience()),
		GrantedAudience:   StringArray(request.GetGrantedAudience()),
	}

	if err = m.db.Clauses(
		clause.OnConflict{
			Columns: []clause.Column{
				{Name: "id"},
			},
			UpdateAll: true,
		},
	).Create(&data).Error; err != nil {
		return fmt.Errorf("error creating refresh token: %w", err)
	}

	return nil
}

func (m Store) GetRefreshTokenSession(ctx context.Context, signature string, session fosite.Session) (request fosite.Requester, err error) {
	var result RefreshToken

	if err := m.db.Preload("Session.User").Preload(clause.Associations).Where(RefreshToken{Signature: signature}).First(&result).Error; err != nil {
		return nil, fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	var form url.Values
	err = json.Unmarshal(result.Form, &form)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling refresh token form attributes: %w", err)
	}

	rq := &fosite.Request{
		ID:                result.ID,
		RequestedAt:       result.RequestedAt,
		Client:            result.Client,
		RequestedScope:    fosite.Arguments(result.RequestedScopes),
		GrantedScope:      fosite.Arguments(result.GrantedScopes),
		Form:              form,
		Session:           &result.Session,
		RequestedAudience: fosite.Arguments(result.RequestedAudience),
		GrantedAudience:   fosite.Arguments(result.GrantedAudience),
	}

	if !result.Active {
		return rq, fosite.ErrInactiveToken
	}

	return rq, nil
}

func (m Store) DeleteRefreshTokenSession(ctx context.Context, signature string) (err error) {
	if err := m.db.Where(&RefreshToken{Signature: signature}).Delete(&RefreshToken{}).Error; err != nil {
		return fmt.Errorf("failed to delete refresh token: %w", err)
	}

	return nil
}

// RevokeRefreshToken revokes a refresh token as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
// If the particular
// token is a refresh token and the authorization server supports the
// revocation of access tokens, then the authorization server SHOULD
// also invalidate all access tokens based on the same authorization
// grant (see Implementation Note).
func (m Store) RevokeRefreshToken(ctx context.Context, requestID string) error {

	var result RefreshToken

	if err := m.db.Where(RefreshToken{ID: requestID}).First(&result).Error; err != nil {
		return fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	result.Active = false
	if err := m.db.Save(result).Error; err != nil {
		return fmt.Errorf("failed to invalidate authorization code: %w", err)
	}

	return nil
}

// RevokeRefreshTokenMaybeGracePeriod revokes a refresh token as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
// If the particular
// token is a refresh token and the authorization server supports the
// revocation of access tokens, then the authorization server SHOULD
// also invalidate all access tokens based on the same authorization
// grant (see Implementation Note).
//
// If the Refresh Token grace period is greater than zero in configuration the token
// will have its expiration time set as UTCNow + GracePeriod.
func (m Store) RevokeRefreshTokenMaybeGracePeriod(ctx context.Context, requestID string, signature string) error {
	return m.RevokeRefreshToken(ctx, requestID)
}

func (m Store) RevokeAccessToken(ctx context.Context, requestID string) error {
	var result AccessToken

	if err := m.db.Where(AccessToken{ID: requestID}).First(&result).Error; err != nil {
		return fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	result.Active = false
	if err := m.db.Save(result).Error; err != nil {
		return fmt.Errorf("failed to invalidate authorization code: %w", err)
	}

	return nil
}

func (m Store) Authenticate(ctx context.Context, name string, secret string) error {
	var result User

	if err := m.db.Where(User{Username: name}).First(&result).Error; err != nil {
		return fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	if result.Password != secret {
		return fosite.ErrNotFound.WithDebug("Invalid credentials")
	}

	return nil
}
