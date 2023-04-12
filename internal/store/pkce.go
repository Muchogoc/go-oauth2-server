package store

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/ory/fosite"
	"gorm.io/gorm/clause"
)

func (m Store) CreatePKCERequestSession(ctx context.Context, signature string, requester fosite.Requester) error {
	client := requester.GetClient()

	form, err := json.Marshal(requester.GetRequestForm())
	if err != nil {
		return fmt.Errorf("error marshalling PCKE form: %w", err)
	}

	session := requester.GetSession().(*Session)
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

	data := PKCE{
		ID:                requester.GetID(),
		Active:            true,
		Signature:         signature,
		RequestedAt:       requester.GetRequestedAt(),
		ClientID:          client.GetID(),
		RequestedScopes:   StringArray(requester.GetRequestedScopes()),
		GrantedScopes:     StringArray(requester.GetGrantedScopes()),
		Form:              form,
		SessionID:         session.ID,
		RequestedAudience: StringArray(requester.GetRequestedAudience()),
		GrantedAudience:   StringArray(requester.GetGrantedAudience()),
	}

	if err = m.db.Create(&data).Error; err != nil {
		return fmt.Errorf("error creating PCKE: %w", err)
	}

	return nil
}

func (m Store) GetPKCERequestSession(ctx context.Context, signature string, session fosite.Session) (fosite.Requester, error) {
	var result PKCE

	if err := m.db.Preload("Session.User").Preload(clause.Associations).Where(PKCE{Signature: signature}).First(&result).Error; err != nil {
		return nil, fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	var form url.Values
	err := json.Unmarshal(result.Form, &form)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling PCKE form attributes: %w", err)
	}

	rq := fosite.Request{
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

	return &rq, nil
}

func (m Store) DeletePKCERequestSession(ctx context.Context, signature string) error {
	if err := m.db.Where(&PKCE{Signature: signature}).Delete(&PKCE{}).Error; err != nil {
		return fmt.Errorf("failed to delete PCKE request: %w", err)
	}

	return nil
}
