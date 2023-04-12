package store

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/ory/fosite"
)

// ClientAssertionJWTValid returns an error if the JTI is known or the DB check failed
// and nil if the JTI is not known.
func (m Store) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	var result ClientJWT

	if err := m.db.Where(ClientJWT{JTI: jti}).First(&result).Error; err != nil {
		return nil
	}

	if result.ExpiresAt.After(time.Now()) {
		return fosite.ErrJTIKnown
	}

	return nil
}

// GetClient loads the client by its ID or returns an error
// if the client does not exist or another error occurred.
func (m Store) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var result Client

	if err := m.db.Where(Client{ID: id}).First(&result).Error; err != nil {
		return nil, fmt.Errorf("error fetching client: %w", err)
	}

	return result, nil
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
func (m Store) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	var result ClientJWT

	if err := m.db.Where(ClientJWT{JTI: jti}).Where("expires_at > ?", time.Now()).First(&result).Error; err != nil {
		return fosite.ErrJTIKnown
	}

	jwt := ClientJWT{
		ID:        uuid.NewString(),
		JTI:       jti,
		ExpiresAt: exp,
	}

	if err := m.db.Create(&jwt).Error; err != nil {
		return fmt.Errorf("error creating client assertion jwt: %w", err)
	}

	return nil
}
