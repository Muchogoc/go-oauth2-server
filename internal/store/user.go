package store

import (
	"context"
	"fmt"

	"github.com/ory/fosite"
	"gorm.io/gorm/clause"
)

func (m Store) GetUser(ctx context.Context, username string) (*User, error) {
	var result User

	if err := m.db.Preload(clause.Associations).Where(User{Username: username}).First(&result).Error; err != nil {
		return nil, fmt.Errorf("%w: %w", fosite.ErrNotFound, err)
	}

	return &result, nil

}
