package store

import (
	"log"

	"github.com/google/uuid"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"
)

var dsn = "auth.db"

type Store struct {
	db *gorm.DB
}

func NewStore() *Store {
	db, err := gorm.Open(
		sqlite.Open(dsn),
		&gorm.Config{
			Logger: logger.Default.LogMode(logger.Error),
		},
	)
	if err != nil {
		log.Fatal("failed to connect database")
	}

	err = db.AutoMigrate(
		AccessToken{},
		AuthorizationCode{},
		Client{},
		ClientJWT{},
		User{},
		PKCE{},
		RefreshToken{},
		Session{},
	)
	if err != nil {
		log.Fatal("failed to run migrations:", err)
	}

	users := []User{
		{
			ID:       uuid.NewString(),
			Active:   true,
			Name:     "Charles Doe",
			Username: "ovl_doe",
			Password: "12345678",
		},
	}

	clients := []Client{
		{
			ID:     "client-one",
			Active: true,
			Secret: "$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO", // "foobar"
			RotatedSecrets: []string{
				"$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC", // "foobaz"
			},
			Public: false,
			RedirectURIs: []string{
				"http://localhost:8080/callback",
				"http://127.0.0.1:8080/callback",
				"http://127.0.0.1:8080/accounts/customprovider/login/callback/",
				"http://localhost:8080/accounts/customprovider/login/callback/",
			},
			Scopes: []string{
				"fosite", "photos", "offline",
			},
			Audience: []string{},
			Grants: []string{
				"implicit", "refresh_token", "authorization_code", "client_credentials",
			},
			ResponseTypes: []string{
				"code", "token", "code token", "implicit",
			},
			TokenEndpointAuthMethod: "client_secret_basic",
		},
		{
			ID:     "client-two",
			Active: true,
			Secret: "$2a$10$IxMdI6d.LIRZPpSfEwNoeu4rY3FhDREsxFJXikcgdRRAStxUlsuEO", // "foobar"
			RotatedSecrets: []string{
				"$2y$10$X51gLxUQJ.hGw1epgHTE5u0bt64xM0COU7K9iAp.OFg8p2pUd.1zC", // "foobaz"
			},
			Public:       false,
			RedirectURIs: []string{},
			Scopes: []string{
				"fosite", "photos", "offline",
			},
			Audience: []string{},
			Grants: []string{
				"implicit", "refresh_token", "authorization_code", "client_credentials",
			},
			ResponseTypes: []string{
				"code", "token", "code token",
			},
			TokenEndpointAuthMethod: "client_secret_basic",
		},
	}

	for _, client := range clients {
		err = db.Clauses(
			clause.OnConflict{
				Columns: []clause.Column{
					{Name: "id"},
				},
				UpdateAll: true,
			},
		).Create(&client).Error
		if err != nil {
			log.Fatal("failed to create client:", err)
		}
	}

	for _, user := range users {
		err = db.Clauses(
			clause.OnConflict{
				Columns: []clause.Column{
					{Name: "username"},
				},
				UpdateAll: true,
			},
		).Create(&user).Error
		if err != nil {
			log.Fatal("failed to create client:", err)
		}
	}

	return &Store{
		db: db,
	}
}
