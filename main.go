package main

import (
	"os"
	"time"

	"github.com/Muchogoc/go-oauth2-server/config"
	"github.com/Muchogoc/go-oauth2-server/internal"
	"github.com/Muchogoc/go-oauth2-server/internal/store"
	"github.com/Muchogoc/go-oauth2-server/log"
	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
)

func main() {
	cfg := config.Config()

	r := gin.Default()

	secret := []byte("some-cool-secret-that-is-32bytes")

	conf := &fosite.Config{
		GlobalSecret: secret,

		AccessTokenLifespan:   1 * time.Hour,
		RefreshTokenLifespan:  24 * time.Hour,
		AuthorizeCodeLifespan: 5 * time.Minute,

		SendDebugMessagesToClients: true,
	}

	storage := store.NewStore()

	provider := compose.Compose(
		conf,
		storage,
		compose.NewOAuth2HMACStrategy(conf),
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2AuthorizeImplicitFactory,
		compose.OAuth2ClientCredentialsGrantFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2TokenRevocationFactory,
	)

	auth := internal.NewAuth(provider, storage)

	oauth2Routes := r.Group("/oauth2")

	oauth2Routes.GET("/authorize", auth.AuthorizeHandler)
	oauth2Routes.POST("/authorize", auth.AuthorizeHandler)
	oauth2Routes.POST("/token", auth.TokenHandler)
	oauth2Routes.POST("/revoke", auth.RevokeHandler)
	oauth2Routes.POST("/introspect", auth.IntrospectionHandler)

	log.Info("starting server and listening on ", cfg.GetString("listen_address"))
	err := r.Run(cfg.GetString("listen_address"))
	if err != nil {
		os.Exit(1)
	}
}
