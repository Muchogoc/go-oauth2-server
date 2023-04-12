package internal

import (
	"github.com/Muchogoc/go-oauth2-server/internal/html"
	"github.com/Muchogoc/go-oauth2-server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/ory/fosite"
)

type Auth struct {
	provider fosite.OAuth2Provider
	store    *store.Store
}

func NewAuth(provider fosite.OAuth2Provider, store *store.Store) *Auth {

	return &Auth{
		provider: provider,
		store:    store,
	}
}

type Authorize struct {
	Username string   `form:"username"`
	Password string   `form:"password"`
	Scopes   []string `form:"scopes"`
}

func (a Auth) AuthorizeHandler(c *gin.Context) {
	ctx := c.Request.Context()

	ar, err := a.provider.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	_ = ar.GetClient()

	params := Authorize{}
	err = c.Bind(&params)
	if err != nil {
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	// Check if username exists
	if params.Password == "" || params.Username == "" {
		c.Writer.Header().Set("Content-Type", "text/html; charset=utf-8")
		params := html.LoginParams{
			Title:           "Login",
			RequestedScopes: ar.GetRequestedScopes(),
		}

		_ = html.Login(c.Writer, params)

		return
	}

	err = a.store.Authenticate(ctx, params.Username, params.Password)
	if err != nil {
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	// let's see what scopes the user gave consent to
	for _, scope := range params.Scopes {
		ar.GrantScope(scope)
	}

	user, err := a.store.GetUser(ctx, params.Username)
	if err != nil {
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	session, _ := store.NewSession(
		ctx,
		ar.GetClient().GetID(),
		user.ID,
		user.Username,
		user.Name,
		map[string]interface{}{
			"organisation_id": uuid.New().String(),
			"user_id":         user.ID,
		},
	)
	response, err := a.provider.NewAuthorizeResponse(ctx, ar, session)
	if err != nil {
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	a.provider.WriteAuthorizeResponse(ctx, c.Writer, ar, response)

}

func (a Auth) TokenHandler(c *gin.Context) {
	ctx := c.Request.Context()

	ar, err := a.provider.NewAccessRequest(ctx, c.Request, new(store.Session))
	if err != nil {
		a.provider.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}

	// If this is a client_credentials grant, grant all requested scopes
	// NewAccessRequest validated that all requested scopes the client is allowed to perform
	// based on configured scope matching strategy.
	if ar.GetGrantTypes().ExactOne("client_credentials") {
		for _, scope := range ar.GetRequestedScopes() {
			ar.GrantScope(scope)
		}
	}

	// Next we create a response for the access request. Again, we iterate through the TokenEndpointHandlers
	// and aggregate the result in response.
	response, err := a.provider.NewAccessResponse(ctx, ar)
	if err != nil {
		a.provider.WriteAccessError(ctx, c.Writer, ar, err)
		return
	}

	// All done, send the response.
	a.provider.WriteAccessResponse(ctx, c.Writer, ar, response)

}

func (a Auth) RevokeHandler(c *gin.Context) {
	ctx := c.Request.Context()

	err := a.provider.NewRevocationRequest(ctx, c.Request)
	if err != nil {
		a.provider.WriteRevocationResponse(ctx, c.Writer, err)
		return
	}

	a.provider.WriteRevocationResponse(ctx, c.Writer, nil)
}

func (a Auth) IntrospectionHandler(c *gin.Context) {
	ctx := c.Request.Context()

	ir, err := a.provider.NewIntrospectionRequest(ctx, c.Request, new(store.Session))
	if err != nil {
		a.provider.WriteIntrospectionError(ctx, c.Writer, err)
		return
	}

	a.provider.WriteIntrospectionResponse(ctx, c.Writer, ir)
}
