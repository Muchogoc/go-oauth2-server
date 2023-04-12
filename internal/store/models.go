package store

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/mohae/deepcopy"
	"github.com/ory/fosite"
	"github.com/ory/fosite/token/jwt"
	"gorm.io/datatypes"
	"gorm.io/gorm"
	"time"
)

type AccessToken struct {
	gorm.Model

	ID        string `gorm:"primarykey"`
	Active    bool
	Signature string `gorm:"unique"`

	RequestedAt       time.Time
	RequestedScopes   StringArray
	GrantedScopes     StringArray
	Form              datatypes.JSON
	RequestedAudience StringArray
	GrantedAudience   StringArray

	ClientID  string
	Client    Client
	SessionID string
	Session   Session
}

func (AccessToken) TableName() string {
	return "access_tokens"
}

type AuthorizationCode struct {
	gorm.Model

	ID     string `gorm:"primarykey"`
	Active bool
	Code   string

	RequestedAt       time.Time
	RequestedScopes   StringArray
	GrantedScopes     StringArray
	Form              datatypes.JSON
	RequestedAudience StringArray
	GrantedAudience   StringArray

	SessionID string
	Session   Session
	ClientID  string
	Client    Client
}

func (AuthorizationCode) TableName() string {
	return "authorization_codes"
}

type Client struct {
	gorm.Model

	ID                      string `gorm:"primarykey"`
	Active                  bool
	Secret                  string
	RotatedSecrets          StringArray
	Public                  bool
	RedirectURIs            StringArray
	Scopes                  StringArray
	Audience                StringArray
	Grants                  StringArray
	ResponseTypes           StringArray
	TokenEndpointAuthMethod string
}

func (Client) TableName() string {
	return "clients"
}

// GetID returns the client ID.
func (c Client) GetID() string {
	return c.ID
}

// GetHashedSecret returns the hashed secret as it is stored in the store.
func (c Client) GetHashedSecret() []byte {
	return []byte(c.Secret)
}

func (c Client) GetRotatedHashes() [][]byte {
	var secrets [][]byte

	for _, secret := range c.RotatedSecrets {
		secrets = append(secrets, []byte(secret))
	}

	return secrets
}

// GetRedirectURIs returns the client's allowed redirect URIs.
func (c Client) GetRedirectURIs() []string {
	var URIs []string

	for _, st := range c.RedirectURIs {
		URIs = append(URIs, st)
	}

	return URIs
}

// GetGrantTypes returns the client's allowed grant types.
func (c Client) GetGrantTypes() fosite.Arguments {
	var Grants []string

	for _, st := range c.Grants {
		Grants = append(Grants, st)
	}

	return Grants
}

// GetResponseTypes returns the client's allowed response types.
// All allowed combinations of response types have to be listed, each combination having
// response types of the combination separated by a space.
func (c Client) GetResponseTypes() fosite.Arguments {
	var responses []string

	for _, st := range c.ResponseTypes {
		responses = append(responses, st)
	}

	return responses
}

// GetScopes returns the scopes this client is allowed to request.
func (c Client) GetScopes() fosite.Arguments {
	var Scopes []string

	for _, st := range c.Scopes {
		Scopes = append(Scopes, st)
	}

	return Scopes
}

// IsPublic returns true, if this client is marked as public.
func (c Client) IsPublic() bool {
	return c.Public
}

// GetAudience returns the allowed audience(s) for this client.
func (c Client) GetAudience() fosite.Arguments {
	var Audience []string

	for _, st := range c.Audience {
		Audience = append(Audience, st)
	}

	return Audience
}

type ClientJWT struct {
	gorm.Model

	ID        string `gorm:"primarykey"`
	Active    bool
	JTI       string
	ExpiresAt time.Time
}

type PKCE struct {
	gorm.Model

	ID        string `gorm:"primarykey"`
	Active    bool
	Signature string `gorm:"unique"`

	RequestedAt       time.Time
	RequestedScopes   StringArray
	GrantedScopes     StringArray
	Form              datatypes.JSON
	RequestedAudience StringArray
	GrantedAudience   StringArray

	SessionID string
	Session   Session
	ClientID  string
	Client    Client
}

func (PKCE) TableName() string {
	return "pkces"
}

type RefreshToken struct {
	gorm.Model

	ID        string `gorm:"primarykey"`
	Active    bool
	Signature string `gorm:"unique"`

	RequestedAt       time.Time
	RequestedScopes   StringArray
	GrantedScopes     StringArray
	Form              datatypes.JSON
	RequestedAudience StringArray
	GrantedAudience   StringArray

	ClientID  string
	Client    Client
	SessionID string
	Session   Session
}

func (RefreshToken) TableName() string {
	return "refresh_tokens"
}

func NewSession(
	ctx context.Context,
	clientID string,
	userID string,
	username string,
	subject string,
	extra map[string]interface{},
) (*Session, error) {

	session := &Session{
		ID:       uuid.New().String(),
		UserID:   userID,
		ClientID: clientID,
		Username: username,
		Subject:  subject,
	}

	if extra != nil {
		sess_extra, err := json.Marshal(extra)
		if err != nil {
			return nil, fmt.Errorf("error marshalling session extra: %w", err)
		}

		session.Extra = sess_extra
	}

	return session, nil
}

type Session struct {
	gorm.Model

	ID       string `gorm:"primarykey"`
	ClientID string

	Username  string
	Subject   string
	ExpiresAt datatypes.JSON

	// Default
	Extra datatypes.JSON

	UserID string
	User   User
}

// SetExpiresAt sets the expiration time of a token.
//
//	session.SetExpiresAt(fosite.AccessToken, time.Now().UTC().Add(time.Hour))
func (s *Session) SetExpiresAt(key fosite.TokenType, exp time.Time) {
	expiresAt := make(map[fosite.TokenType]time.Time)

	if s.ExpiresAt != nil {
		_ = json.Unmarshal(s.ExpiresAt, &expiresAt)
	}

	expiresAt[key] = exp

	sess_expires, _ := json.Marshal(expiresAt)

	s.ExpiresAt = sess_expires
}

// GetExpiresAt returns the expiration time of a token if set, or time.IsZero() if not.
//
//	session.GetExpiresAt(fosite.AccessToken)
func (s *Session) GetExpiresAt(key fosite.TokenType) time.Time {
	if s.ExpiresAt == nil {
		return time.Time{}
	}

	expiresAt := make(map[fosite.TokenType]time.Time)
	_ = json.Unmarshal(s.ExpiresAt, &expiresAt)

	if _, ok := expiresAt[key]; !ok {
		return time.Time{}
	}

	return expiresAt[key]
}

// GetUsername returns the username, if set. This is optional and only used during token introspection.
func (s *Session) GetUsername() string {
	if s == nil {
		return ""
	}

	return s.Username
}

func (s *Session) GetExtraClaims() map[string]interface{} {
	if s == nil {
		return nil
	}

	var extra map[string]interface{}

	if s.Extra != nil {
		_ = json.Unmarshal(s.Extra, &extra)
	}

	return extra
}

// GetSubject returns the subject, if set. This is optional and only used during token introspection.
func (s *Session) GetSubject() string {
	if s == nil {
		return ""
	}

	return s.Subject
}

// Clone clones the session.
func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	return deepcopy.Copy(s).(fosite.Session)
}

// IDTokenClaims returns a pointer to claims which will be modified in-place by handlers.
// Session should store this pointer and return always the same pointer.
func (s *Session) IDTokenClaims() *jwt.IDTokenClaims {
	return &jwt.IDTokenClaims{}
}

// IDTokenHeaders returns a pointer to header values which will be modified in-place by handlers.
// Session should store this pointer and return always the same pointer.
func (s *Session) IDTokenHeaders() *jwt.Headers {
	return &jwt.Headers{}
}

type User struct {
	gorm.Model

	ID       string `gorm:"primarykey"`
	Active   bool
	Name     string
	Username string `gorm:"unique"`
	Password string
}

func (User) TableName() string {
	return "users"
}

type UserRole struct {
	ID     int `gorm:"primarykey;autoIncrement"`
	UserID string
	RoleID string
}

func (UserRole) TableName() string {
	return "user_roles"
}
