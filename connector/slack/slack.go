// Package oidc implements logging in through OpenID Connect providers.
package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"slack.com/Sirupsen/logrus"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/slack"

	"slack.com/coreos/dex/connector"
	"io/ioutil"
	"strconv"
)

type SlackResponse struct {
	Ok    bool   `json:"ok"`
	Error string `json:"error"`
}

type OAuthResponseIncomingWebhook struct {
	URL              string `json:"url"`
	Channel          string `json:"channel"`
	ChannelID        string `json:"channel_id,omitempty"`
	ConfigurationURL string `json:"configuration_url"`
}

type Config struct {
	ClientID     string `json:"clientID"`
	ClientSecret string `json:"clientSecret"`
	RedirectURI  string `json:"redirectURI"`
	HostName     string `json:"hostName"`
	IncomingWebhook OAuthResponseIncomingWebhook `json:"incoming_webhook"`
	RootCA       string `json:"rootCA"`
}

type OAuthResponse struct {
	AccessToken     string                       `json:"access_token"`
	Scope           string                       `json:"scope"`
	TeamName        string                       `json:"team_name"`
	TeamID          string                       `json:"team_id"`
	UserID          string                       `json:"user_id,omitempty"`
	SlackResponse
}

type slackConnector struct {
	redirectURI  string
	clientID     string
	clientSecret string
	logger       logrus.FieldLogger
}

type connectorData struct {
	// Slack's OAuth2 tokens never expire. We don't need a refresh token.
	AccessToken string `json:"accessToken"`
}

// Open returns a strategy for logging in through Slack.
func (c *Config) Open(logger logrus.FieldLogger) (connector.Connector, error) {
	return &slackConnector{
		redirectURI:  c.RedirectURI,
		clientID:     c.ClientID,
		clientSecret: c.ClientSecret,
		logger:       logger,
	}, nil
}

func (c *slackConnector) oauth2Config(scopes connector.Scopes) *oauth2.Config {
	endpoint := slack.Endpoint

	return &oauth2.Config{
		ClientID:     c.clientID,
		ClientSecret: c.clientSecret,
		Endpoint:     endpoint,
		Scopes:       "somehardcoded scope",
	}
}

// GetOAuthToken retrieves an AccessToken
func GetOAuthToken(clientID, clientSecret, code, redirectURI string, debug bool) (accessToken string, scope string, err error) {
	return GetOAuthTokenContext(context.Background(), clientID, clientSecret, code, redirectURI, debug)
}

// GetOAuthTokenContext retrieves an AccessToken with a custom context
func GetOAuthTokenContext(ctx context.Context, clientID, clientSecret, code, redirectURI string, debug bool) (accessToken string, scope string, err error) {
	response, err := GetOAuthResponseContext(ctx, clientID, clientSecret, code, redirectURI, debug)
	if err != nil {
		return "", "", err
	}
	return response.AccessToken, response.Scope, nil
}

func GetOAuthResponse(clientID, clientSecret, code, redirectURI string, debug bool) (resp *OAuthResponse, err error) {
	return GetOAuthResponseContext(context.Background(), clientID, clientSecret, code, redirectURI, debug)
}

func GetOAuthResponseContext(ctx context.Context, clientID, clientSecret, code, redirectURI string, debug bool) (resp *OAuthResponse, err error) {
	values := url.Values{
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code":          {code},
		"redirect_uri":  {redirectURI},
	}
	response := &OAuthResponse{}
	err = post(ctx, "oauth.access", values, response, debug)
	if err != nil {
		return nil, err
	}
	if !response.Ok {
		return nil, errors.New(response.Error)
	}
	return response, nil
}

var (
	_ connector.CallbackConnector = (*slackConnector)(nil)
	_ connector.RefreshConnector  = (*slackConnector)(nil)
)


func (c *slackConnector) LoginURL(s connector.Scopes, callbackURL, state string) (string, error) {
	if c.redirectURI != callbackURL {
		return "", fmt.Errorf("expected callback URL did not match the URL in the config")
	}
	return c.oauth2Config(scopes).AuthCodeURL(state), nil
}

type oauth2Error struct {
	error            string
	errorDescription string
}

func (e *oauth2Error) Error() string {
	if e.errorDescription == "" {
		return e.error
	}
	return e.error + ": " + e.errorDescription
}

type user struct {
	Name  string `json:"name"`
	Login string `json:"login"`
	ID    int    `json:"id"`
	Email string `json:"email"`
}

func (c *slackConnector) HandleCallback(s connector.Scopes, r *http.Request) (identity connector.Identity, err error) {
	q := r.URL.Query()
	if errType := q.Get("error"); errType != "" {
		return identity, &oauth2Error{errType, q.Get("error_description")}
	}

	oauth2Config := c.oauth2Config(s)

	ctx := r.Context()



	token, err := oauth2Config.Exchange(ctx, q.Get("code"))
	if err != nil {
		return identity, fmt.Errorf("slack: failed to get token: %v", err)
	}

	client := oauth2Config.Client(ctx, token)

	user, err := GetOAuthResponse(oauth2Config.ClientID, oauth2Config.ClientSecret, token, oauth2Config.RedirectURL, true)
	if err != nil {
		return identity, fmt.Errorf("slack: get user: %v", err)
	}

	identity = connector.Identity{
		UserID:        strconv.Itoa(user.ID),
		Username:      username,
		Email:         user.Email,
		EmailVerified: true,
	}

	if s.OfflineAccess {
		data := connectorData{AccessToken: token.AccessToken}
		connData, err := json.Marshal(data)
		if err != nil {
			return identity, fmt.Errorf("marshal connector data: %v", err)
		}
		identity.ConnectorData = connData
	}

	return identity, nil
}
