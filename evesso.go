package evesso

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/golang-jwt/jwt"
	"github.com/lestrrat-go/jwx/jwk"
)

type serverInfo struct {
	Issuer                                     string   `json:"issuer"`
	AuthorizationEndpoint                      string   `json:"authorization_endpoint"`
	TokenEndpoint                              string   `json:"token_endpoint"`
	ResponseTypesSupported                     []string `json:"response_types_supported"`
	JwksURI                                    string   `json:"jwks_uri"`
	RevocationEndpoint                         string   `json:"revocation_endpoint"`
	RevocationEndpointAuthMethodsSupported     []string `json:"revocation_endpoint_auth_methods_supported"`
	TokenEndpointAuthMethodsSupported          []string `json:"token_endpoint_auth_methods_supported"`
	TokenEndpointAuthSigningAlgValuesSupported []string `json:"token_endpoint_auth_signing_alg_values_supported"`
	CodeChallengeMethodsSupported              []string `json:"code_challenge_methods_supported"`
}

type ExchangeCodeResponse struct {
	AccessToken  string `json:"access_token"`
	ExpiresIn    int64  `json:"expires_in"`
	TokenType    string `json:"token_type"`
	RefreshToken string `json:"refresh_token"`
}

const eveOAuthServer = "https://login.eveonline.com/.well-known/oauth-authorization-server"

type Client struct {
	httpClient   *http.Client
	discovery    serverInfo
	keySet       jwk.Set
	callbackURL  string
	clientID     string
	clientSecret string
}

// NewClient constructor
func NewClient(ctx context.Context, httpClient *http.Client, clientID, clientSecret, callbackURL string) (*Client, error) {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	client := &Client{
		httpClient:   httpClient,
		clientID:     clientID,
		clientSecret: clientSecret,
		callbackURL:  callbackURL,
	}

	req, err := http.NewRequestWithContext(ctx, "GET", eveOAuthServer, nil)
	if err != nil {
		return nil, err
	}

	resp, err := client.httpClient.Do(req)
	if err != nil {
		return nil, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&client.discovery)
	if err != nil {
		return nil, err
	}

	return client, nil
}

// AuthenticateURL return authentication URL created with provided state and scopes.
func (c *Client) AuthenticateURL(state string, scopes ...string) string {
	u := url.Values{
		"response_type": {"code"},
		"redirect_uri":  {c.callbackURL},
		"client_id":     {c.clientID},
		"scope":         {strings.Join(scopes, " ")},
		"state":         {state},
	}

	return fmt.Sprintf("%s?%s", c.discovery.AuthorizationEndpoint, u.Encode())
}

// ExchangeCode excanges code for JWT token.
func (c *Client) ExchangeCode(ctx context.Context, code string) (result ExchangeCodeResponse, err error) {
	v := url.Values{
		"grant_type": {"authorization_code"},
		"code":       {code},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.discovery.TokenEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return result, err
	}

	req.Header.Set("Authorization", "Basic "+c.getAuthHeaderValue())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return result, err
	}

	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&result)
	if err != nil {
		return result, err
	}

	return result, nil
}

// RevokeToken revokes refresh token.
func (c *Client) RevokeToken(ctx context.Context, refreshToken string) error {
	v := url.Values{
		"token_type_hint": {"refresh_token"},
		"token":           {refreshToken},
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.discovery.RevocationEndpoint, strings.NewReader(v.Encode()))
	if err != nil {
		return err
	}

	req.Header.Set("Authorization", "Basic "+c.getAuthHeaderValue())
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}

	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revocation of token returned not expected status code: %d", resp.StatusCode)
	}

	return nil
}

// GetCharacterDetails returns characterID and characterName from provided JWT token claims.
func (c *Client) GetCharacterDetails(t *jwt.Token) (characterID int, characterName string, err error) {
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return 0, "", errors.New("provided token claims could not be mapped")
	}

	sub, ok := claims["sub"].(string)
	if !ok {
		return 0, "", errors.New("sub claim of JWT token is not string")
	}

	characterName, ok = claims["name"].(string)
	if !ok {
		return 0, "", errors.New("name claim of JWT token is not string")
	}

	idParts := strings.SplitN(sub, ":", 3)
	if len(idParts) < 3 {
		return 0, "", errors.New("sub claim of JWT token doesn't have proper formatting")
	}

	characterID, err = strconv.Atoi(idParts[2])
	if err != nil {
		return 0, "", err
	}

	return characterID, characterName, nil
}

// ParseToken parses and validates token
func (c *Client) ParseToken(ctx context.Context, token string) (*jwt.Token, error) {
	parsedToken, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		var err error

		if c.keySet == nil {
			c.keySet, err = jwk.Fetch(ctx, c.discovery.JwksURI, jwk.WithHTTPClient(c.httpClient))
			if err != nil {
				return nil, err
			}
		}

		keyID, ok := t.Header["kid"].(string)
		if !ok {
			return nil, errors.New("expecting JWT header to have string kid")
		}

		if key, ok := c.keySet.LookupKeyID(keyID); ok {
			var z interface{}

			err = key.Raw(&z)
			if err != nil {
				return nil, err
			}

			return z, nil
		}

		return "", errors.New("no key for JTW token found")
	})

	if err != nil {
		return nil, err
	}

	if claims, ok := parsedToken.Claims.(jwt.MapClaims); ok && parsedToken.Valid {
		if !claims.VerifyIssuer(c.discovery.Issuer, true) {
			return nil, fmt.Errorf("token issuer is not %q", c.discovery.Issuer)
		}

		partyID, ok := claims["azp"].(string)
		if !ok || partyID != c.clientID {
			return nil, errors.New("token issued not to our client id")
		}
	}

	return parsedToken, nil
}

// getAuthHeaderValue constructs Basic auth header value
func (c *Client) getAuthHeaderValue() string {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "%s:%s", c.clientID, c.clientSecret)

	return base64.StdEncoding.EncodeToString(buf.Bytes())
}
