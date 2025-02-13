package dex

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

type Config struct {
	Client *http.Client

	Endpoint  string
	Values    url.Values
	BasicAuth string
}

func Issue(ctx context.Context, config Config) (string, error) {
	log := log.FromContext(ctx)

	httpClient := config.Client
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	req, err := http.NewRequestWithContext(ctx, "POST", config.Endpoint, strings.NewReader(config.Values.Encode()))
	if err != nil {
		return "", fmt.Errorf("failed to create request: %w", err)
	}
	if config.BasicAuth != "" {
		user, password, _ := strings.Cut(config.BasicAuth, ":")
		req.SetBasicAuth(user, password)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("failed to send a request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)

		log.Error(errors.New(string(b)), "failed to issue access token")

		return "", fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	var token tokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		return "", fmt.Errorf("failed to decode response: %w", err)
	}

	return token.AccessToken, nil
}

func GetTokenExp(token string) (*time.Time, error) {
	var claims jwt.RegisteredClaims
	_, _, err := new(jwt.Parser).ParseUnverified(token, &claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse jwt: %w", err)
	}

	if claims.ExpiresAt == nil {
		return nil, errors.New("token does not have an expiration time")
	}

	return &claims.ExpiresAt.Time, nil
}

type tokenResponse struct {
	AccessToken     string `json:"access_token"`
	IssuedTokenType string `json:"issued_token_type"`
	TokenType       string `json:"token_type"`
	ExpiresIn       int    `json:"expires_in"`
}
