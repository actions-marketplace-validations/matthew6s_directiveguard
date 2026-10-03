package cloud

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"
)

type Config struct {
	Address             string
	DatabasePath        string
	BaseURL             string
	GitHubClientID      string
	GitHubClientSecret  string
	SessionSecret       []byte
	StripeSecretKey     string
	StripeAPIBase       string
	StripeWebhookSecret string
	StripeTeamPriceID   string
}

func ConfigFromEnv() (Config, error) {
	config := Config{
		Address:             envOr("AGENTSHIELD_ADDRESS", ":8080"),
		DatabasePath:        envOr("AGENTSHIELD_DATABASE", "agentshield-cloud.db"),
		BaseURL:             strings.TrimRight(envOr("AGENTSHIELD_BASE_URL", "http://localhost:8080"), "/"),
		GitHubClientID:      os.Getenv("GITHUB_CLIENT_ID"),
		GitHubClientSecret:  os.Getenv("GITHUB_CLIENT_SECRET"),
		StripeSecretKey:     os.Getenv("STRIPE_SECRET_KEY"),
		StripeAPIBase:       envOr("STRIPE_API_BASE", "https://api.stripe.com"),
		StripeWebhookSecret: os.Getenv("STRIPE_WEBHOOK_SECRET"),
		StripeTeamPriceID:   os.Getenv("STRIPE_TEAM_PRICE_ID"),
	}
	encodedSecret := os.Getenv("AGENTSHIELD_SESSION_SECRET")
	if encodedSecret == "" {
		return Config{}, fmt.Errorf("AGENTSHIELD_SESSION_SECRET is required (base64-encoded 32+ random bytes)")
	}
	secret, err := base64.StdEncoding.DecodeString(encodedSecret)
	if err != nil || len(secret) < 32 {
		return Config{}, fmt.Errorf("AGENTSHIELD_SESSION_SECRET must be base64-encoded and at least 32 bytes")
	}
	config.SessionSecret = secret
	if (config.GitHubClientID == "") != (config.GitHubClientSecret == "") {
		return Config{}, fmt.Errorf("GITHUB_CLIENT_ID and GITHUB_CLIENT_SECRET must be configured together")
	}
	return config, nil
}

func (c Config) GitHubEnabled() bool { return c.GitHubClientID != "" }
func (c Config) BillingEnabled() bool {
	return c.StripeSecretKey != "" && c.StripeWebhookSecret != "" && c.StripeTeamPriceID != ""
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
