package alerting

import (
	"net/http"
	"os"
	"time"
)

type TeamsConfig struct {
	WebhookURL string
}

type TeamsClient struct {
	config TeamsConfig
	client *http.Client
}

func NewTeamsClient() *TeamsClient {
	config:= TeamsConfig{
		WebhookURL: os.Getenv("TEAMS_WEBHOOK_URL"),
	}

	return &TeamsClient{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}