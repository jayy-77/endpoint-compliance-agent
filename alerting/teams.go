package alerting

import (
	"bytes"
	"fmt"
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
	config := TeamsConfig{
		WebhookURL: os.Getenv("TEAMS_WEBHOOK_URL"),
	}

	return &TeamsClient{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}
func (t *TeamsClient) sendMessage(message string) error {
	resp, err := t.client.Post(t.config.WebhookURL, "application/json", bytes.NewBuffer([]byte(message)))
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack API returned status %d", resp.StatusCode)
	}
	return nil
}
func (t *TeamsClient) TestConnection() error {
	if t.config.WebhookURL == "" {
		return fmt.Errorf("TEAMS_WEBHOOK_URL not configured")
	}
	testMessage := `{"text": "🧪 *Compliance Agent Test* - Connection successful!"}`
	return t.sendMessage(testMessage)
}
