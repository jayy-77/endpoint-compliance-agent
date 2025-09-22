package alerting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

// SlackConfig holds configuration for Slack webhook integration
type SlackConfig struct {
	WebhookURL string
	Channel    string
	Username   string
	IconEmoji  string
}

// SlackClient handles sending alerts to Slack
type SlackClient struct {
	config SlackConfig
	client *http.Client
}

// NewSlackClient creates a new Slack client
func NewSlackClient() *SlackClient {
	config := SlackConfig{
		WebhookURL: os.Getenv("SLACK_WEBHOOK_URL"),
		Channel:    os.Getenv("SLACK_CHANNEL"),
		Username:   "Compliance Agent",
		IconEmoji:  ":shield:",
	}

	// Set defaults if not provided
	if config.Channel == "" {
		config.Channel = "#compliance"
	}

	return &SlackClient{
		config: config,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

// SlackMessage represents a Slack message payload
type SlackMessage struct {
	Channel     string       `json:"channel,omitempty"`
	Username    string       `json:"username,omitempty"`
	IconEmoji   string       `json:"icon_emoji,omitempty"`
	Text        string       `json:"text,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

// Attachment represents a Slack message attachment
type Attachment struct {
	Color     string   `json:"color,omitempty"`
	Title     string   `json:"title,omitempty"`
	Text      string   `json:"text,omitempty"`
	Fields    []Field  `json:"fields,omitempty"`
	Actions   []Action `json:"actions,omitempty"`
	Timestamp int64    `json:"ts,omitempty"`
}

// Field represents a field in a Slack attachment
type Field struct {
	Title string `json:"title"`
	Value string `json:"value"`
	Short bool   `json:"short"`
}

// ComplianceReport represents the compliance report structure for Slack
type ComplianceReport struct {
	GeneratedAt   time.Time              `json:"generated_at"`
	Hostname      string                 `json:"hostname"`
	Users         []map[string]string    `json:"users"`
	Processes     []map[string]string    `json:"processes"`
	OpenPorts     []int                  `json:"open_ports"`
	Packages      []map[string]string    `json:"packages"`
	Violations    []map[string]string    `json:"violations"`
	ExtraMetadata map[string]interface{} `json:"meta,omitempty"`
}

// SendComplianceReport sends a compliance report to Slack
func (s *SlackClient) SendComplianceReport(report ComplianceReport) error {
	if s.config.WebhookURL == "" {
		return fmt.Errorf("SLACK_WEBHOOK_URL not configured")
	}

	// Determine message color based on violations
	color := "good" // green
	if len(report.Violations) > 0 {
		if len(report.Violations) > 10 {
			color = "danger" // red
		} else {
			color = "warning" // yellow
		}
	}

	// Create summary text
	summaryText := fmt.Sprintf("📊 *Compliance Report* for `%s`", report.Hostname)
	if len(report.Violations) > 0 {
		summaryText += fmt.Sprintf(" - ⚠️ *%d violations detected*", len(report.Violations))
	} else {
		summaryText += " - ✅ *No violations detected*"
	}

	// Create fields for the attachment
	fields := []Field{
		{
			Title: "🕐 Generated At",
			Value: report.GeneratedAt.Format("2006-01-02 15:04:05 UTC"),
			Short: true,
		},
		{
			Title: "🖥️ Hostname",
			Value: report.Hostname,
			Short: true,
		},
		{
			Title: "👥 Users",
			Value: fmt.Sprintf("%d", len(report.Users)),
			Short: true,
		},
		{
			Title: "⚙️ Processes",
			Value: fmt.Sprintf("%d", len(report.Processes)),
			Short: true,
		},
		{
			Title: "🔌 Open Ports",
			Value: fmt.Sprintf("%d", len(report.OpenPorts)),
			Short: true,
		},
		{
			Title: "📦 Packages",
			Value: fmt.Sprintf("%d", len(report.Packages)),
			Short: true,
		},
	}

	// Add violations summary if any
	if len(report.Violations) > 0 {
		violationSummary := s.createViolationSummary(report.Violations)
		fields = append(fields, Field{
			Title: "⚠️ Violations Summary",
			Value: violationSummary,
			Short: false,
		})
	}

	// Create attachment
	attachment := Attachment{
		Color:     color,
		Title:     "Compliance Report Details",
		Text:      "Click 'View Report' to see full details",
		Fields:    fields,
		Timestamp: report.GeneratedAt.Unix(),
	}

	// Add action buttons
	attachment.Actions = []Action{
		{
			Type: "button",
			Text: "View Full Report",
			URL:  "file://compliance_report.json",
			Style: "primary",
		},
	}

	// Create message
	message := SlackMessage{
		Channel:     s.config.Channel,
		Username:    s.config.Username,
		IconEmoji:   s.config.IconEmoji,
		Text:        summaryText,
		Attachments: []Attachment{attachment},
	}

	return s.sendMessage(message)
}

// Action represents a Slack action button
type Action struct {
	Type  string `json:"type"`
	Text  string `json:"text"`
	URL   string `json:"url,omitempty"`
	Style string `json:"style,omitempty"`
}

// createViolationSummary creates a summary of violations by category
func (s *SlackClient) createViolationSummary(violations []map[string]string) string {
	categoryCount := make(map[string]int)
	for _, violation := range violations {
		category := violation["category"]
		if category == "" {
			category = "unknown"
		}
		categoryCount[category]++
	}

	summary := ""
	for category, count := range categoryCount {
		emoji := "⚠️"
		switch category {
		case "user":
			emoji = "👤"
		case "port":
			emoji = "🔌"
		case "package":
			emoji = "📦"
		case "process":
			emoji = "⚙️"
		}
		summary += fmt.Sprintf("%s %s: %d\n", emoji, category, count)
	}

	return summary
}

// SendViolationAlert sends an immediate alert for critical violations
func (s *SlackClient) SendViolationAlert(hostname string, violations []map[string]string) error {
	if s.config.WebhookURL == "" {
		return fmt.Errorf("SLACK_WEBHOOK_URL not configured")
	}

	if len(violations) == 0 {
		return nil // No violations to report
	}

	// Create urgent alert message
	text := fmt.Sprintf("🚨 *CRITICAL COMPLIANCE VIOLATIONS* detected on `%s`", hostname)

	// Group violations by category
	categoryViolations := make(map[string][]map[string]string)
	for _, violation := range violations {
		category := violation["category"]
		if category == "" {
			category = "unknown"
		}
		categoryViolations[category] = append(categoryViolations[category], violation)
	}

	// Create fields for each category
	fields := []Field{}
	for category, vios := range categoryViolations {
		emoji := "⚠️"
		switch category {
		case "user":
			emoji = "👤"
		case "port":
			emoji = "🔌"
		case "package":
			emoji = "📦"
		case "process":
			emoji = "⚙️"
		}

		// Show first few violations for each category
		violationText := ""
		maxShow := 3
		if len(vios) > maxShow {
			violationText = fmt.Sprintf("%d violations (showing first %d):\n", len(vios), maxShow)
		} else {
			violationText = fmt.Sprintf("%d violations:\n", len(vios))
		}

		for i, vio := range vios {
			if i >= maxShow {
				break
			}
			violationText += fmt.Sprintf("• %s\n", vio["message"])
		}

		fields = append(fields, Field{
			Title: fmt.Sprintf("%s %s", emoji, category),
			Value: violationText,
			Short: false,
		})
	}

	// Create attachment
	attachment := Attachment{
		Color:     "danger",
		Title:     "Immediate Action Required",
		Text:      "Review the violations below and take appropriate action",
		Fields:    fields,
		Timestamp: time.Now().Unix(),
	}

	// Create message
	message := SlackMessage{
		Channel:     s.config.Channel,
		Username:    s.config.Username,
		IconEmoji:   ":rotating_light:",
		Text:        text,
		Attachments: []Attachment{attachment},
	}

	return s.sendMessage(message)
}

// sendMessage sends a message to Slack
func (s *SlackClient) sendMessage(message SlackMessage) error {
	jsonData, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}

	resp, err := s.client.Post(s.config.WebhookURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("slack API returned status %d", resp.StatusCode)
	}

	return nil
}

// TestConnection tests the Slack webhook connection
func (s *SlackClient) TestConnection() error {
	if s.config.WebhookURL == "" {
		return fmt.Errorf("SLACK_WEBHOOK_URL not configured")
	}

	testMessage := SlackMessage{
		Channel:   s.config.Channel,
		Username:  s.config.Username,
		IconEmoji: s.config.IconEmoji,
		Text:      "🧪 *Compliance Agent Test* - Connection successful!",
	}

	return s.sendMessage(testMessage)
}
