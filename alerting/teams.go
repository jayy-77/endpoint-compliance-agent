package alerting

import (
	"bytes"
	"encoding/json"
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

// TO BE Compatible with Teams actionalbe message card
type TeamsMessage struct {
	Type       string         `json:"@type"`
	Context    string         `json:"@context"`
	ThemeColor string         `json:"themeColor,omitempty"`
	Summary    string         `json:"summary"`
	Title      string         `json:"title,omitempty"`
	Text       string         `json:"text,omitempty"`
	Sections   []TeamsSection `json:"sections,omitempty"`
	Actions    []TeamsAction  `json:"potentialAction,omitempty"`
}

type TeamsSection struct {
	ActivityTitle    string      `json:"activityTitle,omitempty"`
	ActivitySubtitle string      `json:"activitySubtitle,omitempty"`
	ActivityImage    string      `json:"activityImage,omitempty"`
	Text             string      `json:"text,omitempty"`
	Facts            []TeamsFact `json:"facts,omitempty"`
}
type TeamsFact struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type TeamsAction struct {
	Type    string              `json:"@type"`
	Name    string              `json:"name"`
	Targets []TeamsActionTarget `json:"targets"`
}

type TeamsActionTarget struct {
	OS  string `json:"os"`
	URI string `json:"uri"`
}

func (t *TeamsClient) SendComplianceReport(report ComplianceReport) error {
	if t.config.WebhookURL == "" {
		return fmt.Errorf("TEAMS_WEBHOOK_URL not configured")
	}

	themeColor := "00FF00" // green
	if len(report.Violations) > 0 {
		if len(report.Violations) > 10 {
			themeColor = "FF0000" // red
		} else {
			themeColor = "FFA500" // orange
		}
	}

	// Build the message card
	summaryText := fmt.Sprintf("Compliance Report for %s", report.Hostname)
	titleText := "📊 Compliance Report"
	if len(report.Violations) > 0 {
		titleText += fmt.Sprintf(" - ⚠️ %d violations detected", len(report.Violations))
	} else {
		titleText += " - ✅ No violations detected"
	}
	// Create facts for the main section
	facts := []TeamsFact{
		{
			Name:  "🕐 Generated At",
			Value: report.GeneratedAt.Format("2006-01-02 15:04:05 UTC"),
		},
		{
			Name:  "🖥️ Hostname",
			Value: report.Hostname,
		},
		{
			Name:  "👥 Users",
			Value: fmt.Sprintf("%d", len(report.Users)),
		},
		{
			Name:  "⚙️ Processes",
			Value: fmt.Sprintf("%d", len(report.Processes)),
		},
		{
			Name:  "🔌 Open Ports",
			Value: fmt.Sprintf("%d", len(report.OpenPorts)),
		},
		{
			Name:  "📦 Packages",
			Value: fmt.Sprintf("%d", len(report.Packages)),
		},
	}
	sections := []TeamsSection{
		{
			ActivityTitle:    "Compliance Report Details",
			ActivitySubtitle: report.GeneratedAt.Format("2006-01-02 15:04:05 UTC"),
			Facts:            facts,
		},
	}
	if len(report.Violations) > 0 {
		violationText := t.createViolationSummary(report.Violations)
		sections = append(sections, TeamsSection{
			ActivityTitle: "⚠️ Violations Summary",
			Text:          violationText,
		})
	}
	message := TeamsMessage{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		ThemeColor: themeColor,
		Summary:    summaryText,
		Title:      titleText,
		Sections:   sections,
	}
	return t.sendMessage(message)
}

func (t *TeamsClient) createViolationSummary(violations []map[string]string) string {
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
		summary += fmt.Sprintf("%s %s: %d\n\n", emoji, category, count)
	}

	return summary
}

// SendViolationAlert sends an immediate alert for critical violations
func (t *TeamsClient) SendViolationAlert(hostname string, violations []map[string]string) error {
	if t.config.WebhookURL == "" {
		return fmt.Errorf("TEAMS_WEBHOOK_URL not configured")
	}

	if len(violations) == 0 {
		return nil // No violations to report
	}

	// Create urgent alert message
	titleText := fmt.Sprintf("🚨 CRITICAL COMPLIANCE VIOLATIONS detected on %s", hostname)

	// Group violations by category
	categoryViolations := make(map[string][]map[string]string)
	for _, violation := range violations {
		category := violation["category"]
		if category == "" {
			category = "unknown"
		}
		categoryViolations[category] = append(categoryViolations[category], violation)
	}

	// Create sections for each category
	sections := []TeamsSection{}
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
			violationText = fmt.Sprintf("%d violations (showing first %d):\n\n", len(vios), maxShow)
		} else {
			violationText = fmt.Sprintf("%d violations:\n\n", len(vios))
		}

		for i, vio := range vios {
			if i >= maxShow {
				break
			}
			violationText += fmt.Sprintf("• %s\n\n", vio["message"])
		}

		sections = append(sections, TeamsSection{
			ActivityTitle: fmt.Sprintf("%s %s", emoji, category),
			Text:          violationText,
		})
	}

	// Create message
	message := TeamsMessage{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		ThemeColor: "FF0000", // red for critical
		Summary:    fmt.Sprintf("Critical violations on %s", hostname),
		Title:      titleText,
		Text:       "Immediate Action Required - Review the violations below and take appropriate action",
		Sections:   sections,
	}

	return t.sendMessage(message)
}

func (t *TeamsClient) sendMessage(message TeamsMessage) error {
	jsonMessage, err := json.Marshal(message)
	if err != nil {
		return fmt.Errorf("failed to marshal message: %w", err)
	}
	resp, err := t.client.Post(t.config.WebhookURL, "application/json", bytes.NewBuffer(jsonMessage))
	if err != nil {
		return fmt.Errorf("failed to send message: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("TEAMS WEBHOOK returned status %d", resp.StatusCode)
	}
	return nil
}
func (t *TeamsClient) TestConnection() error {
	if t.config.WebhookURL == "" {
		return fmt.Errorf("TEAMS_WEBHOOK_URL not configured")
	}
	testMessage := TeamsMessage{
		Type:       "MessageCard",
		Context:    "https://schema.org/extensions",
		ThemeColor: "0078D4",
		Summary:    "Compliance Agent Test",
		Title:      "🧪 Compliance Agent Test",
		Text:       "Connection successful!",
	}

	return t.sendMessage(testMessage)
}
