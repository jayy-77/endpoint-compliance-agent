package report

import (
    "encoding/json"
    "os"
    "time"
)

type ComplianceReport struct {
    GeneratedAt   time.Time              `json:"generated_at"`
    Hostname      string                 `json:"hostname"`
    Users         []map[string]string    `json:"users"`
    Processes     []map[string]string    `json:"processes"`
    OpenPorts     []int                  `json:"open_ports"`
    Violations    []map[string]string    `json:"violations"`
    ExtraMetadata map[string]interface{} `json:"meta,omitempty"`
}

func (r *ComplianceReport) ToJSON() ([]byte, error) {
    return json.MarshalIndent(r, "", "  ")
}

func (r *ComplianceReport) SaveToFile(path string) error {
    data, err := r.ToJSON()
    if err != nil {
        return err
    }
    return os.WriteFile(path, data, 0644)
}


