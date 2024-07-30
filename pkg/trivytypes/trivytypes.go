// Package trivytypes provides a subset of https://pkg.go.dev/github.com/aquasecurity/trivy@v0.53.0/pkg/types
package trivytypes

type Report struct {
	SchemaVersion int      `json:",omitempty"`
	ArtifactName  string   `json:",omitempty"`
	ArtifactType  string   `json:",omitempty"`
	Results       []Result `json:",omitempty"`
}

type Result struct {
	Target          string          `json:",omitempty"`
	Class           string          `json:",omitempty"`
	Type            string          `json:",omitempty"`
	Vulnerabilities []Vulnerability `json:",omitempty"`
}

type Vulnerability struct {
	VulnerabilityID string         `json:",omitempty"`
	PkgID           string         `json:",omitempty"`
	Title           string         `json:",omitempty"`
	Description     string         `json:",omitempty"`
	Severity        string         `json:",omitempty"`
	CweIDs          []string       `json:",omitempty"`
	VendorSeverity  map[string]int `json:",omitempty"`
	// TODO: CVSS
}
