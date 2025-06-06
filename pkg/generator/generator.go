package generator

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/AkihiroSuda/vexllm/pkg/llm"
	"github.com/openvex/go-vex/pkg/vex"
	"github.com/tmc/langchaingo/llms"
)

const (
	DefaultBatchSize        = 10
	DefaultSleepOnRateLimit = 10 * time.Second
	DefaultRetryOnRateLimit = 10
)

type Opts struct {
	LLM         llms.Model
	Temperature float64
	BatchSize   int // Decrease to avoid rate limit
	Seed        int

	SleepOnRateLimit time.Duration
	RetryOnRateLimit int

	Hints Hints

	DebugDir string
}

type Hints struct {
	Descriptions             []string
	Container                bool
	NotServer                bool
	UsedCommands             []string
	UnusedCommands           []string
	CompromiseOnAvailability bool // Focus on Confidentiality and Integrity
}

func New(o Opts) (*Generator, error) {
	g := &Generator{
		o: o,
	}
	if g.o.LLM == nil {
		return nil, errors.New("no model")
	}
	if g.o.BatchSize == 0 {
		g.o.BatchSize = DefaultBatchSize
	}
	if g.o.SleepOnRateLimit == 0 {
		g.o.SleepOnRateLimit = DefaultSleepOnRateLimit
	}
	if g.o.RetryOnRateLimit == 0 {
		g.o.RetryOnRateLimit = DefaultRetryOnRateLimit
	}
	if g.o.DebugDir != "" {
		if err := os.MkdirAll(g.o.DebugDir, 0755); err != nil {
			slog.Error("failed to create the debug dir", "error", err)
			g.o.DebugDir = ""
		}
	}
	return g, nil
}

type Generator struct {
	o Opts
}

type Vulnerability struct {
	VulnID      string `json:"vulnId"`
	PkgID       string `json:"pkgId"`
	Title       string `json:"title"`
	Description string `json:"description,omitempty"`
	Severity    string `json:"severity,omitempty"`
	// TODO: CVSS
}

type llmOutput struct {
	Confidence float64 `json:"confidence"` // 0.0-1.0
	Reason     string  `json:"reason"`
}

const llmOutputExample = `
{
	"CVE-2042-12345": {"confidence": 0.4, "reason": "This DDOS vulnerability is only exploitable in public server programs."},
	"CVE-2042-23456": {"confidence": 0.8, "reason": "The vulnerable package \"foo\" is unlikely used."}
}
`

func retryOnRateLimit(ctx context.Context, interval time.Duration, maxRetry int, fn func(context.Context) error) error {
	var err error
	began := time.Now()
	for i := 0; i < maxRetry; i++ {
		err = fn(ctx)
		if !llm.IsRateLimit(err) {
			return err
		}
		slog.InfoContext(ctx, "Detected rate limit. Sleeping.", "interval", interval, "error", err)
		time.Sleep(interval)
	}
	elapsed := time.Since(began)
	return fmt.Errorf("still hitting rate limit, after retrying %d times in %v: %w", maxRetry, elapsed, err)
}

func (g *Generator) GenerateStatements(ctx context.Context, vulns []Vulnerability, h func([]vex.Statement) error) error {
	batchSize := g.o.BatchSize // TODO: optimize automatically
	for i := 0; i < len(vulns); i += batchSize {
		batch := vulns[i:min(i+batchSize, len(vulns))]
		if err := retryOnRateLimit(ctx, g.o.SleepOnRateLimit, g.o.RetryOnRateLimit,
			func(ctx context.Context) error {
				return g.generateStatements(ctx, batch, h)
			}); err != nil {
			return err
		}
	}
	return nil
}

func (g *Generator) generateStatements(ctx context.Context, vulns []Vulnerability, h func([]vex.Statement) error) error {
	var b bytes.Buffer
	streamingFunc := func(ctx context.Context, batch []byte) error {
		fmt.Fprint(os.Stderr, string(batch)) // Printed for debugging purpose. Do not try to parse this stderr.
		_, err := b.Write(batch)
		return err
	}
	callOpts := []llms.CallOption{
		llms.WithJSONMode(),
		llms.WithStreamingFunc(streamingFunc),
	}
	if g.o.Temperature > 0.0 {
		slog.Debug("Using temperature", "temperature", g.o.Temperature)
		callOpts = append(callOpts, llms.WithTemperature(g.o.Temperature))
	}
	if g.o.Seed != 0 {
		slog.Debug("Using seed", "seed", g.o.Seed)
		callOpts = append(callOpts, llms.WithSeed(g.o.Seed))
	}

	systemPrompt := `You are a security expert talented for triaging vulnerability reports.
You judge whether a vulnerability is likely negligible under the specified hints.

### Hints
`
	for _, f := range g.o.Hints.Descriptions {
		systemPrompt += "* " + f + "\n"
	}
	if g.o.Hints.Container {
		systemPrompt += "* The artifact is a container image. So, kernel-related vulnerabilities are safely negligible.\n"
	}
	if g.o.Hints.NotServer {
		systemPrompt += "* The artifact is not used as a network server program. So, server-specific vulnerabilities are safely negligible.\n"
	}
	if len(g.o.Hints.UsedCommands) > 0 {
		systemPrompt += fmt.Sprintf("* The following shell commands are known to be used: %v\n",
			g.o.Hints.UsedCommands)
	}
	if len(g.o.Hints.UnusedCommands) > 0 {
		systemPrompt += fmt.Sprintf("* The following shell commands are known to be unused and their vulnerabilities are negligible, although these commands might be still present in the artifact: %v\n",
			g.o.Hints.UnusedCommands)
	}
	if g.o.Hints.CompromiseOnAvailability {
		systemPrompt += "* Put solid focus on Confidentiality and Integrity rather than Availability. " +
			"e.g., denial-of-service does not need to be considered as catastrophic as data leakage and modification.\n"
	}

	systemPrompt += `
### Input format:
The input is similar to [Trivy](https://github.com/aquasecurity/trivy)'s JSON, but not exactly same.

### Output format
If you find negligible vulnerabilities, print a JSON map formatted and indented as follows:
`
	systemPrompt += "```json\n" + llmOutputExample + "\n```\n"
	systemPrompt += "* `confidence` (0.0-1.0): higher value if you are confident with the answer.\n"
	systemPrompt += "* `reason`: the reason why you think the vulnerability is negligible. Should be unique, descriptive, and in 2 or 3 sentences.\n"
	systemPrompt += "Do not include non-negligible vulnerabilities in the result.\n"
	systemPrompt += "Only print a valid JSON.\n"

	vulnsMap := make(map[string]Vulnerability)
	for _, f := range vulns {
		vulnsMap[f.VulnID] = f
	}
	vulnsJSON, err := json.Marshal(vulns)
	if err != nil {
		return err
	}
	humanPrompt := string(vulnsJSON)

	msgs := []llms.MessageContent{
		llms.TextParts(llms.ChatMessageTypeSystem, systemPrompt),
		llms.TextParts(llms.ChatMessageTypeHuman, humanPrompt),
	}

	if g.o.DebugDir != "" {
		if err := os.WriteFile(filepath.Join(g.o.DebugDir, "system.prompt"), []byte(systemPrompt), 0644); err != nil {
			slog.ErrorContext(ctx, "failed to write system.prompt", "error", err)
		}
		if err := os.WriteFile(filepath.Join(g.o.DebugDir, "human.prompt"), []byte(humanPrompt), 0644); err != nil {
			slog.ErrorContext(ctx, "failed to write human.prompt", "error", err)
		}
	}

	if _, err = g.o.LLM.GenerateContent(ctx, msgs, callOpts...); err != nil {
		return err
	}

	var m map[string]llmOutput
	if err = json.Unmarshal(b.Bytes(), &m); err != nil {
		return fmt.Errorf("unparsable JSON output from LLM: %w: %q", err, b.String())
	}

	var stmts []vex.Statement
	for k, v := range m {
		vv, err := json.Marshal(v)
		if err != nil {
			return err
		}
		desc := vulnsMap[k].Title
		if d := vulnsMap[k].Description; d != "" {
			desc = d
		}
		stmt := vex.Statement{
			Vulnerability: vex.Vulnerability{
				ID:          k,
				Description: desc,
			},
			Products: []vex.Product{
				{
					Component: vex.Component{
						ID: vulnsMap[k].PkgID,
					},
				},
			},
			Status:          vex.StatusNotAffected,
			Justification:   vex.VulnerableCodeNotInExecutePath,
			ImpactStatement: string(vv),
		}
		stmts = append(stmts, stmt)
	}

	return h(stmts)
}
