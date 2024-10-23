package generate

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/AkihiroSuda/vexllm/pkg/generator"
	"github.com/AkihiroSuda/vexllm/pkg/llm"
	"github.com/AkihiroSuda/vexllm/pkg/llm/llmfactory" // FIXME: dependency monster
	"github.com/AkihiroSuda/vexllm/pkg/outputhandler"
	"github.com/AkihiroSuda/vexllm/pkg/trivypluginutil"
	"github.com/AkihiroSuda/vexllm/pkg/trivytypes"
	"github.com/spf13/cobra"
)

func Example() string {
	exe := "vexllm"
	if trivypluginutil.IsTrivyPluginMode() {
		exe = "trivy " + exe
	}
	return fmt.Sprintf(`  # Basic usage
  export OPENAI_API_KEY=...

  trivy image python:3.12.4 --format=json --severity HIGH,CRITICAL >python.json

  %s generate python.json .trivyignore \
    --hint-not-server \
    --hint-compromise-on-availability \
    --hint-used-commands=python3 \
    --hint-unused-commands=git,wget,curl,apt,apt-get

  trivy convert --format=table python.json
`, exe)
}

func New() *cobra.Command {
	cmd := &cobra.Command{
		Use:                   "generate INPUT OUTPUT",
		Short:                 "Generate VEX using LLM",
		Long:                  "Generate Vulnerability-Exploitability eXchange (VEX) information using LLM, so as to silence negligible CVE alerts that are produced by Trivy.",
		Example:               Example(),
		Args:                  cobra.ExactArgs(2),
		RunE:                  action,
		DisableFlagsInUseLine: true,
	}
	flags := cmd.Flags()
	flags.String("llm", llm.Auto, fmt.Sprintf("LLM backend (%v)", llm.Names))
	flags.Float64("llm-temperature", generator.DefaultTemperature, "Temperature")
	flags.Int("llm-batch-size", generator.DefaultBatchSize, "Number of vulnerabilities to be processed in a single LLM API call")
	flags.String("input-format", "auto", "Input format ([auto trivy])")
	flags.String("output-format", "auto", "Output format ([auto trivyignore openvex])")
	flags.StringArray("hint", nil, "Hint, as an arbitrary text") // StringArray retains comma symbols
	flags.Bool("hint-not-server", false, "Hint: not a server program")
	flags.StringSlice("hint-used-commands", nil, "Hint: list of used shell commands")
	flags.StringSlice("hint-unused-commands", nil, "Hint: list of unused shell commands")
	flags.Bool("hint-compromise-on-availability", false,
		"Hint: focus on Confidentiality and Integrity rather than on Availability")
	flags.String("debug-dir", "", "Directory to dump debug info")
	return cmd
}

func action(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	flags := cmd.Flags()

	inputPath, outputPath := args[0], args[1]
	inputFormat, err := flags.GetString("input-format")
	if err != nil {
		return err
	}
	switch inputFormat {
	case "", "auto":
		inputFormat = "trivy"
		slog.DebugContext(ctx, "Automatically choosing input format", "format", inputFormat)
	}
	switch inputFormat {
	case "trivy":
		// NOP
	default:
		return fmt.Errorf("unknown input format %q", inputFormat)
	}
	inputB, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	var input trivytypes.Report
	if err = json.Unmarshal(inputB, &input); err != nil {
		return err
	}

	var h outputhandler.OutputHandler
	outputW, err := os.Create(outputPath)
	if err != nil {
		return err
	}
	defer outputW.Close()
	outputFormat, err := flags.GetString("output-format")
	if err != nil {
		return err
	}
	switch outputFormat {
	case "", "auto":
		outputFormat = "openvex"
		if strings.Contains(outputPath, "trivyignore") {
			outputFormat = "trivyignore"
		}
		slog.DebugContext(ctx, "Automatically choosing output format", "format", outputFormat)
	}
	switch outputFormat {
	case "trivyignore":
		h = outputhandler.NewTrivyignoreOutputHandler(outputW)
	case "openvex":
		h = outputhandler.NewOpenvexOutputHandler(outputW)
	default:
		return fmt.Errorf("unknown output format %q", outputFormat)
	}
	defer h.Close()

	var o generator.Opts
	llmName, err := flags.GetString("llm")
	if err != nil {
		return err
	}
	o.LLM, err = llmfactory.New(ctx, llmName)
	if err != nil {
		return err
	}
	o.Temperature, err = flags.GetFloat64("llm-temperature")
	if err != nil {
		return err
	}
	o.BatchSize, err = flags.GetInt("llm-batch-size")
	if err != nil {
		return err
	}
	o.Hints.Descriptions = []string{
		fmt.Sprintf("Artifact type: %q", input.ArtifactType),
		fmt.Sprintf("Artifact name: %q", input.ArtifactName),
	}
	hints, err := flags.GetStringArray("hint")
	if err != nil {
		return err
	}
	o.Hints.Descriptions = append(o.Hints.Descriptions, hints...)
	if input.ArtifactType == "container_image" {
		o.Hints.Container = true
	}
	o.Hints.NotServer, err = flags.GetBool("hint-not-server")
	if err != nil {
		return err
	}
	o.Hints.UsedCommands, err = flags.GetStringSlice("hint-used-commands")
	if err != nil {
		return err
	}
	o.Hints.UnusedCommands, err = flags.GetStringSlice("hint-unused-commands")
	if err != nil {
		return err
	}
	o.Hints.CompromiseOnAvailability, err = flags.GetBool("hint-compromise-on-availability")
	if err != nil {
		return err
	}
	o.DebugDir, err = flags.GetString("debug-dir")
	if err != nil {
		return err
	}
	g, err := generator.New(o)
	if err != nil {
		return err
	}

	vulns := make([]generator.Vulnerability, len(input.Results[0].Vulnerabilities))
	for i, f := range input.Results[0].Vulnerabilities {
		vulns[i] = generator.Vulnerability{
			VulnID:      f.VulnerabilityID,
			PkgID:       f.PkgID,
			Title:       f.Title,
			Description: f.Description,
			Severity:    f.Severity,
			// TODO: CVSS
		}
	}
	if err = g.GenerateStatements(ctx, vulns, h.HandleStatements); err != nil {
		return err
	}
	return h.Close()
}
