package llmfactory

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/AkihiroSuda/vexllm/pkg/llm"
	"github.com/tmc/langchaingo/llms"
	"github.com/tmc/langchaingo/llms/anthropic"
	"github.com/tmc/langchaingo/llms/googleai"
	"github.com/tmc/langchaingo/llms/ollama"
	"github.com/tmc/langchaingo/llms/openai"
)

// New instantiates an LLM.
// Only tested with "openai".
func New(ctx context.Context, name string) (llms.Model, error) {
	switch name {
	case "", llm.Auto:
		// TODO: add more sophisticated logic
		slog.DebugContext(ctx, "Automatically choosing model", "name", llm.OpenAI)
		name = llm.OpenAI
	}
	switch name {
	case llm.OpenAI:
		return openai.New()
	case llm.Ollama:
		return ollama.New()
	case llm.Anthropic:
		return anthropic.New()
	case llm.GoogleAI:
		return googleai.New(ctx)
	default:
		return nil, fmt.Errorf("unknown LLM %q, make sure to use one of %v", name, llm.Names)
	}
}
