package llm

import (
	"strings"
)

const (
	Auto      = "auto"
	OpenAI    = "openai"
	Ollama    = "ollama"
	Anthropic = "anthropic"
	GoogleAI  = "googleai"
)

var Names = []string{
	Auto, OpenAI, Ollama, Anthropic, GoogleAI,
}

func IsRateLimit(err error) bool {
	if err == nil {
		return false
	}
	errS := err.Error()
	// OpenAI (2024-07-11):
	// error="API returned unexpected status code: 429: Rate limit reached for gpt-3.5-turbo in organization org-XXXXXXXX on tokens per min (TPM): Limit 60000, Used 40635, Requested 23224. Please try again in 3.858s. Visit https://platform.openai.com/account/rate-limits to learn more."
	//
	// TODO: add more checks (in the langchaingo upstream?)
	return strings.Contains(errS, "status code: 429")
}

func IsTooManyTokens(err error) bool {
	if err == nil {
		return false
	}
	errS := err.Error()
	// OpenAI (2024-07-11):
	// error="API returned unexpected status code: 400: This model's maximum context length is 16385 tokens. However, your messages resulted in 29138 tokens. Please reduce the length of the messages."
	//
	// TODO: add more checks (in the langchaingo upstream?)
	return strings.Contains(errS, "status code: 400")
}
