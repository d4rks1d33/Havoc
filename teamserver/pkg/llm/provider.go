package llm

/*
 * provider.go — LLM provider interface and implementations.
 *
 * Supports: Gemini, OpenAI (and compatible: OpenRouter), Anthropic, Ollama.
 * All providers implement the Provider interface with a single Chat() method.
 */

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ── Provider interface ────────────────────────────────────────────────

type Message struct {
	Role    string // "system" | "user" | "assistant"
	Content string
}

type Provider interface {
	// Chat sends a conversation and returns the assistant's reply.
	Chat(messages []Message, maxTokens int) (string, error)
	Name() string
}

// ── HTTP helper ───────────────────────────────────────────────────────

var httpClient = &http.Client{Timeout: 120 * time.Second}

func doPost(url string, headers map[string]string, body any) ([]byte, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", url, bytes.NewReader(b))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, string(data))
	}
	return data, nil
}

// ── NewProvider factory ───────────────────────────────────────────────

func NewProvider(providerName, apiKey, model, baseUrl string) (Provider, error) {
	switch strings.ToLower(providerName) {
	case "gemini":
		return &GeminiProvider{ApiKey: apiKey, Model: model}, nil
	case "openai":
		url := baseUrl
		if url == "" { url = "https://api.openai.com" }
		return &OpenAIProvider{ApiKey: apiKey, Model: model, BaseUrl: url}, nil
	case "anthropic":
		return &AnthropicProvider{ApiKey: apiKey, Model: model}, nil
	case "openrouter":
		url := baseUrl
		if url == "" { url = "https://openrouter.ai/api" }
		return &OpenAIProvider{ApiKey: apiKey, Model: model, BaseUrl: url}, nil
	case "ollama":
		url := baseUrl
		if url == "" { url = "http://localhost:11434" }
		return &OllamaProvider{Model: model, BaseUrl: url}, nil
	default:
		return nil, fmt.Errorf("unknown LLM provider: %q (supported: gemini, openai, anthropic, openrouter, ollama)", providerName)
	}
}

// ── Gemini ────────────────────────────────────────────────────────────

type GeminiProvider struct {
	ApiKey string
	Model  string
}

func (g *GeminiProvider) Name() string { return fmt.Sprintf("Gemini/%s", g.Model) }

func (g *GeminiProvider) Chat(messages []Message, maxTokens int) (string, error) {
	// Gemini uses a different format: system instruction + contents array
	type Part struct {
		Text string `json:"text"`
	}
	type Content struct {
		Role  string `json:"role"` // "user" | "model"
		Parts []Part `json:"parts"`
	}
	type SystemInstruction struct {
		Parts []Part `json:"parts"`
	}
	type Request struct {
		SystemInstruction *SystemInstruction `json:"systemInstruction,omitempty"`
		Contents          []Content          `json:"contents"`
		GenerationConfig  map[string]any     `json:"generationConfig,omitempty"`
	}

	var sysInstruction *SystemInstruction
	var contents []Content

	for _, m := range messages {
		switch m.Role {
		case "system":
			sysInstruction = &SystemInstruction{Parts: []Part{{Text: m.Content}}}
		case "user":
			contents = append(contents, Content{Role: "user", Parts: []Part{{Text: m.Content}}})
		case "assistant":
			contents = append(contents, Content{Role: "model", Parts: []Part{{Text: m.Content}}})
		}
	}

	genConfig := map[string]any{}
	if maxTokens > 0 { genConfig["maxOutputTokens"] = maxTokens }

	req := Request{
		SystemInstruction: sysInstruction,
		Contents:          contents,
		GenerationConfig:  genConfig,
	}

	model := g.Model
	if model == "" { model = "gemini-1.5-pro" }
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
		model, g.ApiKey)

	data, err := doPost(url, nil, req)
	if err != nil { return "", err }

	var result struct {
		Candidates []struct {
			Content struct {
				Parts []struct {
					Text string `json:"text"`
				} `json:"parts"`
			} `json:"content"`
		} `json:"candidates"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil { return "", err }
	if result.Error != nil { return "", fmt.Errorf("Gemini API error: %s", result.Error.Message) }
	if len(result.Candidates) == 0 || len(result.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("Gemini returned no content")
	}
	return result.Candidates[0].Content.Parts[0].Text, nil
}

// ── OpenAI (+ OpenRouter) ─────────────────────────────────────────────

type OpenAIProvider struct {
	ApiKey  string
	Model   string
	BaseUrl string
}

func (o *OpenAIProvider) Name() string { return fmt.Sprintf("OpenAI/%s", o.Model) }

func (o *OpenAIProvider) Chat(messages []Message, maxTokens int) (string, error) {
	type Msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type Request struct {
		Model     string `json:"model"`
		Messages  []Msg  `json:"messages"`
		MaxTokens int    `json:"max_tokens,omitempty"`
	}

	var msgs []Msg
	for _, m := range messages {
		msgs = append(msgs, Msg{Role: m.Role, Content: m.Content})
	}

	req := Request{Model: o.Model, Messages: msgs, MaxTokens: maxTokens}
	url := strings.TrimRight(o.BaseUrl, "/") + "/v1/chat/completions"
	headers := map[string]string{"Authorization": "Bearer " + o.ApiKey}

	data, err := doPost(url, headers, req)
	if err != nil { return "", err }

	var result struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil { return "", err }
	if result.Error != nil { return "", fmt.Errorf("OpenAI API error: %s", result.Error.Message) }
	if len(result.Choices) == 0 { return "", fmt.Errorf("OpenAI returned no choices") }
	return result.Choices[0].Message.Content, nil
}

// ── Anthropic ─────────────────────────────────────────────────────────

type AnthropicProvider struct {
	ApiKey string
	Model  string
}

func (a *AnthropicProvider) Name() string { return fmt.Sprintf("Anthropic/%s", a.Model) }

func (a *AnthropicProvider) Chat(messages []Message, maxTokens int) (string, error) {
	type Msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type Request struct {
		Model     string `json:"model"`
		MaxTokens int    `json:"max_tokens"`
		System    string `json:"system,omitempty"`
		Messages  []Msg  `json:"messages"`
	}

	var systemPrompt string
	var msgs []Msg
	for _, m := range messages {
		if m.Role == "system" { systemPrompt = m.Content; continue }
		msgs = append(msgs, Msg{Role: m.Role, Content: m.Content})
	}
	if maxTokens == 0 { maxTokens = 4096 }

	req := Request{Model: a.Model, MaxTokens: maxTokens, System: systemPrompt, Messages: msgs}
	headers := map[string]string{
		"x-api-key":         a.ApiKey,
		"anthropic-version": "2023-06-01",
	}

	data, err := doPost("https://api.anthropic.com/v1/messages", headers, req)
	if err != nil { return "", err }

	var result struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		Error *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil { return "", err }
	if result.Error != nil { return "", fmt.Errorf("Anthropic API error: %s", result.Error.Message) }
	for _, c := range result.Content {
		if c.Type == "text" { return c.Text, nil }
	}
	return "", fmt.Errorf("Anthropic returned no text content")
}

// ── Ollama ────────────────────────────────────────────────────────────

type OllamaProvider struct {
	Model   string
	BaseUrl string
}

func (o *OllamaProvider) Name() string { return fmt.Sprintf("Ollama/%s", o.Model) }

func (o *OllamaProvider) Chat(messages []Message, maxTokens int) (string, error) {
	type Msg struct {
		Role    string `json:"role"`
		Content string `json:"content"`
	}
	type Request struct {
		Model    string         `json:"model"`
		Messages []Msg          `json:"messages"`
		Stream   bool           `json:"stream"`
		Options  map[string]any `json:"options,omitempty"`
	}

	var msgs []Msg
	for _, m := range messages {
		msgs = append(msgs, Msg{Role: m.Role, Content: m.Content})
	}

	opts := map[string]any{}
	if maxTokens > 0 { opts["num_predict"] = maxTokens }

	req := Request{Model: o.Model, Messages: msgs, Stream: false, Options: opts}
	url := strings.TrimRight(o.BaseUrl, "/") + "/api/chat"

	data, err := doPost(url, nil, req)
	if err != nil { return "", err }

	var result struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Error string `json:"error"`
	}
	if err := json.Unmarshal(data, &result); err != nil { return "", err }
	if result.Error != "" { return "", fmt.Errorf("Ollama error: %s", result.Error) }
	return result.Message.Content, nil
}
