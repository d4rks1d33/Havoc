package llm

/*
 * agent.go — Autonomous LLM agent that controls a Havoc agent.
 *
 * The agent receives a goal from the operator, then iteratively:
 *   1. Asks the LLM what to do next
 *   2. Parses the LLM's response for a command to run
 *   3. Executes the command on the target via the C2
 *   4. Feeds the output back to the LLM
 *   5. Repeats until the LLM declares the goal complete or max steps reached
 *
 * The LLM communicates using a simple JSON tool-call protocol:
 *
 *   To run a command:
 *   {"action": "execute", "command": "shell whoami", "reasoning": "..."}
 *
 *   To report completion:
 *   {"action": "done", "summary": "Gathered: username=root, ..."}
 *
 *   To report failure:
 *   {"action": "error", "summary": "Could not achieve goal because ..."}
 */

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// ── Types ─────────────────────────────────────────────────────────────

// ExecuteFunc is called by the agent to run a command on the target.
// It returns the command output as a string.
type ExecuteFunc func(command string) (string, error)

// OutputFunc is called to stream progress back to the operator console.
// msgType is "Info", "Good", "Error", or "Warn".
type OutputFunc func(msgType, message string)

// AgentConfig configures the LLM agent run.
type AgentConfig struct {
	Provider  Provider
	MaxSteps  int
	MaxTokens int
	Goal      string
	AgentOS   string // e.g. "Windows 10 x64", "Android 14 (API 34)", "Linux 5.15"
	AgentUser string // e.g. "DOMAIN\\user" or "user"
	AgentHost string // hostname
}

// ── System prompt ─────────────────────────────────────────────────────

const systemPromptTemplate = `You are an autonomous security research agent with shell access to a target machine.

TARGET INFORMATION:
- Hostname: %s
- OS: %s
- User: %s

YOUR GOAL: %s

INSTRUCTIONS:
- You have full shell access to the target machine via the C2 framework.
- At each step, decide what command to run to make progress toward your goal.
- Be systematic and thorough. Collect information incrementally.
- After each command output, analyze what you learned and decide the next step.
- When you have achieved the goal, report a summary of your findings.
- Keep commands concise and non-destructive unless explicitly instructed otherwise.
- Do NOT run commands that could damage the system or delete data unless the goal requires it.
- Available commands: shell <cmd>, dir/ls <path>, download <file>, upload <src> <dst>, ps, whoami, sleep <s>, exit
- IMPORTANT: To run ANY command, you MUST prefix it with "shell". Examples:
  * shell whoami
  * shell ipconfig /all
  * shell hostname
  * shell net user
  Never write just "whoami" or "hostname" — always "shell whoami", "shell hostname", etc.

RESPONSE FORMAT (STRICT JSON — no markdown, no explanation outside the JSON):

To execute a command:
{"action":"execute","command":"<havoc_command>","reasoning":"<why_you_chose_this>"}

To declare success:
{"action":"done","summary":"<what_you_found_and_accomplished>"}

To declare failure:
{"action":"error","summary":"<why_you_could_not_complete_the_goal>"}

Always respond with ONLY the JSON object, nothing else.`

// ── Main agent loop ───────────────────────────────────────────────────

// Run executes the autonomous LLM agent loop.
// It returns a final summary string.
func Run(cfg AgentConfig, execute ExecuteFunc, output OutputFunc) string {
	maxSteps := cfg.MaxSteps
	if maxSteps <= 0 { maxSteps = 20 }
	maxTokens := cfg.MaxTokens
	if maxTokens <= 0 { maxTokens = 4096 }

	sysPrompt := fmt.Sprintf(systemPromptTemplate,
		cfg.AgentHost, cfg.AgentOS, cfg.AgentUser, cfg.Goal)

	output("Info", fmt.Sprintf("[LLM:%s] Starting autonomous agent", cfg.Provider.Name()))
	output("Info", fmt.Sprintf("[LLM] Goal: %s", cfg.Goal))

	messages := []Message{
		{Role: "system", Content: sysPrompt},
		{Role: "user", Content: fmt.Sprintf("Begin. Your goal is: %s\n\nStart by gathering basic reconnaissance information.", cfg.Goal)},
	}

	for step := 1; step <= maxSteps; step++ {
		output("Info", fmt.Sprintf("[LLM] Step %d/%d — asking %s...", step, maxSteps, cfg.Provider.Name()))

		// Ask the LLM
		reply, err := cfg.Provider.Chat(messages, maxTokens)
		if err != nil {
			output("Error", fmt.Sprintf("[LLM] Provider error: %v", err))
			time.Sleep(2 * time.Second) // brief backoff
			continue
		}

		// Parse the LLM's response
		action, command, reasoning, summary := parseResponse(reply)

		switch action {
		case "execute":
			output("Info", fmt.Sprintf("[LLM] Reasoning: %s", reasoning))
			output("Info", fmt.Sprintf("[LLM] Executing: %s", command))

			// Run the command
			cmdOutput, execErr := execute(command)
			if execErr != nil {
				cmdOutput = fmt.Sprintf("[!] Execution error: %v", execErr)
				output("Warn", fmt.Sprintf("[LLM] Command error: %v", execErr))
			} else {
				// Truncate very long outputs
				if len(cmdOutput) > 8192 {
					cmdOutput = cmdOutput[:8192] + "\n[...output truncated at 8192 chars]"
				}
				output("Good", fmt.Sprintf("[LLM] Output (%d bytes):\n%s", len(cmdOutput), cmdOutput))
			}

			// Add to conversation
			messages = append(messages,
				Message{Role: "assistant", Content: reply},
				Message{Role: "user", Content: fmt.Sprintf("Command output:\n```\n%s\n```\n\nContinue toward the goal.", cmdOutput)},
			)

		case "done":
			output("Good", fmt.Sprintf("[LLM] Goal achieved after %d steps!", step))
			output("Good", fmt.Sprintf("[LLM] Summary: %s", summary))
			return summary

		case "error":
			output("Error", fmt.Sprintf("[LLM] Agent could not complete goal: %s", summary))
			return fmt.Sprintf("[FAILED] %s", summary)

		default:
			// LLM returned something unexpected — try to extract a command anyway
			output("Warn", fmt.Sprintf("[LLM] Unexpected response format, attempting recovery: %s", reply[:min(200, len(reply))]))
			messages = append(messages,
				Message{Role: "assistant", Content: reply},
				Message{Role: "user", Content: `Please respond with ONLY a JSON object in this exact format: {"action":"execute","command":"<cmd>","reasoning":"<why>"} or {"action":"done","summary":"<findings>"}`},
			)
		}

		// Small delay to avoid rate limiting
		time.Sleep(500 * time.Millisecond)
	}

	msg := fmt.Sprintf("[LLM] Reached maximum steps (%d) without completing goal", maxSteps)
	output("Warn", msg)
	return msg
}

// ── Response parser ───────────────────────────────────────────────────

var jsonBlockRe = regexp.MustCompile("(?s)```(?:json)?\\s*({.+?})\\s*```")
var jsonRawRe   = regexp.MustCompile("(?s)({\\s*\"action\"[^}]+})")

func parseResponse(raw string) (action, command, reasoning, summary string) {
	raw = strings.TrimSpace(raw)

	// Try to extract JSON from markdown code block first
	if m := jsonBlockRe.FindStringSubmatch(raw); len(m) > 1 {
		raw = m[1]
	} else if m := jsonRawRe.FindStringSubmatch(raw); len(m) > 1 {
		raw = m[1]
	}

	var obj map[string]string
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		// Couldn't parse — return unknown action
		return "unknown", "", "", raw
	}

	action    = obj["action"]
	command   = obj["command"]
	reasoning = obj["reasoning"]
	summary   = obj["summary"]
	return
}

func min(a, b int) int {
	if a < b { return a }
	return b
}
