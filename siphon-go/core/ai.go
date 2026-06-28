package core

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenAIRequest represents the payload for the Chat Completions API.
type OpenAIRequest struct {
	Model       string    `json:"model"`
	Messages    []Message `json:"messages"`
	Temperature float32   `json:"temperature"`
	MaxTokens   int       `json:"max_tokens,omitempty"`
}

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// OpenAIResponse parses the returned JSON from the API.
type OpenAIResponse struct {
	Choices []struct {
		Message Message `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

// AnalyzeReportWithAI reads the generated findings and asks an AI model to evaluate them.
func AnalyzeReportWithAI(findings []Finding, outputFile string) {
	apiKey := os.Getenv("OPENAI_API_KEY")
	if apiKey == "" {
		Logf("\n  %s[AI]%s No OPENAI_API_KEY found in .env. Skipping AI analysis.\n", RED, RESET)
		return
	}

	if len(findings) == 0 {
		Logf("\n  %s[AI]%s No findings to analyze.\n", YELLOW, RESET)
		return
	}

	Logf("\n  %s[AI]%s Connecting to AI for report analysis...\n", MAGENTA, RESET)
	sp := StartSpinner("Analyzing report with AI")

	// Limit findings if there are too many, to avoid exceeding context limits.
	maxFindings := 50
	analyzeSlice := findings
	if len(findings) > maxFindings {
		analyzeSlice = findings[:maxFindings]
	}

	var findingsText strings.Builder
	for i, f := range analyzeSlice {
		findingsText.WriteString(fmt.Sprintf("[%d] Tool: %s | Type: %s | URL: %s\nMatch: %s\nSeverity: %s | Confidence: %d\n---\n",
			i+1, f.Tool, f.Type, f.URL, f.Match, f.Severity, f.Confidence))
	}
	if len(findings) > maxFindings {
		findingsText.WriteString(fmt.Sprintf("\n... and %d more findings omitted to fit context.", len(findings)-maxFindings))
	}

	sysPrompt := `You are an elite offensive security engineer and bug bounty hunter reviewing the output of an automated JavaScript secret scanner (Siphon). 
Your objective is to deeply analyze the provided findings, filter out ALL noise, and deliver a highly structured, accurate, and actionable security report.

# RULES
1. Strict False Positive Filtering: IGNORE obviously fake or placeholder values (e.g., "123456", "example.com", "YOUR_API_KEY", "XXXX").
2. IGNORE ASCII Art and Terminal Codes: Do NOT report block-style ASCII art (e.g., ███╗) or ANSI color/terminal escape sequences (e.g., [Coded by Brosck], [-] Send URLs). These are NOT secrets. DO NOT LIST THEM individually.
3. Priority Focus: Highlight ONLY critical secrets (e.g., AWS keys, Stripe tokens, RSA private keys, JWTs, database credentials).
4. Context Awareness: Take the URL and the type of the secret into consideration. A secret in a source map (.js.map) or an environment file (.env) is highly critical.
5. Professional Tone: Use a clinical, professional, and confident tone. No emojis.
6. No Hallucinations: Base your analysis *only* on the provided findings. If there are no critical findings, clearly state that the targets appear clean.

# REQUIRED OUTPUT FORMAT
You MUST format your response exactly according to the following structure:

### 1. Executive Summary
Provide a 2-3 sentence high-level overview. If no valid secrets were found, explicitly state "No high-risk secrets were detected." DO NOT describe the noise (ASCII art, terminal sequences) in detail here.

### 2. High-Risk Findings (True Positives)
List ONLY the findings that have a high probability of being valid and exploitable. For each valid finding, you MUST explicitly provide:
- **Secret Type:** (e.g. AWS Key, Stripe Token)
- **Match:** The snippet of the secret that was found
- **Location (URL):** Where it was found
- **Explanation:** Provide a detailed 1-2 sentence explanation of *why* this specific match is valid (e.g., "The entropy and format match a live production key", "It is located inside a production .env file").
- **Risk Impact:** What an attacker could do with this.

If there are NO True Positives, simply write: "**None.** No valid secrets, credentials, or sensitive data were identified."

### 3. False Positives & Low-Risk Noise
Do NOT list every single false positive. Provide a SINGLE BRIEF paragraph explaining what kind of noise was filtered out (e.g., "Filtered out X matches containing ASCII art, tool metadata, and terminal escape sequences.").

### 4. Actionable Recommendations
Provide concrete steps for the security team based ONLY on the True Positives. If no True Positives were found, provide a single generic recommendation about maintaining secret hygiene.`

	modelName := os.Getenv("OPENAI_MODEL")
	if modelName == "" {
		modelName = "gpt-4o-mini"
	}

	reqBody := OpenAIRequest{
		Model: modelName,
		Messages: []Message{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: "Here are the secret scanner findings:\n\n" + findingsText.String()},
		},
		Temperature: 0.2, // Lower temperature for more analytical and deterministic output
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		sp.Fail("Failed to marshal AI request")
		return
	}

	// Assuming standard OpenAI endpoint, can be swapped via an env variable if necessary.
	apiURL := os.Getenv("OPENAI_API_URL")
	if apiURL == "" {
		apiURL = "https://api.openai.com/v1/chat/completions"
	}

	req, err := http.NewRequest("POST", apiURL, bytes.NewBuffer(jsonData))
	if err != nil {
		sp.Fail("Failed to create AI request")
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+apiKey)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		sp.Fail("Failed to contact AI provider")
		return
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != 200 {
		sp.Fail("AI Provider returned error code: " + fmt.Sprint(resp.StatusCode))
		Logf("\n  %s[AI ERR]%s %s\n", RED, RESET, string(bodyBytes))
		return
	}

	var aiResp OpenAIResponse
	if err := json.Unmarshal(bodyBytes, &aiResp); err != nil {
		sp.Fail("Failed to parse AI response")
		return
	}

	if aiResp.Error != nil {
		sp.Fail("AI Error: " + aiResp.Error.Message)
		return
	}

	sp.Success("AI Analysis complete")

	if len(aiResp.Choices) > 0 {
		responseMsg := aiResp.Choices[0].Message.Content
		
		fmt.Printf("\n")
		fmt.Printf("  %s╭─────────────────────────────────────────────────────────────%s\n", MAGENTA, RESET)
		fmt.Printf("  %s│ %sAI SECURITY SUMMARY%s\n", MAGENTA, BOLD, RESET)
		fmt.Printf("  %s├─────────────────────────────────────────────────────────────%s\n", MAGENTA, RESET)
		
		// Print line by line for clean formatting
		lines := strings.Split(responseMsg, "\n")
		for _, line := range lines {
			fmt.Printf("  %s│%s %s\n", MAGENTA, RESET, line)
		}
		fmt.Printf("  %s╰─────────────────────────────────────────────────────────────%s\n\n", MAGENTA, RESET)

		// Save to file
		if outputFile != "" {
			err := os.WriteFile(outputFile, []byte(responseMsg), 0644)
			if err == nil {
				Logf("  %s[AI]%s Summary successfully saved to %s\n", GREEN, RESET, outputFile)
			} else {
				Logf("  %s[AI]%s Failed to save summary to file: %v\n", RED, RESET, err)
			}
		}
	} else {
		Logf("  %s[AI]%s Received empty response from provider.\n", RED, RESET)
	}
}
