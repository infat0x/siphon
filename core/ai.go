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
	apiKey := strings.TrimSpace(os.Getenv("AI_API_KEY"))
	if apiKey == "" {
		Logf("\n  %s[AI]%s No AI_API_KEY found in .env. Skipping AI analysis.\n", RED, RESET)
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
Your ONLY objective is to act as a STRICT FILTER.

# INSTRUCTIONS
1. Analyze the provided findings and rigorously discard ALL false positives (ASCII art, terminal escape sequences, dummy passwords, example API keys, public keys, tool metadata).
2. ONLY if you find a verified, high-risk True Positive (like a live AWS key, Stripe token, Database URI, or JWT), report it.
3. If there are NO TRUE POSITIVES AT ALL, your output must be EXACTLY the phrase: NO_SECRETS_FOUND
   Do not add ANY other text, summaries, headers, or explanations. Just that exact phrase.
4. If there ARE True Positives, output ONLY the true positives in this exact format. Do NOT include any introduction, conclusion, or summary text.

[URL]
Type: [Secret Type]
Match: [The matched string]
Reason: [1 concise sentence on why this is a valid risk]
---`

	modelName := os.Getenv("AI_MODEL")
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
	apiURL := os.Getenv("AI_API_URL")
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
		responseMsg := strings.TrimSpace(aiResp.Choices[0].Message.Content)
		
		if responseMsg == "NO_SECRETS_FOUND" {
			Logf("  %s[AI]%s No true positive secrets were found. All findings were filtered out as noise.\n", GREEN, RESET)
			return // Nothing to save or print
		}

		fmt.Printf("\n")
		fmt.Printf("  %s╭─────────────────────────────────────────────────────────────%s\n", MAGENTA, RESET)
		fmt.Printf("  %s│ %sAI VERIFIED SECRETS%s\n", MAGENTA, BOLD, RESET)
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
				Logf("  %s[AI]%s Verified secrets successfully saved to %s\n", GREEN, RESET, outputFile)
			} else {
				Logf("  %s[AI]%s Failed to save to file: %v\n", RED, RESET, err)
			}
		}
	} else {
		Logf("  %s[AI]%s Received empty response from provider.\n", RED, RESET)
	}
}

// AnalyzeReportFileWithAI reads a report file (JSON or TXT) and sends it to AI.
func AnalyzeReportFileWithAI(filePath string, outputFile string) {
	apiKey := strings.TrimSpace(os.Getenv("AI_API_KEY"))
	if apiKey == "" {
		Logf("\n  %s[AI]%s No AI_API_KEY found in .env. Skipping AI analysis.\n", RED, RESET)
		return
	}

	data, err := os.ReadFile(filePath)
	if err != nil {
		Logf("\n  %s[AI]%s Failed to read report file: %v\n", RED, RESET, err)
		return
	}

	// Try to parse as JSON first
	if strings.HasSuffix(strings.ToLower(filePath), ".json") {
		var report map[string]interface{}
		if err := json.Unmarshal(data, &report); err == nil {
			if findingsRaw, ok := report["findings"]; ok {
				var findings []Finding
				findingsBytes, _ := json.Marshal(findingsRaw)
				json.Unmarshal(findingsBytes, &findings)
				AnalyzeReportWithAI(findings, outputFile)
				return
			}
		}
	}

	// If not JSON or failed to parse JSON, treat as raw text
	Logf("\n  %s[AI]%s Connecting to AI for raw report analysis...\n", MAGENTA, RESET)
	sp := StartSpinner("Analyzing raw report file with AI")

	fileContent := string(data)
	if len(fileContent) > 20000 {
		fileContent = fileContent[:20000] + "\n... [TRUNCATED DUE TO LENGTH]"
	}

	sysPrompt := `You are an elite offensive security engineer reviewing a raw text report generated by a secret scanner.
Your ONLY objective is to act as a STRICT FILTER.

# INSTRUCTIONS
1. Analyze the provided raw report text and rigorously discard ALL false positives.
2. ONLY if you find a verified, high-risk True Positive (like a live AWS key, Stripe token, Database URI, or JWT), report it.
3. If there are NO TRUE POSITIVES AT ALL, your output must be EXACTLY the phrase: NO_SECRETS_FOUND
   Do not add ANY other text, summaries, headers, or explanations. Just that exact phrase.
4. If there ARE True Positives, output ONLY the true positives in this exact format:

[URL]
Type: [Secret Type]
Match: [The matched string]
Reason: [1 concise sentence on why this is a valid risk]
---`

	modelName := os.Getenv("AI_MODEL")
	if modelName == "" {
		modelName = "gpt-4o-mini"
	}

	reqBody := OpenAIRequest{
		Model: modelName,
		Messages: []Message{
			{Role: "system", Content: sysPrompt},
			{Role: "user", Content: "Here is the raw report file content:\n\n" + fileContent},
		},
		Temperature: 0.2,
	}

	jsonData, err := json.Marshal(reqBody)
	if err != nil {
		sp.Fail("Failed to marshal AI request")
		return
	}

	apiURL := os.Getenv("AI_API_URL")
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
		responseMsg := strings.TrimSpace(aiResp.Choices[0].Message.Content)
		
		if responseMsg == "NO_SECRETS_FOUND" {
			Logf("  %s[AI]%s No true positive secrets were found. All findings were filtered out as noise.\n", GREEN, RESET)
			return
		}

		fmt.Printf("\n")
		fmt.Printf("  %s╭─────────────────────────────────────────────────────────────%s\n", MAGENTA, RESET)
		fmt.Printf("  %s│ %sAI VERIFIED SECRETS%s\n", MAGENTA, BOLD, RESET)
		fmt.Printf("  %s├─────────────────────────────────────────────────────────────%s\n", MAGENTA, RESET)
		
		lines := strings.Split(responseMsg, "\n")
		for _, line := range lines {
			fmt.Printf("  %s│%s %s\n", MAGENTA, RESET, line)
		}
		fmt.Printf("  %s╰─────────────────────────────────────────────────────────────%s\n\n", MAGENTA, RESET)

		if outputFile != "" {
			err := os.WriteFile(outputFile, []byte(responseMsg), 0644)
			if err == nil {
				Logf("  %s[AI]%s Verified secrets successfully saved to %s\n", GREEN, RESET, outputFile)
			} else {
				Logf("  %s[AI]%s Failed to save to file: %v\n", RED, RESET, err)
			}
		}
	} else {
		Logf("  %s[AI]%s Received empty response from provider.\n", RED, RESET)
	}
}
