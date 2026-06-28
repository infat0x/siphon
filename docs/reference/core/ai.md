# AI Engine (`core/ai.go`)

The `ai.go` module integrates advanced Large Language Models (LLMs), specifically OpenAI's GPT models, into the Siphon pipeline to act as the ultimate false-positive filter.

## Overview

Automated secret scanners often generate a high volume of false positives. Strings that look like high-entropy base64 strings might actually be CSS hashes, random identifiers, or benign data.

Siphon solves this by feeding the raw findings into an AI model with a strictly engineered system prompt.

> [!NOTE]
> The AI integration is entirely optional. It only runs if an `AI_API_KEY` is present in the `.env` file and the user explicitly types `y` or `yes` when prompted at the end of the scan.

## System Prompt Engineering

The true power of this module lies in the prompt injected into the AI model. It enforces strict compliance and prevents the model from generating conversational fluff.

```go
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
```

> [!TIP]
> Notice the instruction `NO_SECRETS_FOUND`. This allows Siphon to programmatically detect when the AI considers the entire report to be noise without parsing complex JSON responses.

## Request Execution

The `AnalyzeReportWithAI` function handles marshaling the findings, capping the payload size (to prevent token limit errors), and transmitting the request to the specified `AI_API_URL`.

```go
reqBody := OpenAIRequest{
    Model: modelName, // Usually gpt-4o-mini
    Messages: []Message{
        {Role: "system", Content: sysPrompt},
        {Role: "user", Content: "Here are the secret scanner findings:\n\n" + findingsText.String()},
    },
    Temperature: 0.2, // Lower temperature for analytical and deterministic output
}
```

> [!WARNING]
> Sending findings to an external AI API means sending potentially sensitive strings to a third party. Siphon explicitly warns the user in the CLI before doing this.
