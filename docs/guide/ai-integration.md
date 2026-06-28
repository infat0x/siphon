# AI Integration

Siphon natively integrates with LLMs (currently Gemini) to virtually eliminate false positives.

## How it works
1. The regex and entropy scanners flag a potential secret.
2. Siphon sends the matched string and the 500 surrounding lines of code to the LLM.
3. The LLM acts as an expert security analyst, determining if the string is a real credential or a placeholder/test key.

## Enabling AI
Set the `GEMINI_API_KEY` environment variable. The AI engine will automatically initialize.

> [!TIP]
> The AI engine runs asynchronously and will not slow down the initial scanning phase.
