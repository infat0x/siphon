# Fine Tuning the AI

The default Gemini prompts in Siphon are tuned for general-purpose secret detection.

## Custom System Prompts
You can modify the system prompt sent to the LLM by creating a `.siphon_prompt.txt` file in your execution directory.
Siphon will automatically load this file and use it to instruct the AI.

> [!TIP]
> Tell the AI specifically what your company's secrets look like to further reduce false positives.
