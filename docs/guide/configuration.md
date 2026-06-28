# Configuration

Siphon can be configured via command-line flags or environment variables.

## Global Options
- `-threads`: Number of concurrent workers (default: 50)
- `-timeout`: HTTP timeout in seconds (default: 10)
- `-insecure`: Skip SSL certificate verification

## Environment Variables
Siphon automatically reads a `.env` file in the current directory.
```env
GEMINI_API_KEY=your_key_here
GITHUB_TOKEN=your_token_here
```

> [!WARNING]
> Keep your `.env` file secure and never commit it to source control.
