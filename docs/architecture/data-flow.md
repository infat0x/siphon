# Data Flow

How data moves through Siphon:

1. **Network Layer**: `net/http` with custom dialers to bypass rate limits.
2. **Disk Layer**: Temporary files are stored in `/tmp/siphon_XX` to prevent memory exhaustion on large bundles.
3. **Memory Layer**: Regular expressions are compiled once at startup and shared globally.
4. **Output Layer**: Results are flushed to the `results/` directory continuously, ensuring data is not lost if the program crashes.
