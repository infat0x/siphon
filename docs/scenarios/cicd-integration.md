# CI/CD Integration

Siphon can be integrated into GitHub Actions, GitLab CI, or Jenkins to prevent developers from accidentally deploying hardcoded secrets.

## GitHub Actions Example
```yaml
name: Siphon Secret Scan
on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Run Siphon
        run: ./siphon -dir ./src/ -o results.json
      - name: Fail on Secrets
        run: |
          if [ -s results.json ]; then
            echo "Secrets found!"
            exit 1
          fi
```

> [!NOTE]
> Siphon supports exit codes. If secrets are found, it can automatically exit with code `1` to break the build.
