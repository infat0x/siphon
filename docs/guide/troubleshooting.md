# Troubleshooting

Common issues and their solutions.

## Error: "Too many open files"
Your OS is limiting the number of simultaneous network connections.
**Fix**: Run `ulimit -n 65535` before running Siphon.

## Error: "context deadline exceeded"
The target is too slow or the `-timeout` flag is too short.
**Fix**: Increase the timeout with `-timeout 30`.

## No JS files found
The target might be a Single Page Application that loads scripts dynamically after page load.
**Fix**: Currently, Siphon does not execute JavaScript. You will need to manually extract the JS URLs and feed them to Siphon via `-l`.
