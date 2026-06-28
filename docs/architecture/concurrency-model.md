# Concurrency Model

Siphon achieves massive speed using Go's native concurrency features.

## Goroutines and Channels
Instead of loading everything into memory, Siphon streams URLs through channels.
A pool of worker Goroutines (controlled by the `-threads` flag) listens on these channels, processing HTTP requests and regex matching in parallel.

## Sync.Pool
To reduce Garbage Collection (GC) overhead when processing gigabytes of JavaScript strings, Siphon uses `sync.Pool` to recycle byte buffers across different files.
