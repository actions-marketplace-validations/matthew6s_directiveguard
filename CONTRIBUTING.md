# Contributing

Bug reports, false-positive examples, documentation improvements, and narrowly scoped detection rules are welcome.

Before submitting a pull request:

1. Open an issue for substantial behavioral changes.
2. Add positive and negative tests for detection rules.
3. Run `go test -race ./...`, `go vet ./...`, and `go build ./cmd/agentshield`.
4. Explain the security boundary and likely false positives in the pull request.

Rules should identify a concrete unsafe behavior. Avoid broad keyword matching that labels ordinary documentation as malicious.
