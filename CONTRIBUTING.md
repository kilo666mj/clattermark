# Contributing

Issues and pull requests are welcome. Keep changes focused, avoid including
private log data or credentials, and add tests for behavior changes.

Before opening a pull request, run:

```sh
go test -race ./...
go vet ./...
go build .
```

CI also runs `golangci-lint` and CodeQL. Public interfaces, configuration keys,
metric names, and the decision-service request shape should remain backward
compatible unless a change is explicitly documented as breaking.

Security vulnerabilities should be reported through GitHub private
vulnerability reporting as described in [SECURITY.md](SECURITY.md).
