# Clattermark

Clattermark watches line-oriented system and application logs, filters expected
noise, groups related incidents, suppresses duplicates, and delivers the events
that remain to [Tintwire](https://github.com/kilo666mj/tintwire) with an optional
Mattermost webhook fallback.

```text
log files -> match and parse -> excludes -> optional decision API -> dedupe -> notifications
                                      \-> incident aggregation -> quiet notification
```

Clattermark is designed for centralized syslog collectors, but it can follow any
file that receives complete newline-delimited records. It begins at the end of
each configured file, follows rotations, and applies backpressure rather than
dropping lines when alert processing is saturated.

## Features

- Follows multiple files and restarts interrupted tails.
- Matches named monitor rules expressed as regular expressions.
- Parses common RFC 3339 syslog envelopes into host, process, PID, timestamp,
  and message fields.
- Supports static exclusions, process exclusions, and authenticated dynamic
  exclusions shared through Redis or KeyDB.
- Deduplicates normalized alerts across replicas with configurable cooldowns.
- Groups related events into durable incidents and emits periodic and quiet
  notifications.
- Optionally consults a small HTTP decision API before sending an alert.
- Sends native Tintwire cards with Mattermost-compatible webhook fallback.
- Exposes readiness, Prometheus metrics, and an authenticated exclusions API.
- Drains in-flight alert work during graceful shutdown.

## Security boundary

Log input is untrusted data. Clattermark may use it to select and format an
alert, but a log record is never authentication or proof of identity. Keep the
HTTP listener on a trusted network, protect webhook and API credentials, and
restrict access to the input logs and state directory.

Dynamic excludes can suppress future alerts. Their mutation endpoints require
a bearer or slash-command token, are rate limited, and should not be exposed
directly to the public internet. The health and metrics endpoints do not require
authentication, so bind them to loopback or a protected monitoring network.

## Requirements

- Go 1.26 or newer to build from source.
- A Redis-compatible server such as Redis or KeyDB.
- A Tintwire webhook URL, a Mattermost incoming webhook URL, or both for actual
  notification delivery.

## Quick start

Start a development Redis-compatible server, then:

```sh
touch /tmp/clattermark-input.log
go test ./...
go build -o clattermark .
./clattermark -config examples/config.json -state-dir /tmp/clattermark-state
```

The example binds health and metrics to loopback, disables the optional decision
service and incident aggregation, and contains no credentials. In another
terminal:

```sh
curl --fail http://127.0.0.1:8080/healthz
printf '%s\n' '2026-09-21T12:00:00+00:00 host1 demo[1234]: connection refused' >> /tmp/clattermark-input.log
```

The synthetic record will be processed, but notification delivery will fail
until a webhook is configured in the secrets file. Clattermark starts at EOF,
so append test records only after it is running.

## Configuration

Copy [examples/config.json](examples/config.json) to
`/etc/clattermark/config.json`. Store credentials separately using
[secrets.example.json](secrets.example.json) as the schema. The default secrets
path is `/etc/clattermark/secrets.json`; override it with
`CLATTERMARK_SECRETS_FILE`.

The secrets file is optional when the corresponding integrations do not need
credentials. Values present in it override their non-secret configuration
counterparts. Do not commit a populated secrets file.

The first notification URL is a Tintwire hook in the form
`https://tintwire.example/hooks/<token>`. `secondary_url` is an optional
Mattermost-compatible incoming webhook used when Tintwire delivery fails.

Clattermark requires Redis-compatible storage for dynamic exclusions,
cross-replica deduplication, and durable incident state. Give each independent
deployment its own database or dedicated server.

See [configuration documentation](docs/configuration.md) for the full behavior
and [operations documentation](docs/operations.md) for installation, endpoints,
and recovery.

## Optional decision service

The decision API is an extension point, not a required companion project. When
disabled, locally matched alerts proceed normally. When enabled, failures
default to fail-open so an unavailable classifier does not hide operational
events. See [docs/decision-service.md](docs/decision-service.md) for the wire
contract.

## Installation

The repository includes a hardened example unit at
[contrib/systemd/clattermark.service](contrib/systemd/clattermark.service) and a
matching [logrotate policy](contrib/logrotate/clattermark). Adjust supplementary
groups or ACLs so the service account can read your chosen log files.

## License

[MIT](LICENSE)
