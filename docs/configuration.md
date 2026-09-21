# Configuration

Clattermark reads JSON configuration from `/etc/clattermark/config.json` by
default. Use `-config` to select another file and `-state-dir` to select the
directory that contains the PID, application log, alert log, and dynamic
exclude recovery snapshot.

## Inputs and monitors

`mon_files` lists files to follow. Clattermark seeks to EOF on first startup and
then follows appended complete lines across rotations.

Each `monitors` entry has a required Go regular expression in `search` and an
optional list of literal substrings in `excludes`. A line is a candidate when it
matches any monitor search and none of that monitor's exclusions.

`processes.excludes` contains regular expressions matched against the parsed
process field. Invalid patterns are logged and skipped.

`json_excludes` drops structured noise based on direct fields of a JSON object
in the parsed message text. Each rule requires a `process` regular expression
and at least one `boolean_fields` or `empty_array_fields` condition. All
conditions must match. Missing fields, `null` arrays, malformed JSON, and nested
fields do not match. For example:

```json
{
  "json_excludes": [{
    "process": "^worker$",
    "boolean_fields": {"complete": true},
    "empty_array_fields": ["failures"]
  }]
}
```

## Decision service identity

`decision_service.source` identifies Clattermark to the optional decision
service and defaults to `clattermark`. The same value is included in feedback
actions. Keep this value stable during a migration when the downstream service
uses it for routing, fingerprints, history, or feedback validation.

## Redis-compatible storage

`keydb.host` is a Redis-compatible `host:port`. The password normally belongs
in the secrets file. Storage is used for dynamic excludes, HA-safe deduplication,
incident state, and the incident quiet-notification outbox.

If storage is temporarily unavailable after startup, deduplication falls back
to a local in-memory cooldown. Startup itself requires the configured server so
the process does not begin with an unknown dynamic-exclusion state.

## Notifications

`notifications.primary_url` is a Tintwire hook URL. Clattermark extracts the
hook token and sends a version-1 card to Tintwire's notification API.

`notifications.secondary_url` is an optional Mattermost-compatible incoming
webhook. It is attempted only if Tintwire delivery fails. `channel` is optional;
when omitted, the receiving service's configured default is used.

Webhook URLs should be supplied through the secrets file rather than the main
configuration.

## Dynamic exclusions API

`web.listen_address` controls the HTTP listener. Slash-command tokens and API
bearer tokens belong in the secrets file.

- `GET /healthz` reports readiness and shutdown state.
- `GET /metrics` exposes Prometheus metrics.
- `POST /slash` accepts `status`, `mute <type> <value>`, and
  `unmute <type> <value>` using a form token.
- `GET /api/excludes` lists current exclusions.
- `POST /api/excludes` and `DELETE /api/excludes` mutate exclusions using a
  bearer token and JSON `type`, `value`, and `reason` fields.

Supported exclusion types are `host`, `process`, `pid`, and `text`.

## Deduplication and incidents

`alert_dedup.default_ttl_seconds` controls the normal cooldown. A successful
decision response may supply a positive `ttl_seconds` override.

Incident aggregation is optional. Each rule has a stable name, display title,
and one or more regular expressions. The first matching event is sent
immediately; subsequent events are counted, with notifications at the
configured reminder interval. After `quiet_seconds` without another match, a
durable quiet notification is emitted. Quiet means no matching log was seen; it
does not prove service recovery.

## Secrets

The secrets file may contain any subset of the fields in
`secrets.example.json`. Non-empty values override main configuration values.
The file is optional if no secret values are needed. In production, make it
readable only by the service account and administrators.
