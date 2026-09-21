# Operations

## Installation

Build and install the binary, configuration, and service unit:

```sh
go build -trimpath -o clattermark .
sudo install -m 0755 clattermark /usr/local/bin/clattermark
sudo install -d -m 0750 -o clattermark -g clattermark /etc/clattermark /var/lib/clattermark
sudo install -m 0640 -o root -g clattermark examples/config.json /etc/clattermark/config.json
sudo install -m 0640 -o root -g clattermark secrets.example.json /etc/clattermark/secrets.json
```

Create the `clattermark` system account before installing files. Grant it read
access to configured log inputs using an appropriate group or filesystem ACL.
Do not run Clattermark as root solely to read logs.

## Health and metrics

`/healthz` returns HTTP 200 only while the process is ready and not shutting
down. `/metrics` exposes pipeline, tail, dependency, notification, decision,
and outbox counters plus readiness and last-input timestamps.

The listener has no TLS support. Bind it to loopback or place it behind a
trusted authenticated reverse proxy. Prometheus rules in `monitoring/` provide
a starting point and should be adjusted for local job labels and queue size.

## Shutdown and log rotation

SIGINT and SIGTERM stop ingestion and drain queued work before exit. SIGHUP
reopens the application and alert logs. The contributed logrotate policy sends
SIGHUP after rotation.

## Recovery

Clattermark periodically snapshots dynamic exclusions in its state directory.
If Redis/KeyDB is empty at startup and the snapshot is available, the snapshot
is restored before processing begins.

Incident quiet notifications use a durable Redis/KeyDB outbox. Preserve the
configured database when moving an active deployment or deliberately choose a
new database when starting an independent pipeline.
