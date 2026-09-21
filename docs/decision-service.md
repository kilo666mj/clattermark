# Optional decision service

Clattermark can ask an external HTTP service whether a locally matched alert
should be sent. The integration is optional. Disabled integrations allow all
local candidates, and request failures default to fail-open.

The service should expose `POST /v1/decide`. Clattermark sends:

```json
{
  "kind": "log_alert",
  "source": "clattermark",
  "content": {
    "raw": "original log line",
    "formatted": "fallback notification text",
    "parsed": {
      "host": "host1",
      "process": "nginx",
      "pid": "123",
      "text": "connect() failed",
      "tstmp": "2026-09-21T12:00:00+00:00"
    }
  },
  "policy": {
    "action": "send_alert"
  },
  "metadata": {
    "component": "clattermark"
  },
  "timestamp": "2026-09-21T12:00:00Z"
}
```

The expected response is:

```json
{
  "decision": "allow",
  "confidence": 0.87,
  "reason": "Likely service connectivity issue",
  "summary": "Nginx cannot reach an upstream service.",
  "ttl_seconds": 900,
  "fingerprint": "service-owned-stable-fingerprint"
}
```

`decision` must be `allow` or `deny`. An allowed response below
`min_confidence` is suppressed. A positive TTL overrides the normal alert
deduplication cooldown.

If `feedback_action_target` is configured and an allowed response contains a
fingerprint and host, Clattermark adds a Tintwire action carrying the service's
canonical fingerprint. The target is resolved and authenticated by Tintwire;
Clattermark does not embed decision-service credentials in the card.
