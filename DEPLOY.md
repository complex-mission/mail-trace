# Deployment

[English](DEPLOY.md) · [简体中文](DEPLOY.zh-CN.md)

## Before you launch

Four settings decide whether this service behaves correctly in production.
Three of them fail **silently** when wrong — the tool keeps answering, it
just answers incorrectly.

### 1. Verify your resolvers actually return complete TXT records

This is the one that matters most. SPF and DMARC use a union query across
every configured resolver, because public resolvers in China drop records
from large TXT RRsets. If none of your resolvers returns the full set, the
tool reports "no SPF record" for correctly configured domains and marks
them failing for every receiver — with no error to warn you.

Run this **on the server**, not on your laptop:

```bash
for r in 1.1.1.1 223.5.5.5; do
  printf '%-12s TXT=%s SPF=%s\n' "$r" \
    "$(dig +short TXT github.com @$r | wc -l)" \
    "$(dig +short TXT github.com @$r | grep -c spf1)"
done
```

A healthy resolver returns ~24 TXT records including 1 SPF. If `1.1.1.1`
shows `SPF=0` or times out, set `MAIL_TRACE_DNS` to something that works
from that host. A private recursive resolver is the best answer: it also
makes the DNSBL section trustworthy, since Spamhaus refuses queries coming
from public resolvers.

### 2. Declare your reverse proxy

```bash
MAIL_TRACE_TRUSTED_PROXIES=127.0.0.1,::1
```

Without it every visitor is counted as the proxy's IP and they all share
one rate-limit bucket — ten requests lock the whole site. The service
deliberately refuses to trust `X-Forwarded-For` unless the immediate peer
is on this list, because otherwise anyone could forge the header and
bypass rate limiting entirely.

### 3. Match the shutdown grace to your process manager

`SHUTDOWN_GRACE` defaults to 90s so an in-flight SMTP session is never cut
mid-transaction. But supervisor kills at `stopwaitsecs` (default 10s) and
systemd at `TimeoutStopSec` (default 90s). If your manager's timeout is
shorter, the graceful path never completes. Either raise the manager's
timeout or lower this value to match.

### 4. Serve it over HTTPS

This tool transmits mailbox passwords. On plain HTTP none of its privacy
commitments hold.

---

## Build

The binary embeds the page, the icons and the social card, so a single
file is the entire deployment — no `templates/` or `docs/` needed on the
server.

Cross-compile from any platform:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=v1.0.0" -o mail-trace .
```

That yields a ~9 MB static ELF. `./mail-trace -version` prints what you
built.

## Reverse proxy

```nginx
location / {
    proxy_pass http://127.0.0.1:9013;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    # the delivery test streams over SSE: buffering and caching must be off,
    # and the read timeout must outlast a slow SMTP session
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 180s;
}
```

`proxy_buffering off` is not optional. With buffering on, the browser
receives nothing until the diagnostic finishes, so the step-by-step
pipeline that is the point of the tool never animates.

## Panel-managed deployment (aaPanel / BT Panel)

The Go project manager runs the binary under supervisor. Two things differ
from a hand-rolled systemd unit:

**Environment variables.** The app reads `.env` from its working
directory. Panels do not always set the working directory to the project
folder, and a missing `.env` is not an error — the service starts with
defaults, which means no Redis rate limiting and no trusted proxies. Prefer
the panel's own environment-variable field over `.env`, and confirm from
the startup log either way (see Verification below).

**Stop timeout.** supervisor's `stopwaitsecs` defaults to 10s. Set
`SHUTDOWN_GRACE=10s` to match, or raise `stopwaitsecs` in the generated
supervisor config.

Suggested configuration:

```bash
LISTEN=127.0.0.1:9013
SITE_URL=https://your-domain.example.com
REDIS_URL=redis://127.0.0.1:6379/0
MAIL_TRACE_TRUSTED_PROXIES=127.0.0.1,::1
SHUTDOWN_GRACE=10s
RATE_LIMIT_MAX=10
RATE_LIMIT_WINDOW=1m
```

If the panel's Redis has a password, the URL becomes
`redis://:PASSWORD@127.0.0.1:6379/0`; percent-encode any `@ : / ?` in it.

Keep `LISTEN` on `127.0.0.1`. The service is meant to sit behind the
panel's nginx, and binding a public interface would expose it without TLS
and without the proxy headers the rate limiter depends on.

---

## Outbound port 25

The full delivery test has to reach the target SMTP port. Most cloud
providers block outbound 25 by default — including Tencent Cloud and
Alibaba Cloud, in their international regions as well as domestic ones —
and rarely grant exceptions. Ports 465 and 587 are normally unaffected, so
submission-based testing works everywhere; only direct-to-MX testing on 25
needs the block lifted.

Check from the server before assuming either way:

```bash
timeout 5 bash -c 'cat < /dev/null > /dev/tcp/gmail-smtp-in.l.google.com/25' \
  && echo "25 outbound OK" || echo "25 outbound blocked"
timeout 5 bash -c 'cat < /dev/null > /dev/tcp/smtp.qq.com/465' \
  && echo "465 outbound OK" || echo "465 outbound blocked"
```

## Verification

The startup log states what the service actually loaded. Read it once
after every configuration change — this is where a silently ignored `.env`
shows up:

```
loaded config file /www/wwwroot/mail-trace/.env
rate limiting enabled via Redis: 10 requests / 1m0s
2 trusted proxy range(s) configured; X-Forwarded-For will be honoured
Mail Trace v1.0.0 listening on http://127.0.0.1:9013 (Ctrl+C to stop)
```

If instead you see either of these, the corresponding setting did not take
effect:

```
REDIS_URL is not set, rate limiting is off
MAIL_TRACE_TRUSTED_PROXIES is not set; rate limiting counts RemoteAddr (...)
```

Then check the behaviour end to end:

```bash
# 1. the page is served and canonical follows SITE_URL
curl -s https://your-domain.example.com/ | grep -o 'rel="canonical" href="[^"]*"'

# 2. security headers are present
curl -sI https://your-domain.example.com/ | grep -iE 'content-security-policy|x-frame-options'

# 3. the records endpoint returns a real SPF record — this is the DNS
#    union fix working; an empty spf field means your resolvers are lossy
curl -s -X POST https://your-domain.example.com/api/records \
  -H 'Content-Type: application/json' \
  -d '{"domain":"github.com","lang":"en"}' | grep -o '"spf":"[^"]*"' | head -c 120

# 4. rate limiting counts real client IPs, not the proxy
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST \
    https://your-domain.example.com/api/records \
    -H 'Content-Type: application/json' -d '{"domain":"example.com"}'
done; echo
# expect 200s then 429s — if every request is 200, or the very first is
# 429 for a second visitor, the trusted-proxy setting is wrong

# 5. graceful shutdown actually runs (restart the service, then)
#    look for: stop signal received; no longer accepting requests ...
```

## Operating notes

- **Rate limiting fails open.** If Redis becomes unreachable the service
  logs `rate-limit lookup failed, allowing this request` and serves it. `MAX_CONCURRENT`
  is the backstop that still applies.
- **DNSBL results are only as good as your resolver.** On a public
  resolver Spamhaus answers `127.255.255.x`, which the tool reports as
  "query refused — result unreliable" rather than pretending it is a
  listing. A private recursive resolver removes the caveat.
- **The diagnostic sends real mail** unless the request sets
  `dry_run: true`. Every non-dry run delivers a message to the recipient
  address given.
