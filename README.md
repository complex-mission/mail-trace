<div align="center">

<img src="docs/logo.svg" width="88" alt="Mail Trace">

# Mail Trace

**Trace every SMTP hop. Find out exactly why your mail bounces or lands in spam.**

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-5b9cf6)](LICENSE)
[![Single binary](https://img.shields.io/badge/deploy-single%20binary-8b7df6)](#self-hosting)
[![i18n](https://img.shields.io/badge/i18n-English%20%7C%20中文-d67df6)](#)

[Live demo](https://mail-trace.complexmission.com) · [Self-hosting](#self-hosting) · [Why another tool](#why-another-tool)

**English** · [简体中文](README.zh-CN.md)

</div>

---

## What it solves

"The mail won't send" and "the mail sent but landed in spam" are two completely different faults, yet most online checkers only cover half of it — and often check the wrong thing. Mail Trace does both, and shows you the evidence behind every verdict.

<table>
<tr><td width="50%" valign="top">

### Records check · no password needed

Just changed your DNS and want to know whether it took effect, and whether Gmail will accept you? A domain name is all it takes.

- MX / A / AAAA
- **Full SPF evaluation per RFC 7208** — recursively expands `include`, `redirect`, `a`, `mx`, `ip4`, `ip6` and `exists`, decides whether the sending IP you gave is actually authorized, and counts against the 10-lookup limit
- DKIM selector probing (40+ common selectors built in, or enter your own)
- DMARC record and `p=` policy
- MTA-STS / TLS-RPT / BIMI / DANE
- **PTR and FCrDNS round-trip** for the sending IP
- 5 DNSBLs, **classified by return code** instead of a blanket "listed"
- **Sender requirements of Gmail / Yahoo / Microsoft / Chinese receivers, checked line by line**

</td><td width="50%" valign="top">

### Full delivery test · a real SMTP session

Records all correct but mail still won't go out? Then the problem is inside the session.

- DNS resolution → TCP connect → banner → EHLO
- SSL/TLS or STARTTLS handshake (certificate chain, validity, protocol and cipher)
- AUTH (LOGIN / PLAIN)
- MAIL FROM → RCPT TO → DATA
- Latency of every hop plus the **raw server reply**
- Failure-specific guidance keyed to the actual status code
- Optional dry-run mode that stops before delivery

</td></tr>
</table>

<div align="center">
<img src="docs/records-check.png" width="82%" alt="Records check and receiver requirements">
</div>

---

## Why another tool

There is no shortage of mail checkers. But the three things below are what most of them get wrong, and they are the reason this one exists.

### 1. A DNSBL hit is not the same as being blocklisted

Spamhaus return codes carry three completely different meanings. Conflating them leads to the opposite conclusion:

| Return code | Type | Meaning | Severity |
|---|---|---|---|
| `127.0.0.2` – `127.0.0.9` | SBL / CSS / XBL | Real spam history, or a compromised host | **Hard problem** |
| `127.0.0.10` / `127.0.0.11` | **PBL (policy list)** | "This IP range should not connect to MX hosts directly." Cloud IP ranges are in it by default — **nothing to do with spam** | Only matters for direct self-hosted delivery |
| `127.255.255.x` | Query refused | You used a public resolver or exceeded the free quota — **the result is invalid** | Not a listing |

Plenty of tools see any A record come back and report "listed, please request delisting". If the answer was `127.255.255.254` that advice is meaningless; if it is PBL and you deliver through a provider's relay, equally meaningless.

### 2. Reverse DNS applies to the sending IP, not the domain's A record

The A record of `example.com` usually points at a web server and has nothing to do with sending mail. What matters is the PTR record of **the IP that actually opened the SMTP connection**, plus a forward lookup that resolves back to that same IP (FCrDNS).

### 3. SPF is not "is there a record", it is "does this IP pass"

The most common and most damaging failure: the SPF record lists a provider `include`, but mail is actually sent straight from a self-hosted server whose IP is nowhere in the authorized set. Combine that with `-all` and receivers reject outright. Checking only that a record exists and starts with `v=spf1` will never surface this.

Mail Trace expands the whole include chain for you:

```
v=spf1 include:spf1.dm.aliyun.com -all

include:spf1.dm.aliyun.com → v=spf1 ip4:115.124.21.0/24 ip4:140.205.208.0/24 … -all
  include:spfdm-global-1.aliyun.com → v=spf1 ip4:115.124.24.0/24 … -all
    -all → fail
  -all → fail
-all → fail

Result: fail — 203.0.113.10 is not authorized, and the policy is -all (hard fail)
```

### Also: a submission host is not an egress IP

When you submit through a provider on 465/587, the host that actually talks to the recipient's MX is the provider's **egress IP pool**, not the submission server you connected to. So the right question becomes "does the SPF record include the provider", not "does the submission host's IP match" — and that host's PTR and PBL status are irrelevant to you. Mail Trace recognises 17 providers (Tencent Exmail, Alibaba Mail / DirectMail, NetEase, 263, Gmail, Microsoft 365, SendGrid, Mailgun, Amazon SES, Postmark, Mailjet, Zoho, Xserver, SendCloud and others) and switches its criteria automatically.

---

## Privacy and security

This is a tool that asks for your mailbox password, so the security boundary has to be spelled out.

**How credentials are handled**

- **Never persisted**: the username and password exist only in the memory serving that one request, and are released when it ends. Nothing is written to a database, log or file.
- **Never logged**: server logs contain only the source IP and rate-limit counters.
- **Never forwarded**: credentials are used solely to authenticate against the SMTP server you entered.
- **No session**: no accounts, no cookies, no profiling, no caching.
- **One third-party request**: page fonts come from Google Fonts, so the browser talks directly to `fonts.googleapis.com` / `fonts.gstatic.com` and Google sees the visitor's IP and user agent. Those requests carry no credentials or diagnostic content, and Google Fonts sets no cookies. If that bothers you, delete the three font `<link>` lines from the page head and it falls back to system fonts.

You do not have to take any of this on faith — the code is here, and `grep` settles it. The thorough option is to run your own instance.

**Protections on the server itself** (see [`security.go`](security.go) and [`sec_test.go`](sec_test.go))

| Attack surface | Handling |
|---|---|
| SSRF / internal probing | Blocks loopback, private, link-local (including the `169.254.169.254` cloud metadata address), CGNAT and reserved ranges; and re-checks **the final connect IP** inside `Dialer.Control` to stop DNS rebinding |
| Port scanning | Port allowlist, only 25 / 465 / 587 / 2525 |
| SMTP command and header injection | Every field rejects CR/LF and control characters; addresses are shape-validated |
| Cleartext credential exposure | Authentication is aborted if the channel is not encrypted — `AUTH LOGIN` / `PLAIN` is base64, not encryption |
| Resource exhaustion | 16 KB request body cap, I/O deadlines throughout, concurrency gate, optional Redis rate limiting |

`sec_test.go` pins the behaviour above with 15 cases; `go test` reproduces it.

> `MAIL_TRACE_ALLOW_PRIVATE=1` opens up both internal addresses and the port allowlist. **Self-hosted internal use only.** Enabling it on a public deployment turns this service into an outbound port scanner.

---

## Self-hosting

One binary, no runtime dependencies. Redis is optional (rate limiting only).

```bash
git clone https://github.com/complex-mission/mail-trace.git
cd mail-trace
go build -o mail-trace .

cp .env.example .env    # adjust as needed
./mail-trace            # listens on 127.0.0.1:9013 by default
```

See [DEPLOY.md](DEPLOY.md) for a pre-launch checklist, reverse-proxy requirements, panel-managed setups and verification commands.

Pass the listen address directly with `./mail-trace -listen 0.0.0.0:9013` (the old positional form `./mail-trace 0.0.0.0:9013` still works). `./mail-trace -version` prints the version.

On `SIGINT` / `SIGTERM` it stops accepting new connections and gives in-flight diagnostics up to 90 seconds to finish — cutting an SMTP session mid-transaction leaves a half-finished transaction on the far side.

A `Dockerfile` is included:

```bash
docker build -t mail-trace .
docker run --rm -p 9013:9013 --env-file .env mail-trace
```

### Environment variables

| Variable | Default | Description |
|---|---|---|
| `LISTEN` | `127.0.0.1:9013` | Listen address |
| `SITE_URL` | `https://mail-trace.complexmission.com` | Written into canonical / sitemap / OG / llms.txt. **Change this when self-hosting** |
| `REDIS_URL` | empty | Enables rate limiting. Recommended for public deployments |
| `RATE_LIMIT_MAX` | `10` | Max requests per window |
| `RATE_LIMIT_WINDOW` | `1m` | Rate-limit window |
| `MAIL_TRACE_TRUSTED_PROXIES` | empty | Reverse-proxy ranges (CIDR or IP, comma separated). **Required behind nginx**, otherwise rate limiting counts the proxy IP and every visitor shares one bucket |
| `MAX_CONCURRENT` | `32` | Cap on concurrent diagnostics; excess requests get 503. `0` disables the cap |
| `MAIL_TRACE_ALLOWED_PORTS` | `25,465,587,994,2525` | Ports the diagnostic may connect to. The allowlist stops the service being used as a port scanner; widen it for non-standard mail servers |
| `MAIL_TRACE_DNS` | empty | DNS resolvers (comma separated, `:53` optional). Empty uses the built-in default `223.5.5.5 + 1.1.1.1` |
| `SHUTDOWN_GRACE` | `90s` | How long in-flight diagnostics may finish after a stop signal. Match your process manager's timeout — supervisor kills at 10s by default |
| `MAIL_TRACE_ALLOW_PRIVATE` | off | Allows internal targets and any port. **Internal deployments only** |

#### About `MAIL_TRACE_DNS`

The default list deliberately mixes in a non-Chinese resolver, and that is not an accident: **public resolvers in China silently drop records from large TXT RRsets.**

Measured on the same `github.com`, three queries each:

| Resolver | TXT records returned | Included SPF |
|---|---|---|
| 223.5.5.5 (Alibaba) | 14 / 17 / 18 | 1/3 |
| 114.114.114.114 | 6 | 0/3 |
| 180.76.76.76 (Baidu) | 3 | 1/3 |
| 119.29.29.29 (DNSPod) | unreachable | — |
| 1.1.1.1 / 8.8.8.8 / 9.9.9.9 | **24 / 24 / 24** | **3/3** |

Lose the SPF record and the tool declares a perfectly configured domain unfit for all four receivers — worse than not checking at all. So SPF and DMARC use a **concurrent union query**: every resolver is asked and the results are merged, because one resolver's silence is not proof that a record does not exist. The queries run in parallel, so the second resolver costs no extra time; if it is unreachable, you simply fall back to the partial answer rather than failing.

Separately, blocklists such as Spamhaus refuse queries from public resolvers (returning `127.255.255.x`). **For a trustworthy DNSBL verdict this must point at your own recursive resolver**; otherwise treat that section as "unknown".

---

### Reverse proxy

Serve it over HTTPS. This tool transmits passwords; on a plaintext deployment none of the privacy commitments hold.

```nginx
server {
    listen 443 ssl http2;
    server_name mail-trace.example.com;

    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://127.0.0.1:9013;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # the full delivery test streams over SSE, buffering must be off
        proxy_buffering off;
        proxy_read_timeout 120s;
    }
}
```

Alongside this nginx config you **must** declare the proxy range in `.env`:

```bash
MAIL_TRACE_TRUSTED_PROXIES=127.0.0.1,::1
```

Otherwise the service only ever sees `127.0.0.1` as the source and rate limiting treats every visitor as one person — ten requests lock the whole site. Conversely, without this setting the service will **not** blindly trust `X-Forwarded-For`: anyone can forge that header, and trusting it means no rate limiting at all. Both failure modes have to be avoided, so only explicitly declared proxies are honoured.

### Outbound ports

The full delivery test needs to reach the target SMTP port. **Cloud providers in mainland China block outbound port 25 by default and rarely grant exceptions**; 465/587 are generally unaffected. To cover direct-to-MX delivery on port 25, deploy outside that region.

---

## API

Both endpoints accept a JSON POST. `lang` is `zh` or `en`.

### `POST /api/records` — records only, no credentials

```bash
curl -s https://your-instance.example.com/api/records \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","ip":"203.0.113.10","selectors":["s1"],"lang":"en"}'
```

Returns DNS records, the SPF evaluation trace, PTR/FCrDNS, DNSBL detail, and the receiver requirement matrix.

### `POST /api/test-stream` — full delivery test (SSE)

```bash
curl -N https://your-instance.example.com/api/test-stream \
  -H 'Content-Type: application/json' \
  -d '{"host":"smtp.example.com","port":587,"username":"u","password":"p",
       "from":"a@example.com","to":"b@example.com","dry_run":true,"lang":"en"}'
```

Streams `step` / `tls` / `extensions` / `dns` / `done` events. `POST /api/test` is the non-streaming variant that returns the result in one response.

---

## Project layout

```
main.go        HTTP routing, SMTP session, hop-by-hop diagnostics, DNS queries, i18n
server.go      client IP resolution, concurrency gate, access log, server timeouts and graceful shutdown
analysis.go    SPF evaluation, DNSBL classification, PTR/FCrDNS, policy records, provider detection
records.go     records-only mode and receiver requirement checks
security.go    input validation, SSRF protection, port allowlist
seo.go         robots.txt / sitemap.xml / llms.txt / OG image
templates/     single-file frontend (no build step)
```

The frontend is one self-contained HTML file with no bundler; every icon is inline SVG ([Lucide](https://lucide.dev), ISC). The only external assets are three Google Fonts families (Archivo / Chiron Hei HK / Sometype Mono) — Archivo leads the stack in both languages, CJK glyphs fall through to Chiron Hei HK automatically, and the monospace stack carries a CJK fallback too.

Fonts load with `font-display: swap`, so **the page never blocks on networks that cannot reach Google Fonts** (including parts of mainland China) — it simply renders in system fonts with no loss of function. To drop the external dependency entirely, delete the three `<link>` lines from the head of `templates/index.html`; the system-font fallback chain is already spelled out in the `--font-sans` / `--font-mono` CSS variables.

---

## Contributing

Issues and PRs are welcome, particularly these two kinds:

- **More provider detection**: `knownProviders` in `analysis.go`, which needs the submission host domain and its SPF include.
- **More DKIM selectors**: the selector list in `main.go`. Selectors cannot be enumerated, so the fuller this table, the better the hit rate.

Run `go test ./...` and `gofmt -l .` before opening a PR.

### After changing the social card design

`ogSVG` in `seo.go` is the vector source, but `<meta og:image>` points at the pre-rendered `docs/og.png` — neither Facebook nor X/Twitter accepts SVG, and handing them one degrades the card to text with no image. After editing `ogSVG`, regenerate the bitmap:

```bash
# any headless browser works, Chrome or Edge
chrome --headless --disable-gpu --hide-scrollbars --force-device-scale-factor=1 --window-size=1200,630 --screenshot=docs/og.png file:///absolute/path/og.html
```

`og.html` is a wrapper page that drops the `ogSVG` markup into `<body>` and sets `margin:0; overflow:hidden; width:1200px; height:630px` on `html,body`. Afterwards, `magick docs/og.png -strip -define png:compression-level=9 docs/og.png` recompresses it losslessly (roughly 15% smaller).

---

## Disclaimer

Use this tool only against mail services you own or are authorised to test. Results are based on public DNS data and one real SMTP session, reflect the state at query time, and constitute no guarantee — receivers do not publish their actual filtering policies, and no tool can predict them. Outside dry-run mode, a diagnostic message is actually delivered to the recipient address.

---

<div align="center">
<sub>MIT · <a href="https://github.com/complex-mission/mail-trace">github.com/complex-mission/mail-trace</a></sub>
</div>
