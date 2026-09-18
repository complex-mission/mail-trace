package main

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"net/http"
	"time"
)

// ogPNG 是预先用无头浏览器把 og.svg 渲染好的 1200x630 位图。
//
// 为什么不直接把 og.svg 当社交卡片图：Facebook 与 X/Twitter 都不接受 SVG，
// 给了也只会退化成没有配图的纯文字卡片。而在服务端实时栅格化 SVG 需要额外引入
// 渲染库，为一张从不变化的静态图片增加两个运行时依赖并不划算 —— 所以预渲染后入库。
// 改动 ogSVG 的设计后，需要重新渲染并替换 docs/og.png（README 的贡献一节有命令）。
//
//go:embed docs/og.png
var ogPNGFS embed.FS

var ogPNG, ogPNGETag = func() ([]byte, string) {
	b, err := ogPNGFS.ReadFile("docs/og.png")
	if err != nil {
		panic("embed docs/og.png: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return b, fmt.Sprintf("\"%x\"", sum[:8])
}()

// SiteURL 决定 canonical / sitemap / OG 里写什么域名，部署时用 SITE_URL 覆盖。
const defaultSiteURL = "https://mail-trace.complexmission.com"

var SiteURL = defaultSiteURL

const RepoURL = "https://github.com/complex-mission/mail-trace"

func handleRobots(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, `User-agent: *
Allow: /
Disallow: /api/

# 诊断接口是 POST 且需要用户凭据，抓取无意义
User-agent: GPTBot
Allow: /
Disallow: /api/

User-agent: ClaudeBot
Allow: /
Disallow: /api/

User-agent: PerplexityBot
Allow: /
Disallow: /api/

Sitemap: %s/sitemap.xml
`, SiteURL)
}

func handleSitemap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	today := time.Now().Format("2006-01-02")
	fmt.Fprintf(w, `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"
        xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <url>
    <loc>%s/</loc>
    <lastmod>%s</lastmod>
    <changefreq>weekly</changefreq>
    <priority>1.0</priority>
    <xhtml:link rel="alternate" hreflang="zh-Hans" href="%s/?lang=zh"/>
    <xhtml:link rel="alternate" hreflang="en" href="%s/?lang=en"/>
    <xhtml:link rel="alternate" hreflang="x-default" href="%s/"/>
  </url>
</urlset>
`, SiteURL, today, SiteURL, SiteURL, SiteURL)
}

// handleLLMs 输出 llms.txt：给大模型/AI 搜索一份结构化、无需渲染 JS 的事实清单。
// 这是本站在生成式检索里被正确引用的主要抓手。
func handleLLMs(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	fmt.Fprintf(w, `# Mail Trace

> An open-source mail deliverability diagnostic. Opens a real SMTP session and pinpoints, hop by hop,
> why mail fails to send or lands in spam.
> 开源的邮件送达率诊断工具。真实建立一次 SMTP 会话，逐跳定位邮件发不出去或进垃圾箱的原因。

- Site / 站点: %s
- Source / 源码: %s (MIT)
- Languages / 语言: English, 简体中文

## What it checks / 它做什么

1. DNS resolution, TCP connect, SSL/TLS or STARTTLS handshake, SMTP authentication, MAIL FROM,
   RCPT TO and DATA, each with its latency and the raw server reply.
2. SPF: evaluated in full per RFC 7208, recursively expanding include / redirect / a / mx / ip4 /
   ip6 / exists to decide whether the actual sending IP is authorized, identifying the consequences
   of -all / ~all / ?all, and counting against the 10-lookup limit.
3. Reverse DNS of the sending IP: the PTR record and FCrDNS round-trip of the IP that actually
   opened the SMTP connection, not the PTR of the domain's A record (which points at a web server
   and has nothing to do with sending mail).
4. DNSBL: queries Spamhaus ZEN, SpamCop, Barracuda, PSBL and UCEPROTECT, classifying return codes
   into three kinds - spam-source listings (127.0.0.2-.9), the PBL policy list (127.0.0.10/.11),
   and refused queries (127.255.255.x).
5. DKIM selector probing, DMARC record and policy, MTA-STS, TLS-RPT, BIMI, DANE.
6. Provider detection: when submitting through a third party, SPF and DNSBL are judged against the
   provider's egress pool rather than the submission host.

## Three things most tools get wrong / 常被误判的三件事

- A Spamhaus answer of 127.0.0.11 is the PBL, a policy list meaning "this IP range should not
  connect to MX hosts directly" - it is not a spam accusation. An answer of 127.255.255.x means the
  query was refused (a public resolver was used), so the result is invalid rather than "listed".
- Reverse DNS applies to the actual sending IP, not the domain's A record.
- A recipient domain having no A record, DMARC or PTR is normal; receiving mail only needs MX.

## Privacy / 隐私

Account credentials exist only in the memory serving that one request. They are not written to any
database, log or file, and are not forwarded to any third party. There are no accounts, no cookies
and no caching. The source is open, so this can be verified or self-hosted.

The page loads three font families from Google Fonts, which is the only third-party request the
browser makes; it carries no credentials or diagnostic content.

## Licence / 许可

MIT
`, SiteURL, RepoURL)
}

// handleOGImage 输出社交分享卡片的矢量版（SVG，1200x630）。
// 网页里 <meta og:image> 指向的是 PNG 版本，见 handleOGImagePNG。
func handleOGImage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/svg+xml; charset=utf-8")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	fmt.Fprint(w, ogSVG)
}

// handleOGImagePNG 输出社交分享卡片的位图版。各家抓取器只认这个。
func handleOGImagePNG(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "image/png")
	w.Header().Set("Cache-Control", "public, max-age=86400")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("ETag", ogPNGETag)
	if r.Header.Get("If-None-Match") == ogPNGETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(ogPNG)
}

const ogSVG = `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="630" viewBox="0 0 1200 630">
  <defs>
    <linearGradient id="g" x1="140" y1="150" x2="440" y2="430" gradientUnits="userSpaceOnUse">
      <stop stop-color="#5b9cf6"/><stop offset="0.55" stop-color="#8b7df6"/><stop offset="1" stop-color="#d67df6"/>
    </linearGradient>
    <linearGradient id="gt" x1="140" y1="300" x2="900" y2="380" gradientUnits="userSpaceOnUse">
      <stop stop-color="#5b9cf6"/><stop offset="1" stop-color="#d67df6"/>
    </linearGradient>
    <radialGradient id="glow" cx="0.5" cy="0.5" r="0.5">
      <stop stop-color="#8b7df6" stop-opacity="0.20"/><stop offset="1" stop-color="#8b7df6" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="1200" height="630" fill="#080b12"/>
  <ellipse cx="300" cy="250" rx="520" ry="360" fill="url(#glow)"/>
  <g transform="translate(104,140) scale(3.05)">
    <rect x="5.3" y="14.3" width="30.4" height="24.4" rx="6.5" fill="none" stroke="url(#g)" stroke-width="2.6"/>
    <path d="M11 20.4 20.5 28.6 30 20.4 41.2 10.8" fill="none" stroke="url(#g)" stroke-width="2.6"
          stroke-linecap="round" stroke-linejoin="round"/>
    <circle cx="20.5" cy="28.6" r="2.2" fill="url(#g)"/>
    <circle cx="41.2" cy="10.8" r="4.1" fill="#080b12" stroke="url(#g)" stroke-width="2.6"/>
  </g>
  <text x="96" y="350" font-family="Inter, Segoe UI, system-ui, sans-serif" font-size="82" font-weight="700"
        fill="url(#gt)" letter-spacing="-2">Mail Trace</text>
  <text x="98" y="405" font-family="Inter, Segoe UI, system-ui, sans-serif" font-size="30" fill="#b0bcda">
    邮件发送全链路诊断 — 逐跳定位发不出去或进垃圾箱的原因
  </text>
  <text x="98" y="449" font-family="Inter, Segoe UI, system-ui, sans-serif" font-size="26" fill="#6b7da0">
    Trace every SMTP hop. Full SPF evaluation, PTR/FCrDNS, DNSBL return-code analysis.
  </text>
  <g font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="24" fill="#8b9ec4">
    <rect x="96"  y="496" width="112" height="46" rx="10" fill="#0f1420" stroke="#2a3550"/>
    <text x="118" y="526">SMTP</text>
    <rect x="224" y="496" width="90"  height="46" rx="10" fill="#0f1420" stroke="#2a3550"/>
    <text x="246" y="526">SPF</text>
    <rect x="330" y="496" width="104" height="46" rx="10" fill="#0f1420" stroke="#2a3550"/>
    <text x="352" y="526">DKIM</text>
    <rect x="450" y="496" width="122" height="46" rx="10" fill="#0f1420" stroke="#2a3550"/>
    <text x="472" y="526">DMARC</text>
    <rect x="588" y="496" width="90"  height="46" rx="10" fill="#0f1420" stroke="#2a3550"/>
    <text x="610" y="526">PTR</text>
    <rect x="694" y="496" width="122" height="46" rx="10" fill="#0f1420" stroke="#2a3550"/>
    <text x="716" y="526">DNSBL</text>
  </g>
  <text x="1104" y="566" text-anchor="end" font-family="Inter, Segoe UI, system-ui, sans-serif"
        font-size="24" fill="#4d5d7d">github.com/complex-mission/mail-trace · MIT</text>
</svg>`
