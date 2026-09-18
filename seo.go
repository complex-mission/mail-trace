package main

import (
	"crypto/sha256"
	"embed"
	"fmt"
	"net/http"
	"os"
	"strings"
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
var SiteURL = func() string {
	if v := os.Getenv("SITE_URL"); v != "" {
		return strings.TrimSuffix(v, "/")
	}
	return "https://mail-trace.complexmission.com"
}()

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

> 开源的邮件送达率诊断工具。真实建立一次 SMTP 会话，逐跳定位邮件发不出去或进垃圾箱的原因。
> An open-source mail deliverability diagnostic. Opens a real SMTP session and pinpoints, hop by hop,
> why mail fails to send or lands in spam.

- 站点 / Site: %s
- 源码 / Source: %s (MIT)
- 语言 / Languages: 简体中文, English

## 它做什么 / What it checks

1. DNS 解析、TCP 连接、SSL/TLS 或 STARTTLS 握手、SMTP 认证、MAIL FROM、RCPT TO、DATA，逐跳给出耗时与服务器原始应答。
2. SPF：按 RFC 7208 完整求值，递归展开 include / redirect / a / mx / ip4 / ip6 / exists，
   判断实际发信 IP 是否被授权，识别 -all / ~all / ?all 的后果，并统计 10 次 DNS 查询上限。
3. 发信 IP 的反向解析：检查实际建立 SMTP 连接的那个 IP 的 PTR 记录与 FCrDNS 闭环，
   而不是域名 A 记录的 PTR（后者指向网站，与发信无关）。
4. DNSBL：查询 Spamhaus ZEN、SpamCop、Barracuda、PSBL、UCEPROTECT，并按返回码分三类——
   垃圾源列表（127.0.0.2-.9）、策略列表 PBL（127.0.0.10/.11）、查询被拒（127.255.255.x）。
5. DKIM 选择器探测、DMARC 记录与策略、MTA-STS、TLS-RPT、BIMI、DANE。
6. 服务商识别：走第三方提交服务器时，SPF 与 DNSBL 改按服务商出口 IP 的口径判定。

## 常被误判的三件事 / Three things most tools get wrong

- Spamhaus 返回 127.0.0.11 是 PBL（策略列表），表示"该 IP 段不应直连 MX"，不是垃圾邮件指控；
  返回 127.255.255.x 表示查询被拒（用了公共 DNS），结果无效而非"已列入"。
- 反向解析应当查实际发信 IP，不是域名的 A 记录。
- 收件人域名没有 A 记录、DMARC、PTR 是正常的，收件只依赖 MX。

## 隐私 / Privacy

账号密码仅存在于处理该次请求的内存中，不写入数据库、日志或文件，不转发给任何第三方，
无账号体系、无 Cookie、无缓存。代码开源可自行验证与自建。

## 许可 / Licence

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
