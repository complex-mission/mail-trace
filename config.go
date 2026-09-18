package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

// ── 配置装配 ───────────────────────────────────────────────────────────────────
//
// 所有依赖环境变量的配置都必须在这里赋值，不能写成包级变量的初始化表达式。
//
// 原因是初始化顺序：包级变量在 main() 之前就求值完毕，而 .env 要到 main() 里
// 调 loadDotEnv() 才被读进环境。写成包级初始化的话，.env 里的 SITE_URL、
// MAIL_TRACE_TRUSTED_PROXIES、MAIL_TRACE_DNS、MAIL_TRACE_ALLOW_PRIVATE 全部
// 无声失效 —— 服务照常启动，只是限流按代理 IP 计数、canonical 指回原站、
// 解析器退回默认值。这类故障没有任何报错，只能靠盯日志发现，
// 所以宁可集中在一个函数里，也不散落成各文件的 var 初始化。
//
// 新增任何读环境变量的配置时，加在这里。

func initConfig() {
	// 站点地址：canonical / sitemap / OG / llms.txt 都用它
	if v := strings.TrimSpace(os.Getenv("SITE_URL")); v != "" {
		SiteURL = strings.TrimSuffix(v, "/")
	}

	// 内网目标与端口白名单的总开关
	AllowPrivateTargets = os.Getenv("MAIL_TRACE_ALLOW_PRIVATE") == "1"

	initDNSServers()
	initTrustedProxies()
	initShutdownGrace()
	initIndexHTML()
}

// initDNSServers 解析 MAIL_TRACE_DNS，留空则用内置默认。
func initDNSServers() {
	raw := os.Getenv("MAIL_TRACE_DNS")
	UsingDefaultDNS = raw == ""
	if UsingDefaultDNS {
		dnsServers = defaultDNSServers
		return
	}
	var out []string
	for _, s := range strings.Split(raw, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(s); err != nil {
			s = net.JoinHostPort(s, "53")
		}
		out = append(out, s)
	}
	if len(out) == 0 {
		log.Printf("warning: MAIL_TRACE_DNS yielded no resolvers, falling back to the default")
		dnsServers, UsingDefaultDNS = defaultDNSServers, true
		return
	}
	dnsServers = out
	log.Printf("DNS resolvers: %s", strings.Join(dnsServers, ", "))
}

// initTrustedProxies 解析 MAIL_TRACE_TRUSTED_PROXIES（CIDR 或单个 IP，逗号分隔）。
func initTrustedProxies() {
	trustedProxies = nil
	for _, part := range strings.Split(os.Getenv("MAIL_TRACE_TRUSTED_PROXIES"), ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, n, err := net.ParseCIDR(part); err == nil {
			trustedProxies = append(trustedProxies, n)
			continue
		}
		if ip := net.ParseIP(part); ip != nil {
			bits := 32
			if ip.To4() == nil {
				bits = 128
			}
			trustedProxies = append(trustedProxies, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
			continue
		}
		log.Printf("warning: %q in MAIL_TRACE_TRUSTED_PROXIES is not a valid IP or CIDR, ignoring", part)
	}
}

// initShutdownGrace 解析 SHUTDOWN_GRACE。
func initShutdownGrace() {
	v := os.Getenv("SHUTDOWN_GRACE")
	if v == "" {
		ShutdownGrace = defaultShutdownGrace
		return
	}
	d, err := time.ParseDuration(v)
	if err != nil || d < 0 {
		log.Printf("warning: SHUTDOWN_GRACE=%q is not a valid duration, using the default %s", v, defaultShutdownGrace)
		ShutdownGrace = defaultShutdownGrace
		return
	}
	ShutdownGrace = d
}

// initIndexHTML 读出内嵌页面，并把写死的原站域名替换成 SiteURL。
// 必须在 SiteURL 定下来之后调用。
func initIndexHTML() {
	b, err := templateFS.ReadFile("templates/index.html")
	if err != nil {
		panic("embed templates/index.html: " + err.Error())
	}
	if SiteURL != canonicalPlaceholder {
		b = bytes.ReplaceAll(b, []byte(canonicalPlaceholder), []byte(SiteURL))
	}
	sum := sha256.Sum256(b)
	indexHTML, indexETag = b, fmt.Sprintf("\"%x\"", sum[:8])
}
