package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// ── 客户端 IP ──────────────────────────────────────────────────────────────────

// trustedProxies 决定要不要采信 X-Forwarded-For / X-Real-IP。
//
// 默认为空，也就是一律以 RemoteAddr 为准。无条件相信 XFF 会让限流形同虚设——
// 任何人加一个伪造的头就能换一个新桶；而完全不看它，在反向代理后面又会让
// 所有用户共用代理那一个 IP 的桶（README 里的 nginx 配置正是这种部署）。
// 两头都错，所以交给部署方用 MAIL_TRACE_TRUSTED_PROXIES 显式声明代理网段，
// 逗号分隔，接受 CIDR 或单个 IP。
var trustedProxies []*net.IPNet

func isTrustedProxy(ip net.IP) bool {
	if ip == nil {
		return false
	}
	for _, n := range trustedProxies {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// ClientIP 返回限流该用哪个地址计数。
//
// RemoteAddr 不在可信代理名单里就直接用它——这时任何 XFF 都是客户端自己写的，不可信。
// 在名单里才从右往左扫 X-Forwarded-For，跳过同样可信的跳数，取第一个不可信的地址：
// 那是链路上最后一个我们无法伪造的来源。X-Real-IP 作为兜底，只在可信代理后面才看。
func ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remote := net.ParseIP(host)
	if !isTrustedProxy(remote) {
		if host == "" {
			return "unknown"
		}
		return host
	}

	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		for i := len(parts) - 1; i >= 0; i-- {
			ip := net.ParseIP(strings.TrimSpace(parts[i]))
			if ip == nil {
				continue
			}
			if !isTrustedProxy(ip) {
				return ip.String()
			}
		}
	}
	if xr := strings.TrimSpace(r.Header.Get("X-Real-IP")); xr != "" {
		if ip := net.ParseIP(xr); ip != nil {
			return ip.String()
		}
	}
	if host == "" {
		return "unknown"
	}
	return host
}

// ── 并发上限 ───────────────────────────────────────────────────────────────────

// 一次完整诊断会开一条 SMTP 会话，外加上百次 DNS 查询（光 DKIM 选择器探测就有几十个）。
// 没有上限时，几十个并发请求就能把出站连接数和 DNS 配额打满，而限流是可选的、
// 且 Redis 故障时 fail-open。这里是最后一道闸。
type inFlight struct {
	sem chan struct{}
	n   atomic.Int64
}

func newInFlight(max int) *inFlight {
	if max <= 0 {
		return nil
	}
	return &inFlight{sem: make(chan struct{}, max)}
}

func (f *inFlight) guard(next http.HandlerFunc) http.HandlerFunc {
	if f == nil {
		return next
	}
	return func(w http.ResponseWriter, r *http.Request) {
		select {
		case f.sem <- struct{}{}:
			f.n.Add(1)
			defer func() { f.n.Add(-1); <-f.sem }()
			next(w, r)
		default:
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Retry-After", "30")
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"error":"服务器正忙，请稍后重试 / server busy, please retry shortly"}`))
		}
	}
}

// ── 访问日志 ───────────────────────────────────────────────────────────────────

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	s.status = code
	s.ResponseWriter.WriteHeader(code)
}

// Flush 必须透传，否则 SSE 的 flusher 断言会失败、整个流式输出退化成一次性响应。
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// withLogging 只记录方法、路径、状态码、耗时和客户端 IP。
// 请求体里全是邮箱密码，任何情况下都不碰。
func withLogging(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next(rec, r)
		log.Printf("%s %s %d %dms %s", r.Method, r.URL.Path, rec.status,
			time.Since(start).Milliseconds(), ClientIP(r))
	}
}

// ── 服务器 ─────────────────────────────────────────────────────────────────────

// ShutdownGrace 是收到退出信号后留给进行中诊断的收尾时间。
//
// 默认 90 秒是按最坏情况取的：DATA 阶段会把超时放宽到 120 秒等服务端反垃圾扫描。
// 但进程管理器往往等不了那么久 —— supervisor 的 stopwaitsecs 默认 10 秒，
// 超时就 SIGKILL，优雅退出等于没有。所以放开成可配置，
// 让它能和所在平台的停止超时对齐（设 0 表示不等待，立即关闭）。
var ShutdownGrace = defaultShutdownGrace

const defaultShutdownGrace = 90 * time.Second

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
		log.Printf("警告: %s=%q 不是合法的非负整数，用默认值 %d", key, os.Getenv(key), def)
	}
	return def
}

func newServer(addr string, h http.Handler) *http.Server {
	return &http.Server{
		Addr:    addr,
		Handler: h,
		// 没有这些超时，一条只发半行头就挂住的连接可以一直占着 goroutine（Slowloris）。
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		IdleTimeout:       120 * time.Second,
		// WriteTimeout 必须留空：完整诊断走 SSE，一条响应可能持续一分钟以上，
		// 设了就会在中途把流掐断。超时由每个 handler 自己的 context 负责。
		WriteTimeout: 0,
		ErrorLog:     log.Default(),
	}
}

// shutdownOnSignal 收到 SIGINT/SIGTERM 后停止接受新连接，
// 并给进行中的诊断留出收尾时间（SMTP 会话中途被砍会在对端留下半截事务）。
func shutdownOnSignal(ctx context.Context, srv *http.Server, grace time.Duration) {
	<-ctx.Done()
	log.Printf("收到退出信号，停止接受新请求，最多等待 %s 让进行中的诊断收尾", grace)
	shutCtx, cancel := context.WithTimeout(context.Background(), grace)
	defer cancel()
	if err := srv.Shutdown(shutCtx); err != nil {
		log.Printf("优雅退出超时，强制关闭: %v", err)
		srv.Close()
	}
}
