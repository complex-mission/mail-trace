package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"mime/quotedprintable"
	"net"
	"net/http"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/joho/godotenv"
	"github.com/miekg/dns"
	"github.com/redis/go-redis/v9"
)

//go:embed templates/index.html
var templateFS embed.FS

// ── Types ──────────────────────────────────────────────────────────────────────

type Config struct {
	Host        string `json:"host"`
	Port        int    `json:"port"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	From        string `json:"from"`
	To          string `json:"to"`
	Lang        string `json:"lang"`
	DryRun      bool   `json:"dry_run"`
	InsecureTLS bool   `json:"insecure_tls"`
}

type Step struct {
	Name     string   `json:"name"`
	Status   string   `json:"status"` // ok, fail, warn, skip, info
	Detail   string   `json:"detail"`
	Response string   `json:"response"`
	Tips     []string `json:"tips,omitempty"`
	Timing   int64    `json:"timing_ms,omitempty"`
}

type TLSCertInfo struct {
	Subject   string   `json:"subject"`
	Issuer    string   `json:"issuer"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	DaysLeft  int      `json:"days_left"`
	SANs      []string `json:"sans"`
	Protocol  string   `json:"protocol"`
	Cipher    string   `json:"cipher"`
	Valid     bool     `json:"valid"`
}

type DNSResult struct {
	MX       []string       `json:"mx"`
	A        []string       `json:"a"`
	AAAA     []string       `json:"aaaa"`
	SPF      string         `json:"spf"`
	SPFValid *bool          `json:"spf_valid,omitempty"`
	DKIM     []DKIMRecord   `json:"dkim"`
	DMARC    string         `json:"dmarc"`
	DMARCPol string         `json:"dmarc_policy"`
	MXHosts  []string       `json:"mx_hosts,omitempty"`
	Policy   *PolicyRecords `json:"policy,omitempty"`
}

type DKIMRecord struct {
	Selector string `json:"selector"`
	Found    bool   `json:"found"`
	Record   string `json:"record,omitempty"`
}

type SMTPExtension struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
}

type TestResult struct {
	Steps      []Step                `json:"steps"`
	TotalMs    int64                 `json:"total_ms"`
	Summary    string                `json:"summary"`
	DNS        map[string]*DNSResult `json:"dns"`
	TLSCert    *TLSCertInfo          `json:"tls_cert,omitempty"`
	Extensions []SMTPExtension       `json:"extensions,omitempty"`
	ServerIP   string                `json:"server_ip,omitempty"`
	SPF        *SPFEval              `json:"spf_eval,omitempty"`
	SendingIP  *SendingIPInfo        `json:"sending_ip,omitempty"`
	DNSBL      []DNSBLResult         `json:"dnsbl,omitempty"`
}

type SSEEvent struct {
	Type string      `json:"type"` // step, dns, tls, extensions, done, error
	Data interface{} `json:"data"`
}

// ── i18n ───────────────────────────────────────────────────────────────────────

// L 是请求级语言。所有面向用户的文案都经过 L.T / L.F，
// 没有全局状态，并发请求各用各的语言。
type L string

func (l L) T(zh, en string) string {
	if l == "en" {
		return en
	}
	return zh
}

func (l L) F(zh, en string, a ...interface{}) string {
	return fmt.Sprintf(l.T(zh, en), a...)
}

// ── SMTP Connection ────────────────────────────────────────────────────────────

const smtpIOTimeout = 30 * time.Second

type SMTPConn struct {
	conn    net.Conn
	reader  *bufio.Reader
	tp      *textproto.Reader
	host    string
	timeout time.Duration
}

// dotStuff 转义以 "." 开头的行（RFC 5321 4.5.2），防止正文提前终止 DATA。
// 传入的 msg 必须以 CRLF 结尾。
// htmlEscape 只为邮件 HTML 分段转义正文，不需要 html/template 的上下文分析。
func htmlEscape(s string) string { return html.EscapeString(s) }

func dotStuff(msg string) string {
	return strings.ReplaceAll("\r\n"+msg, "\r\n.", "\r\n..")[2:]
}

// qpEncode 做 quoted-printable 编码：正文含非 ASCII（如 em dash），
// 不能声明 7bit，也不想依赖服务器是否支持 8BITMIME。
func qpEncode(s string) string {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	io.WriteString(w, s)
	w.Close()
	return buf.String()
}

func NewSMTPConn(host string, port int, useSSL bool, insecureTLS bool) (*SMTPConn, error) {
	// 必须用 JoinHostPort：IPv6 字面量要加方括号，直接拼 "%s:%d" 会拼出非法地址
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	var conn net.Conn
	var err error

	// Control 钩子在 connect 之前拿到最终 IP 再查一遍，挡住 DNS rebinding
	dialer := &net.Dialer{Timeout: 15 * time.Second, Control: dialControl}
	if useSSL {
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, &tls.Config{
			MinVersion:         tls.VersionTLS10,
			InsecureSkipVerify: insecureTLS,
		})
	} else {
		conn, err = dialer.Dial("tcp", addr)
	}
	if err != nil {
		return nil, err
	}

	reader := bufio.NewReader(conn)
	tp := textproto.NewReader(reader)
	return &SMTPConn{conn: conn, reader: reader, tp: tp, host: host, timeout: smtpIOTimeout}, nil
}

func (s *SMTPConn) SetTimeout(d time.Duration) {
	s.timeout = d
}

// touchDeadline 在每次 I/O 前刷新读写 deadline，避免服务器不应答时永久阻塞。
func (s *SMTPConn) touchDeadline() {
	if s.timeout > 0 {
		s.conn.SetDeadline(time.Now().Add(s.timeout))
	}
}

func (s *SMTPConn) ReadResponse() (int, string, error) {
	s.touchDeadline()
	code, msg, err := s.tp.ReadResponse(0)
	return code, msg, err
}

func (s *SMTPConn) SendCommand(cmd string) (int, string, error) {
	s.touchDeadline()
	if _, err := fmt.Fprintf(s.conn, "%s\r\n", cmd); err != nil {
		return 0, "", err
	}
	return s.ReadResponse()
}

func (s *SMTPConn) EnableTLS(serverName string, insecureTLS bool) (*tls.ConnectionState, error) {
	tlsConn := tls.Client(s.conn, &tls.Config{
		MinVersion:         tls.VersionTLS10,
		ServerName:         serverName,
		InsecureSkipVerify: insecureTLS,
	})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	state := tlsConn.ConnectionState()
	s.conn = tlsConn
	s.reader = bufio.NewReader(tlsConn)
	s.tp = textproto.NewReader(s.reader)
	return &state, nil
}

func (s *SMTPConn) Close() {
	s.conn.Close()
}

func (s *SMTPConn) RemoteAddr() net.Addr {
	return s.conn.RemoteAddr()
}

func (s *SMTPConn) LocalAddr() net.Addr {
	return s.conn.LocalAddr()
}

// ── SMTP Error Tips ────────────────────────────────────────────────────────────

func getErrorTips(lang L, code int, msg string) []string {
	msgLower := strings.ToLower(msg)
	var tips []string

	switch {
	case code == 421:
		tips = append(tips, lang.T("服务器临时不可用，可能达到连接数限制", "Server temporarily unavailable; the connection limit may have been reached."))
		tips = append(tips, lang.T("稍后重试，或检查是否有大量并发连接", "Retry later, or check for a large number of concurrent connections."))
	case code == 450:
		tips = append(tips, lang.T("邮箱暂时不可用，可能被灰名单拦截", "Mailbox temporarily unavailable; greylisting is a likely cause."))
		tips = append(tips, lang.T("等待几分钟后重试通常可解决", "Waiting a few minutes and retrying usually resolves this."))
	case code == 451:
		tips = append(tips, lang.T("服务器处理时出错，通常是临时限制", "The server hit a processing error, usually a temporary limit."))
	case code == 452:
		tips = append(tips, lang.T("服务器存储空间不足", "The server is out of storage space."))
	case code == 530 || code == 535:
		tips = append(tips, lang.T("认证失败，请检查用户名和密码", "Authentication failed. Check the username and password."))
		if strings.Contains(msgLower, "oauth") {
			tips = append(tips, lang.T("该服务器可能要求 OAuth2 认证而非密码", "This server may require OAuth2 instead of a password."))
		}
		tips = append(tips, lang.T("Gmail 需要使用「应用专用密码」而非账户密码", "Gmail requires an App Password, not your account password."))
		tips = append(tips, lang.T("Outlook 可能需要在安全设置中开启 SMTP 访问", "Outlook may require SMTP AUTH to be enabled in security settings."))
	case code == 550:
		tips = append(tips, lang.T("收件人地址不存在或被拒绝", "The recipient address does not exist or was rejected."))
		tips = append(tips, lang.T("检查收件人邮箱地址是否正确", "Verify the recipient address is correct."))
		if strings.Contains(msgLower, "relay") {
			tips = append(tips, lang.T("服务器拒绝中继：需要先认证才能发送到外部地址", "Relay denied: authentication is required before sending to external addresses."))
		}
	case code == 551:
		tips = append(tips, lang.T("用户不在服务器上，尝试通过其他邮箱转发", "User not local to this server; try forwarding through another mailbox."))
	case code == 552:
		tips = append(tips, lang.T("邮件大小超过服务器限制", "The message exceeds the server's size limit."))
	case code == 553:
		tips = append(tips, lang.T("邮箱地址格式不正确", "The mailbox address is malformed."))
	case code == 554:
		tips = append(tips, lang.T("交易失败或被拒绝", "The transaction failed or was refused."))
		if strings.Contains(msgLower, "spam") || strings.Contains(msgLower, "block") {
			tips = append(tips, lang.T("IP 可能被列入黑名单，检查 DNSBL 状态", "The IP may be blocklisted; check its DNSBL status."))
			tips = append(tips, lang.T("检查 SPF/DKIM/DMARC 认证记录是否正确配置", "Verify SPF / DKIM / DMARC records are configured correctly."))
		}
		if strings.Contains(msgLower, "too many") || strings.Contains(msgLower, "rate") {
			tips = append(tips, lang.T("发送频率过高，降低发送速率", "Sending rate is too high; slow down."))
		}
	case code >= 400 && code < 500:
		tips = append(tips, lang.T("临时错误，稍后重试", "Temporary error; retry later."))
	case code >= 500:
		tips = append(tips, lang.T("永久错误，需要修改配置后重试", "Permanent error; fix the configuration before retrying."))
	}

	if strings.Contains(msgLower, "tls") || strings.Contains(msgLower, "ssl") {
		tips = append(tips, lang.T("可能需要检查 TLS 版本兼容性", "TLS version compatibility may need checking."))
		tips = append(tips, lang.T("尝试切换端口（465=SSL, 587=STARTTLS）", "Try a different port (465 = SSL, 587 = STARTTLS)."))
	}

	return tips
}

// ── SMTP Capabilities Parse ────────────────────────────────────────────────────

func parseEHLOExtensions(msg string) []SMTPExtension {
	var exts []SMTPExtension
	lines := strings.Split(msg, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if len(line) < 5 {
			continue
		}
		// EHLO response lines start with "250-" or "250 "
		if !strings.HasPrefix(line, "250") {
			continue
		}
		parts := strings.SplitN(strings.TrimPrefix(strings.TrimPrefix(line, "250-"), "250 "), " ", 2)
		name := strings.TrimSpace(parts[0])
		if name == "" {
			continue
		}
		ext := SMTPExtension{Name: strings.ToUpper(name)}
		if len(parts) > 1 {
			ext.Value = strings.TrimSpace(parts[1])
		}
		exts = append(exts, ext)
	}

	// Sort: known extensions first
	known := map[string]bool{
		"STARTTLS": true, "AUTH": true, "SIZE": true,
		"PIPELINING": true, "8BITMIME": true, "SMTPUTF8": true,
		"ENHANCEDSTATUSCODES": true, "CHUNKING": true, "BINARYMIME": true,
	}
	sort.Slice(exts, func(i, j int) bool {
		ki := known[exts[i].Name]
		kj := known[exts[j].Name]
		if ki != kj {
			return ki
		}
		return exts[i].Name < exts[j].Name
	})

	return exts
}

// ── DNS Resolution ─────────────────────────────────────────────────────────────

var dnsServers = []string{"223.5.5.5:53", "119.29.29.29:53"}

func dnsQueryContext(ctx context.Context, msg *dns.Msg) (*dns.Msg, error) {
	c := &dns.Client{Timeout: 2 * time.Second}
	for _, server := range dnsServers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		resp, _, err := c.ExchangeContext(ctx, msg, server)
		if err == nil && resp != nil {
			return resp, nil
		}
	}
	return nil, fmt.Errorf("all DNS servers failed")
}

func dnsQuery(msg *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	return dnsQueryContext(ctx, msg)
}

func resolveDNS(domain string) *DNSResult {
	return resolveDNSContext(context.Background(), domain)
}

func resolveDNSContext(ctx context.Context, domain string) *DNSResult {
	r := &DNSResult{}

	// Parallel DNS queries
	var wg sync.WaitGroup
	var mu sync.Mutex

	// MX
	wg.Add(1)
	go func() {
		defer wg.Done()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeMX)
		if resp, err := dnsQueryContext(ctx, m); err == nil {
			mu.Lock()
			for _, ans := range resp.Answer {
				if mx, ok := ans.(*dns.MX); ok {
					host := strings.TrimSuffix(mx.Mx, ".")
					r.MX = append(r.MX, fmt.Sprintf("%s (priority %d)", host, mx.Preference))
					r.MXHosts = append(r.MXHosts, host)
				}
			}
			mu.Unlock()
		}
	}()

	// A
	wg.Add(1)
	go func() {
		defer wg.Done()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeA)
		if resp, err := dnsQueryContext(ctx, m); err == nil {
			mu.Lock()
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					r.A = append(r.A, a.A.String())
				}
			}
			mu.Unlock()
		}
	}()

	// AAAA
	wg.Add(1)
	go func() {
		defer wg.Done()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeAAAA)
		if resp, err := dnsQueryContext(ctx, m); err == nil {
			mu.Lock()
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.AAAA); ok {
					r.AAAA = append(r.AAAA, a.AAAA.String())
				}
			}
			mu.Unlock()
		}
	}()

	// TXT (SPF)
	wg.Add(1)
	go func() {
		defer wg.Done()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
		if resp, err := dnsQueryContext(ctx, m); err == nil {
			mu.Lock()
			for _, ans := range resp.Answer {
				if txt, ok := ans.(*dns.TXT); ok {
					full := strings.Join(txt.Txt, "")
					if strings.Contains(strings.ToLower(full), "v=spf") {
						r.SPF = full
						valid := validateSPF(full)
						r.SPFValid = &valid
					}
				}
			}
			mu.Unlock()
		}
	}()

	// DKIM - check common selectors (sequential with context)
	wg.Add(1)
	go func() {
		defer wg.Done()
		// 覆盖国内外主流服务商的默认选择器。DKIM 选择器无法枚举，
		// 探测不到只说明「不在这张表里」，不等于没配置。
		selectors := []string{
			// 通用 / 自建
			"default", "mail", "dkim", "smtp", "key1", "k1", "k2",
			"s1", "s2", "s1024", "s2048", "20230601", "stalwart",
			// Google Workspace
			"google",
			// Microsoft 365 / Outlook
			"selector1", "selector2",
			// 阿里云（企业邮 + 邮件推送 DirectMail）
			"aliyun", "aliyun-cn", "directmail", "mxhichina", "dm",
			// 腾讯企业邮 / QQ 邮箱
			"tencent", "qqmail", "exmail", "qcloud",
			// 网易企业邮
			"ym", "netease", "s110",
			// 第三方投递平台
			"mandrill", "sendgrid", "mailgun", "sm", "pm", "postmark",
			"zoho", "zmail", "mailjet", "sparkpost", "scph0322",
			// 常见自动化命名
			"cm", "email", "mta", "dkim1", "dkim2",
		}
		var records []DKIMRecord
		for _, sel := range selectors {
			select {
			case <-ctx.Done():
				break
			default:
			}
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(sel+"._domainkey."+domain), dns.TypeTXT)
			rec := DKIMRecord{Selector: sel}
			if resp, err := dnsQueryContext(ctx, m); err == nil && len(resp.Answer) > 0 {
				rec.Found = true
				for _, ans := range resp.Answer {
					if txt, ok := ans.(*dns.TXT); ok {
						rec.Record = strings.Join(txt.Txt, "")
					}
				}
			}
			if rec.Found {
				records = append(records, rec)
			}
		}
		mu.Lock()
		r.DKIM = records
		mu.Unlock()
	}()

	// DMARC
	wg.Add(1)
	go func() {
		defer wg.Done()
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn("_dmarc."+domain), dns.TypeTXT)
		if resp, err := dnsQueryContext(ctx, m); err == nil {
			mu.Lock()
			for _, ans := range resp.Answer {
				if txt, ok := ans.(*dns.TXT); ok {
					r.DMARC = strings.Join(txt.Txt, "")
					r.DMARCPol = extractDMARCPolicy(r.DMARC)
				}
			}
			mu.Unlock()
		}
	}()

	wg.Wait()

	// 现代策略记录（MTA-STS / TLS-RPT / BIMI / DANE），依赖上面拿到的 MX
	r.Policy = checkPolicyRecords(ctx, domain, r.MXHosts)

	return r
}

// reverseIP 生成 DNSBL 查询用的反转地址（RFC 5782）：IPv4 是四段倒序，
// IPv6 是 32 个半字节倒序。非法 IP 返回空串，调用方据此报错而不是发一个畸形查询——
// 畸形查询会全部无应答，在界面上伪装成「未列入任何黑名单」。
func reverseIP(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if v4 := parsed.To4(); v4 != nil {
		return fmt.Sprintf("%d.%d.%d.%d", v4[3], v4[2], v4[1], v4[0])
	}
	v6 := parsed.To16()
	if v6 == nil {
		return ""
	}
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, 63)
	for i := len(v6) - 1; i >= 0; i-- {
		buf = append(buf, hexDigits[v6[i]&0x0f], '.', hexDigits[v6[i]>>4])
		if i > 0 {
			buf = append(buf, '.')
		}
	}
	return string(buf)
}

func validateSPF(spf string) bool {
	spfLower := strings.ToLower(spf)
	return strings.HasPrefix(spfLower, "v=spf1")
}

// extractDMARCPolicy 取 p= 标签的值。必须按 ';' 切分再精确比较标签名：
// 子串匹配会把 sp=reject（子域策略）认成 p=reject，于是一个 p=none、
// 完全没有拦截保护的域名会被报成「Reject」，准入检查也跟着误判为通过。
func extractDMARCPolicy(dmarc string) string {
	for _, part := range strings.Split(dmarc, ";") {
		tag, val, ok := strings.Cut(part, "=")
		if !ok || !strings.EqualFold(strings.TrimSpace(tag), "p") {
			continue
		}
		switch strings.ToLower(strings.TrimSpace(val)) {
		case "reject":
			return "Reject"
		case "quarantine":
			return "Quarantine"
		case "none":
			return "None"
		}
		return ""
	}
	return ""
}

// ── TLS Certificate Info ──────────────────────────────────────────────────────

func getTLSCertInfo(conn *tls.ConnectionState) *TLSCertInfo {
	if conn == nil || len(conn.PeerCertificates) == 0 {
		return nil
	}
	cert := conn.PeerCertificates[0]
	daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)

	info := &TLSCertInfo{
		Subject:   cert.Subject.CommonName,
		Issuer:    cert.Issuer.CommonName,
		NotBefore: cert.NotBefore.Format("2006-01-02 15:04"),
		NotAfter:  cert.NotAfter.Format("2006-01-02 15:04"),
		DaysLeft:  daysLeft,
		SANs:      cert.DNSNames,
		Protocol:  tls.VersionName(conn.Version),
		Cipher:    tls.CipherSuiteName(conn.CipherSuite),
		Valid:     true,
	}

	if daysLeft < 0 {
		info.Valid = false
	}
	return info
}

// ── Main Test Logic ────────────────────────────────────────────────────────────

type StepWriter func(Step)

func testSMTPStream(cfg Config, rawEmit StepWriter) *TestResult {
	lang := L(cfg.Lang)
	result := &TestResult{DNS: make(map[string]*DNSResult)}
	start := time.Now()

	// 每个步骤在流给调用方的同时记进 result.Steps。SSE 的 done 事件、JSON 端点、
	// 以及本函数末尾的失败汇总都只认 result.Steps —— 只调 emit 会让它们全部拿到空列表，
	// 表现为「某一步 fail 了，总结却显示全部通过」。
	emit := func(s Step) {
		result.Steps = append(result.Steps, s)
		rawEmit(s)
	}

	port := cfg.Port
	useSSL := (port == 465)
	host := cfg.Host

	// ── Step 1: DNS resolution of SMTP host ──
	dnsStart := time.Now()
	ips, err := net.LookupHost(host)
	emit(Step{
		Name:   lang.T("DNS 解析", "DNS Resolution"),
		Status: boolToStatus(err == nil),
		Detail: func() string {
			if err != nil {
				return lang.T("解析失败", "resolution failed")
			}
			return fmt.Sprintf("%s → %s (%dms)", host, strings.Join(ips, ", "), time.Since(dnsStart).Milliseconds())
		}(),
		Timing: time.Since(dnsStart).Milliseconds(),
	})

	// ── Step 2: TCP Connect ──
	connStart := time.Now()
	conn, err := NewSMTPConn(host, port, useSSL, cfg.InsecureTLS)
	connMs := time.Since(connStart).Milliseconds()
	if err != nil {
		emit(Step{
			Name:     lang.T("TCP 连接", "TCP Connection"),
			Status:   "fail",
			Detail:   lang.F("连接 %s:%d 失败 (%dms)", "failed to connect to %s:%d (%dms)", host, port, connMs),
			Response: err.Error(),
			Timing:   connMs,
			Tips:     getTCPErrorTips(lang, err, host, port),
		})
		result.Summary = lang.F("TCP 连接失败: %s", "TCP connection failed: %s", err.Error())
		result.TotalMs = time.Since(start).Milliseconds()
		return result
	}
	emit(Step{
		Name:   lang.T("TCP 连接", "TCP Connection"),
		Status: "ok",
		Detail: lang.F("已连接 %s:%d (%dms)", "connected to %s:%d (%dms)", host, port, connMs),
		Timing: connMs,
	})

	// 后面的 PTR / SPF / DNSBL 全按这个 IP 判定，所以必须取「真正建连的那一个」，
	// 而不是 A 记录的第一条：多 A 记录、DNS 轮询或走 IPv6 时两者可能不是同一台机器。
	if ra, ok := conn.RemoteAddr().(*net.TCPAddr); ok && ra.IP != nil {
		result.ServerIP = ra.IP.String()
	} else if len(ips) > 0 {
		result.ServerIP = ips[0]
	}

	// ── Step 3: Banner ──
	bannerStart := time.Now()
	code, bannerMsg, _ := conn.ReadResponse()
	bannerMs := time.Since(bannerStart).Milliseconds()
	bannerOk := (code == 220)
	emit(Step{
		Name:     lang.T("服务器 Banner", "Server Banner"),
		Status:   boolToStatus(bannerOk),
		Detail:   fmt.Sprintf("Code %d (%dms)", code, bannerMs),
		Response: bannerMsg,
		Timing:   bannerMs,
		Tips: func() []string {
			if !bannerOk {
				return getErrorTips(lang, code, bannerMsg)
			}
			return nil
		}(),
	})
	if !bannerOk {
		conn.Close()
		result.Summary = lang.F("服务器拒绝连接: %s", "server refused the connection: %s", bannerMsg)
		result.TotalMs = time.Since(start).Milliseconds()
		return result
	}

	// ── Step 4: EHLO ──
	ehloStart := time.Now()
	ehloCode, ehloMsg, _ := conn.SendCommand("EHLO " + getHostname())
	ehloMs := time.Since(ehloStart).Milliseconds()
	ehloOk := (ehloCode == 250)
	emit(Step{
		Name:     lang.T("EHLO 握手", "EHLO Handshake"),
		Status:   boolToStatus(ehloOk),
		Detail:   fmt.Sprintf("Code %d (%dms)", ehloCode, ehloMs),
		Response: ehloMsg,
		Timing:   ehloMs,
		Tips: func() []string {
			if !ehloOk {
				return getErrorTips(lang, ehloCode, ehloMsg)
			}
			return nil
		}(),
	})

	// Parse extensions
	if ehloOk {
		extensions := parseEHLOExtensions(ehloMsg)
		result.Extensions = extensions
	}

	hasStartTLS := strings.Contains(strings.ToUpper(ehloMsg), "STARTTLS")

	// ── Step 5: STARTTLS (for port 587/25) ──
	// tlsActive 决定后面敢不敢发认证：AUTH LOGIN/PLAIN 只是 base64，不是加密。
	var tlsState *tls.ConnectionState
	tlsActive := false
	if port != 465 && hasStartTLS {
		tlsStart := time.Now()
		tlsCode, tlsMsg, _ := conn.SendCommand("STARTTLS")
		if tlsCode == 220 {
			var tlsErr error
			tlsState, tlsErr = conn.EnableTLS(host, cfg.InsecureTLS)
			tlsMs := time.Since(tlsStart).Milliseconds()
			tlsOk := (tlsErr == nil)
			result.TLSCert = getTLSCertInfo(tlsState)
			emit(Step{
				Name:   lang.T("STARTTLS 加密", "STARTTLS"),
				Status: boolToStatus(tlsOk),
				Detail: fmt.Sprintf("Code %d, TLS %s (%dms)", tlsCode, func() string {
					if tlsState != nil {
						return tls.VersionName(tlsState.Version)
					}
					return ""
				}(), tlsMs),
				Response: func() string {
					if tlsOk {
						return lang.T("TLS 握手成功", "TLS handshake succeeded")
					}
					return lang.F("TLS 失败: %s", "TLS failed: %s", tlsErr)
				}(),
				Timing: tlsMs,
				Tips: func() []string {
					if !tlsOk {
						return []string{lang.T("TLS 握手失败，可能是证书不受信任或域名不匹配", "TLS handshake failed: the certificate may be untrusted or the hostname may not match."), lang.T("勾选「跳过 TLS 证书校验」后可继续测试链路", "Enable \"Skip TLS certificate verification\" to keep testing the path."), lang.T("或切换到 465 端口 (SSL)", "Or switch to port 465 (implicit SSL).")}
					}
					return nil
				}(),
			})
			if tlsOk {
				tlsActive = true
				// 加密后必须重新读一遍能力集：明文阶段的 EHLO 通常不广告 AUTH，
				// 沿用那一份会让「服务器扩展」里缺掉用户最关心的一项。
				if code, msg, err := conn.SendCommand("EHLO " + getHostname()); err == nil && code == 250 {
					result.Extensions = parseEHLOExtensions(msg)
				}
			}
		} else {
			tlsMs := time.Since(tlsStart).Milliseconds()
			emit(Step{
				Name:     lang.T("STARTTLS 加密", "STARTTLS"),
				Status:   "fail",
				Detail:   fmt.Sprintf("Code %d (%dms)", tlsCode, tlsMs),
				Response: tlsMsg,
				Timing:   tlsMs,
				Tips:     getErrorTips(lang, tlsCode, tlsMsg),
			})
		}
	} else if port == 465 {
		// SSL already active, get cert info
		tlsActive = true
		if tlsConn, ok := conn.conn.(*tls.Conn); ok {
			st := tlsConn.ConnectionState()
			tlsState = &st
			result.TLSCert = getTLSCertInfo(tlsState)
		}
		emit(Step{
			Name:   lang.T("SSL/TLS 加密", "SSL/TLS"),
			Status: "ok",
			Detail: func() string {
				if result.TLSCert != nil {
					return fmt.Sprintf("%s, %s", result.TLSCert.Protocol, result.TLSCert.Cipher)
				}
				return lang.T("SSL 已启用", "SSL active")
			}(),
			Timing: 0,
		})
	} else if port != 465 && !hasStartTLS {
		emit(Step{
			Name:   "STARTTLS",
			Status: "warn",
			Detail: lang.T("服务器未提供 STARTTLS", "the server does not advertise STARTTLS"),
			Tips:   []string{lang.T("邮件将以明文传输，存在安全风险", "Mail would be sent in cleartext, which is a security risk."), lang.T("建议使用 465 (SSL) 或 587 (STARTTLS) 端口", "Prefer port 465 (SSL) or 587 (STARTTLS).")},
		})
	}

	// 认证前先确认信道已加密。AUTH LOGIN / PLAIN 只是 base64 编码，
	// 在明文连接上发送等于把密码交给链路上的任何人 —— 一个承诺「凭据不落盘」的
	// 工具更不该是泄露密码的那一环，所以这里宁可停下来报错。
	if !tlsActive && AllowPrivateTargets {
		// 内网自部署常见无 TLS 的测试服务器（MailHog 等）。这个开关本就声明「仅限内网」，
		// 所以降级为警告而不是中止，公网部署仍走下面的硬中止。
		emit(Step{
			Name:   lang.T("SMTP 认证", "SMTP Authentication"),
			Status: "warn",
			Detail: lang.T("信道未加密，凭据将以 base64 明文发送（已由 MAIL_TRACE_ALLOW_PRIVATE 放行）", "the channel is not encrypted; credentials will be sent as cleartext base64 (permitted by MAIL_TRACE_ALLOW_PRIVATE)"),
			Tips:   []string{lang.T("仅内网诊断可接受；请勿在公网链路上这样测试真实密码", "Acceptable for internal diagnostics only - never test a real password this way over the public internet.")},
		})
	} else if !tlsActive {
		emit(Step{
			Name:   lang.T("SMTP 认证", "SMTP Authentication"),
			Status: "fail",
			Detail: lang.T("信道未加密，已中止认证", "the channel is not encrypted; authentication was aborted"),
			Tips: []string{
				lang.T("AUTH LOGIN / PLAIN 只是 base64 编码而非加密，明文链路上发送密码等同泄露", "AUTH LOGIN / PLAIN is base64, not encryption - sending the password over a cleartext link discloses it."),
				lang.T("改用 465 端口（隐式 SSL），或确认服务器在 587 上支持 STARTTLS", "Use port 465 (implicit SSL), or make sure the server offers STARTTLS on 587."),
				lang.T("若 STARTTLS 是因证书问题握手失败，可勾选「跳过 TLS 证书校验」后重试", "If the STARTTLS handshake failed over the certificate, retry with \"Skip TLS certificate verification\" enabled."),
			},
		})
		conn.SendCommand("QUIT")
		conn.Close()
		result.Summary = lang.T("信道未加密，已中止认证以免明文发送密码", "aborted before authentication: the channel is not encrypted")
		result.TotalMs = time.Since(start).Milliseconds()
		return result
	}

	// ── Step 6: AUTH ──
	authStart := time.Now()
	authCode, _, _ := conn.SendCommand("AUTH LOGIN")
	if authCode == 334 {
		conn.SendCommand(base64.StdEncoding.EncodeToString([]byte(cfg.Username)))
		passCode, passMsg, _ := conn.SendCommand(base64.StdEncoding.EncodeToString([]byte(cfg.Password)))
		authMs := time.Since(authStart).Milliseconds()
		authOk := (passCode == 235)
		emit(Step{
			Name:     lang.T("SMTP 认证", "SMTP Authentication"),
			Status:   boolToStatus(authOk),
			Detail:   fmt.Sprintf("AUTH LOGIN, Code %d (%dms)", passCode, authMs),
			Response: passMsg,
			Timing:   authMs,
			Tips: func() []string {
				if !authOk {
					return getErrorTips(lang, passCode, passMsg)
				}
				return nil
			}(),
		})
		if !authOk {
			conn.SendCommand("QUIT")
			conn.Close()
			result.Summary = lang.F("认证失败: %s", "authentication failed: %s", passMsg)
			result.TotalMs = time.Since(start).Milliseconds()
			return result
		}
	} else {
		plain := "\x00" + cfg.Username + "\x00" + cfg.Password
		plainCode, plainMsg, _ := conn.SendCommand("AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte(plain)))
		authMs := time.Since(authStart).Milliseconds()
		authOk := (plainCode == 235)
		emit(Step{
			Name:     lang.T("SMTP 认证", "SMTP Authentication"),
			Status:   boolToStatus(authOk),
			Detail:   fmt.Sprintf("AUTH PLAIN, Code %d (%dms)", plainCode, authMs),
			Response: plainMsg,
			Timing:   authMs,
			Tips: func() []string {
				if !authOk {
					return getErrorTips(lang, plainCode, plainMsg)
				}
				return nil
			}(),
		})
		if !authOk {
			conn.SendCommand("QUIT")
			conn.Close()
			result.Summary = lang.F("认证失败: %s", "authentication failed: %s", plainMsg)
			result.TotalMs = time.Since(start).Milliseconds()
			return result
		}
	}

	// ── Step 7: MAIL FROM ──
	fromStart := time.Now()
	fromCode, fromMsg, _ := conn.SendCommand(fmt.Sprintf("MAIL FROM:<%s>", cfg.From))
	fromMs := time.Since(fromStart).Milliseconds()
	fromOk := (fromCode == 250)
	emit(Step{
		Name:     lang.T("MAIL FROM (发件人)", "MAIL FROM (sender)"),
		Status:   boolToStatus(fromOk),
		Detail:   fmt.Sprintf("<%s>, Code %d (%dms)", cfg.From, fromCode, fromMs),
		Response: fromMsg,
		Timing:   fromMs,
		Tips: func() []string {
			if !fromOk {
				return getErrorTips(lang, fromCode, fromMsg)
			}
			return nil
		}(),
	})

	// ── Step 8: RCPT TO ──
	rcptStart := time.Now()
	rcptCode, rcptMsg, _ := conn.SendCommand(fmt.Sprintf("RCPT TO:<%s>", cfg.To))
	rcptMs := time.Since(rcptStart).Milliseconds()
	rcptOk := (rcptCode == 250)
	emit(Step{
		Name:     lang.T("RCPT TO (收件人)", "RCPT TO (recipient)"),
		Status:   boolToStatus(rcptOk),
		Detail:   fmt.Sprintf("<%s>, Code %d (%dms)", cfg.To, rcptCode, rcptMs),
		Response: rcptMsg,
		Timing:   rcptMs,
		Tips: func() []string {
			if !rcptOk {
				return getErrorTips(lang, rcptCode, rcptMsg)
			}
			return nil
		}(),
	})
	if !rcptOk {
		conn.SendCommand("QUIT")
		conn.Close()
		result.Summary = lang.F("RCPT TO 被拒绝: %s", "RCPT TO rejected: %s", rcptMsg)
		result.TotalMs = time.Since(start).Milliseconds()
		return result
	}

	// ── Step 9: DATA ──
	dataStart := time.Now()
	if cfg.DryRun {
		// Dry run: skip DATA, just QUIT
		conn.SendCommand("QUIT")
		conn.Close()
		dataMs := time.Since(dataStart).Milliseconds()
		emit(Step{
			Name:   lang.T("DATA (发送邮件)", "DATA (message body)"),
			Status: "warn",
			Detail: lang.F("已跳过 (Dry Run) (%dms)", "skipped (dry run) (%dms)", dataMs),
			Timing: dataMs,
			Tips:   []string{lang.T("当前为仅检测模式，未实际发送邮件", "Dry-run mode: no message was actually delivered.")},
		})
		// Skip QUIT step since already done
		emit(Step{Name: lang.T("QUIT 断开", "QUIT"), Status: "ok", Detail: lang.T("连接已正常关闭", "connection closed cleanly")})
		result.TotalMs = time.Since(start).Milliseconds()
		return result
	} else {
		dataCode, dataMsg, _ := conn.SendCommand("DATA")
		if dataCode == 354 {
			date := time.Now().Format(time.RFC1123Z)
			msgID := fmt.Sprintf("%d@%s", time.Now().UnixNano(), host)
			body := fmt.Sprintf(
				"This is an automated diagnostic message generated by Mail Trace,\r\n"+
					"a tool for verifying SMTP delivery infrastructure.\r\n"+
					"\r\n"+
					"Purpose: To confirm that the sending server is correctly configured\r\n"+
					"and able to deliver mail to the intended recipient.\r\n"+
					"\r\n"+
					"  SMTP Host : %s:%d\r\n"+
					"  Sent At   : %s\r\n"+
					"  Message   : %s\r\n"+
					"\r\n"+
					"If you received this message in error or without expectation, you\r\n"+
					"may safely disregard it. No further messages will be sent.\r\n"+
					"\r\n"+
					"— Mail Trace Diagnostics\r\n",
				host, port, date, msgID)

			// HTML 分段：用 <pre> + 内联等宽字体栈。邮件客户端普遍会剥掉 <style>，
			// 所以样式必须写在元素上；pre-wrap 让窄屏下长行折行而不是横向滚动。
			htmlBody := "<!DOCTYPE html>\r\n" +
				"<html><body style=\"margin:0;padding:16px;background:#ffffff\">\r\n" +
				"<pre style=\"font-family:ui-monospace,SFMono-Regular,&#39;SF Mono&#39;,Menlo,Consolas,&#39;Liberation Mono&#39;,monospace;" +
				"font-size:13px;line-height:1.55;color:#1a1a1a;white-space:pre-wrap;word-break:break-word;margin:0\">" +
				htmlEscape(body) +
				"</pre>\r\n</body></html>\r\n"

			boundary := fmt.Sprintf("=_MailTrace_%d_%d", time.Now().UnixNano(), port)
			email := fmt.Sprintf(
				"From: <%s>\r\n"+
					"To: <%s>\r\n"+
					"Subject: [Mail Trace] Delivery Diagnostic Report - %s\r\n"+
					"Date: %s\r\n"+
					"Message-ID: <%s>\r\n"+
					"MIME-Version: 1.0\r\n"+
					"Content-Type: multipart/alternative; boundary=\"%s\"\r\n"+
					"X-Mailer: Mail Trace Diagnostics\r\n"+
					"\r\n"+
					"--%s\r\n"+
					"Content-Type: text/plain; charset=UTF-8\r\n"+
					"Content-Transfer-Encoding: quoted-printable\r\n"+
					"\r\n"+
					"%s\r\n"+
					"--%s\r\n"+
					"Content-Type: text/html; charset=UTF-8\r\n"+
					"Content-Transfer-Encoding: quoted-printable\r\n"+
					"\r\n"+
					"%s\r\n"+
					"--%s--\r\n",
				cfg.From, cfg.To, date, date, msgID, boundary,
				boundary, qpEncode(body),
				boundary, qpEncode(htmlBody),
				boundary)
			// email 已以 CRLF 结尾；DATA 终止符必须是完整的 <CRLF>.<CRLF>
			conn.SetTimeout(120 * time.Second) // 服务端可能做反垃圾扫描，这一步放宽
			if _, err := io.WriteString(conn.conn, dotStuff(email)+".\r\n"); err != nil {
				emit(Step{
					Name:   lang.T("DATA (发送邮件)", "DATA (message body)"),
					Status: "fail",
					Detail: lang.F("写入邮件正文失败: %v", "failed to write the message body: %v", err),
					Tips:   []string{lang.T("连接可能已被服务器中断", "The server may have dropped the connection.")},
				})
				conn.Close()
				result.Summary = lang.F("DATA 写入失败: %v", "DATA write failed: %v", err)
				result.TotalMs = time.Since(start).Milliseconds()
				return result
			}
			sendCode, sendMsg, sendErr := conn.ReadResponse()
			conn.SetTimeout(smtpIOTimeout)
			sendMs := time.Since(dataStart).Milliseconds()
			sendOk := (sendErr == nil && sendCode == 250)
			emit(Step{
				Name:   lang.T("DATA (发送邮件)", "DATA (message body)"),
				Status: boolToStatus(sendOk),
				Detail: func() string {
					if sendErr != nil {
						return lang.F("等待服务器应答失败: %v (%dms)", "failed while waiting for the server reply: %v (%dms)", sendErr, sendMs)
					}
					return fmt.Sprintf("Code %d (%dms)", sendCode, sendMs)
				}(),
				Response: sendMsg,
				Timing:   sendMs,
				Tips: func() []string {
					if sendErr != nil {
						return []string{lang.T("服务器在超时时间内未返回应答，连接可能已被中断", "The server did not reply within the timeout; the connection may have been cut.")}
					}
					if !sendOk {
						return getErrorTips(lang, sendCode, sendMsg)
					}
					return nil
				}(),
			})
		} else {
			dataMs := time.Since(dataStart).Milliseconds()
			emit(Step{
				Name:     lang.T("DATA (发送邮件)", "DATA (message body)"),
				Status:   "fail",
				Detail:   fmt.Sprintf("Code %d (%dms)", dataCode, dataMs),
				Response: dataMsg,
				Timing:   dataMs,
				Tips:     getErrorTips(lang, dataCode, dataMsg),
			})
		}
	}

	// ── Step 10: QUIT ──
	conn.SendCommand("QUIT")
	conn.Close()
	emit(Step{Name: lang.T("QUIT 断开", "QUIT"), Status: "ok", Detail: lang.T("连接已正常关闭", "connection closed cleanly")})

	// Summary
	for _, s := range result.Steps {
		if s.Status == "fail" {
			result.Summary = lang.F("在「%s」失败: %s", "failed at \"%s\": %s", s.Name, s.Detail)
			result.TotalMs = time.Since(start).Milliseconds()
			return result
		}
	}
	result.Summary = lang.T("所有步骤通过，邮件发送成功！", "All checks passed - the message was delivered.")
	result.TotalMs = time.Since(start).Milliseconds()
	return result
}

func getTCPErrorTips(lang L, err error, host string, port int) []string {
	errStr := err.Error()
	var tips []string
	if strings.Contains(errStr, "timeout") {
		tips = append(tips, lang.T("连接超时，服务器可能不可达或防火墙阻断", "Connection timed out; the server may be unreachable or blocked by a firewall."))
		tips = append(tips, lang.T("检查 SMTP 服务器地址和端口是否正确", "Check that the SMTP host and port are correct."))
		tips = append(tips, lang.F("尝试 telnet %s %d 测试连通性", "Try `telnet %s %d` to test reachability.", host, port))
	} else if strings.Contains(errStr, "connection refused") {
		tips = append(tips, lang.T("服务器拒绝连接，端口可能未开放", "Connection refused; the port may be closed."))
		tips = append(tips, lang.F("确认 %s:%d 是否是正确的 SMTP 地址", "Confirm that %s:%d is the correct SMTP endpoint.", host, port))
		tips = append(tips, lang.T("尝试其他端口: 25, 465, 587", "Try another port: 25, 465 or 587."))
	} else if strings.Contains(errStr, "no such host") {
		tips = append(tips, lang.T("域名无法解析，请检查 SMTP 服务器地址", "The hostname does not resolve; check the SMTP server address."))
		tips = append(tips, lang.T("尝试使用 IP 地址连接", "Try connecting by IP address."))
	} else if strings.Contains(errStr, "certificate") || strings.Contains(errStr, "tls") {
		tips = append(tips, lang.T("TLS 证书验证失败", "TLS certificate verification failed."))
		tips = append(tips, lang.T("如果使用自签名证书，尝试切换端口", "If you use a self-signed certificate, try a different port."))
	}
	return tips
}

// ── HTTP Handlers ──────────────────────────────────────────────────────────────

// indexHTML 是嵌入的页面字节。
//
// 这里刻意不走 html/template：页面里没有任何模板动作，而 html/template 为了做
// 上下文转义必须完整解析内联 JS，遇到正则字面量这类「除号还是正则」的歧义会执行
// 失败——而且失败时 header 已经发出，表现为 200 空响应，极难排查。静态页面直接
// 发字节，既没有这个风险，也省掉每次请求的转义开销。
var indexHTML, indexETag = func() ([]byte, string) {
	b, err := templateFS.ReadFile("templates/index.html")
	if err != nil {
		panic("embed templates/index.html: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return b, fmt.Sprintf("\"%x\"", sum[:8])
}()

func handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("ETag", indexETag)
	// 必须回源校验：否则改版后浏览器会继续用旧的 HTML/CSS
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	if match := r.Header.Get("If-None-Match"); match == indexETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Write(indexHTML)
}

// SSE streaming endpoint
func handleTestSSE(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// 请求体上限，避免超大 JSON 打满内存
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)

	var cfg Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}

	if cfg.Host == "" || cfg.Username == "" || cfg.Password == "" || cfg.From == "" || cfg.To == "" {
		http.Error(w, `{"error":"请填写所有必填字段 / all fields are required"}`, 400)
		return
	}

	if cfg.Port == 0 {
		cfg.Port = 587
	}

	// 端口白名单 + 内网地址拦截 + CRLF 注入拦截。
	// 缺了这一步，本服务等于一个「任意 host:port 探测并回显 banner」的对外扫描器，
	// 且 From/To 中的 CRLF 可以注入任意 SMTP 命令和邮件头。
	if err := ValidateConfig(&cfg); err != nil {
		msg, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(msg), 400)
		return
	}

	// SSE headers
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", 500)
		return
	}

	result := &TestResult{DNS: make(map[string]*DNSResult)}

	emit := func(step Step) {
		data, _ := json.Marshal(SSEEvent{Type: "step", Data: step})
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	// Run the test
	testResult := testSMTPStream(cfg, emit)
	result.Steps = testResult.Steps
	result.Summary = testResult.Summary
	result.TotalMs = testResult.TotalMs
	result.TLSCert = testResult.TLSCert
	result.Extensions = testResult.Extensions
	result.ServerIP = testResult.ServerIP

	// ── DNSBL + DNS: run with hard timeout via select ──
	fromDomain := cfg.From[strings.Index(cfg.From, "@")+1:]
	toDomain := cfg.To[strings.Index(cfg.To, "@")+1:]

	type dnsblOut struct {
		results []DNSBLResult
		elapsed int64
	}
	type dnsOut struct {
		from, to *DNSResult
		elapsed  int64
	}

	lang := L(cfg.Lang)

	// 识别服务商：决定 SPF / DNSBL 该针对哪个 IP 判定
	provider := DetectProvider(cfg.Host)
	providerName := ""
	if provider != nil {
		providerName = provider.Name
	}

	// Launch DNSBL
	dnsblCh := make(chan dnsblOut, 1)
	if result.ServerIP != "" {
		emit(Step{Name: lang.T("DNSBL 黑名单", "DNSBL Blocklists"), Status: "info", Detail: lang.F("正在查询发送 IP %s 的黑名单状态...", "checking blocklist status for sending IP %s...", result.ServerIP)})
		go func() {
			start := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			res := CheckDNSBL(ctx, result.ServerIP)
			dnsblCh <- dnsblOut{results: res, elapsed: time.Since(start).Milliseconds()}
		}()
	}

	// Launch DNS
	dnsCh := make(chan dnsOut, 1)
	emit(Step{Name: lang.T("DNS 记录检查", "DNS Records"), Status: "info", Detail: lang.F("正在解析 %s 和 %s 的 DNS 记录...", "resolving DNS records for %s and %s...", fromDomain, toDomain)})
	go func() {
		start := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		var wg sync.WaitGroup
		var mu sync.Mutex
		var fromDNS, toDNS *DNSResult
		wg.Add(2)
		go func() { defer wg.Done(); d := resolveDNSContext(ctx, fromDomain); mu.Lock(); fromDNS = d; mu.Unlock() }()
		go func() { defer wg.Done(); d := resolveDNSContext(ctx, toDomain); mu.Lock(); toDNS = d; mu.Unlock() }()
		wg.Wait()
		dnsCh <- dnsOut{from: fromDNS, to: toDNS, elapsed: time.Since(start).Milliseconds()}
	}()

	// Wait for DNSBL with hard timeout
	if result.ServerIP != "" {
		select {
		case out := <-dnsblCh:
			result.DNSBL = out.results
			var spamHits, policyHits, blockedZones []string
			var detailLines []string
			for _, r := range out.results {
				tag := lang.T("未列入", "not listed")
				switch r.Kind {
				case dnsblSpam:
					tag = lang.T("命中", "listed")
					if r.Advisory {
						tag = lang.T("命中（参考性列表）", "listed (advisory list)")
					} else {
						spamHits = append(spamHits, r.Blacklist)
					}
				case dnsblPolicy:
					tag = lang.T("策略列表", "policy list")
					policyHits = append(policyHits, r.Blacklist)
				case dnsblBlocked:
					tag = lang.T("查询被拒，结果不可信", "query refused - result unreliable")
					blockedZones = append(blockedZones, r.Blacklist)
				case dnsblError:
					tag = lang.T("查询失败", "query failed")
				}
				line := fmt.Sprintf("  %-16s %s (%dms)", r.Blacklist, tag, r.LatencyMs)
				if r.Meaning != "" {
					line += "\n      → " + r.Meaning
				}
				if len(r.Codes) > 0 {
					line += lang.T("\n      返回码: ", "\n      return codes: ") + strings.Join(r.Codes, ", ")
				}
				detailLines = append(detailLines, line)
			}
			resp := strings.Join(detailLines, "\n")

			usingRelay := providerName != ""
			switch {
			case len(spamHits) > 0:
				emit(Step{Name: lang.T("DNSBL 黑名单", "DNSBL Blocklists"), Status: "fail",
					Detail:   lang.F("%d 个垃圾源列表命中 (%dms)", "%d spam-source listing(s) (%dms)", len(spamHits), out.elapsed),
					Response: resp,
					Tips: []string{
						lang.T("SBL/XBL/SpamCop 这类列表命中属于硬问题：该 IP 有实际的垃圾邮件或被入侵记录", "A hit on SBL / XBL / SpamCop is a hard problem: the IP has a real record of spam or compromise."),
						lang.T("到对应列表官网做 delisting 申请；先确认服务器没有被利用发信（开放中继、账号泄露、Web 表单被滥用）", "Request delisting on the list's own site - but first make sure the server isn't being abused (open relay, leaked credentials, abused web forms)."),
					}})
			case len(policyHits) > 0 && !usingRelay:
				emit(Step{Name: lang.T("DNSBL 黑名单", "DNSBL Blocklists"), Status: "warn",
					Detail:   lang.F("命中策略类列表: %s (%dms)", "listed on policy list(s): %s (%dms)", strings.Join(policyHits, ", "), out.elapsed),
					Response: resp,
					Tips: []string{
						lang.T("PBL 不是垃圾邮件指控，它表示「这个 IP 段不应该直连对方 MX 发信」——云主机 IP 段默认基本都在里面", "PBL is not a spam accusation. It means \"this IP range should not connect directly to other MX hosts\" - most cloud IP ranges are in it by default."),
						lang.T("你当前是自建服务器直连投递，PBL 会被大量收件方直接拒收", "You are delivering directly from a self-hosted server, so PBL will cause many receivers to reject outright."),
						lang.T("两条出路：① 到 spamhaus.org 的 PBL Removal 页面为该 IP 申请移除（需 IP 有 PTR 且不是动态段）；② 改为通过服务商的中继/提交服务器投递（如阿里云邮件推送、SendGrid）", "Two ways out: (1) request removal on the Spamhaus PBL Removal page (the IP needs a PTR record and must not be in a dynamic range); (2) relay through a provider's submission service instead (Alibaba DirectMail, SendGrid, ...)."),
					}})
			case len(policyHits) > 0 && usingRelay:
				emit(Step{Name: lang.T("DNSBL 黑名单", "DNSBL Blocklists"), Status: "ok",
					Detail:   lang.F("仅命中策略类列表，对当前投递方式无影响 (%dms)", "only policy lists matched - no impact on your delivery path (%dms)", out.elapsed),
					Response: resp,
					Tips: []string{
						lang.F("你走的是 %s 的提交服务器，真正连对方 MX 的是服务商出口 IP，提交服务器的 PBL 状态不影响投递", "You submit through %s. The IP that actually connects to the recipient's MX is the provider's egress IP, so the submission host's PBL status does not affect delivery.", providerName),
					}})
			case len(blockedZones) > 0:
				emit(Step{Name: lang.T("DNSBL 黑名单", "DNSBL Blocklists"), Status: "warn",
					Detail:   lang.F("%d 个列表拒绝了查询 (%dms)", "%d list(s) refused the query (%dms)", len(blockedZones), out.elapsed),
					Response: resp,
					Tips: []string{
						"Spamhaus 等列表会拒绝来自公共 DNS（223.5.5.5 / 8.8.8.8 等）的查询，返回 127.255.255.x",
						lang.T("这不代表 IP 被列入。要拿到准确结果需在服务器上跑自己的递归 DNS，或申请 Spamhaus 数据源", "That does not mean the IP is listed. For a trustworthy answer, run your own recursive resolver on the server or apply for a Spamhaus data feed."),
					}})
			default:
				emit(Step{Name: lang.T("DNSBL 黑名单", "DNSBL Blocklists"), Status: "ok",
					Detail: lang.F("未在黑名单中 (%dms)", "not listed on any blocklist (%dms)", out.elapsed), Response: resp})
			}
		case <-time.After(11 * time.Second):
			emit(Step{Name: lang.T("DNSBL 黑名单", "DNSBL Blocklists"), Status: "warn", Detail: lang.T("查询超时 (11s)", "query timed out (11s)"), Tips: []string{lang.T("DNS 查询超时，可能网络不通或 DNS 服务器不可达", "DNS query timed out; the network or resolver may be unreachable.")}})
		}
	}

	// Wait for DNS with hard timeout
	select {
	case out := <-dnsCh:
		result.DNS["from"] = out.from
		result.DNS["to"] = out.to
		emit(Step{Name: lang.T("DNS 记录检查", "DNS Records"), Status: "ok", Detail: lang.F("发件人: %s, 收件人: %s (%dms)", "sender: %s, recipient: %s (%dms)", fromDomain, toDomain, out.elapsed)})
	case <-time.After(11 * time.Second):
		emit(Step{Name: lang.T("DNS 记录检查", "DNS Records"), Status: "warn", Detail: lang.T("DNS 解析超时 (11s)", "DNS resolution timed out (11s)"), Tips: []string{lang.T("DNS 查询超时，可能网络不通或 DNS 服务器不可达", "DNS query timed out; the network or resolver may be unreachable.")}})
	}

	// ── 发信 IP 反向解析 (PTR / FCrDNS) ──
	// 查的是实际建连的那个 IP，不是域名的 A 记录
	if result.ServerIP != "" {
		ctxPTR, cancelPTR := context.WithTimeout(context.Background(), 6*time.Second)
		info := checkSendingIP(ctxPTR, result.ServerIP)
		cancelPTR()
		info.HELOHost = getHostname()
		result.SendingIP = info
		switch {
		case provider != nil:
			emit(Step{Name: lang.T("发信 IP 反向解析", "Sending IP Reverse DNS"), Status: "ok",
				Detail: lang.F("经由 %s 中继投递，出口 IP 由服务商维护", "relayed through %s; the egress IP is managed by the provider", providerName),
				Response: func() string {
					if info.HasPTR {
						return lang.F("提交服务器 %s → PTR %s", "submission host %s -> PTR %s", info.IP, info.PTR)
					}
					return lang.F("提交服务器 %s 无 PTR（对中继投递无影响）", "submission host %s has no PTR (irrelevant for relayed delivery)", info.IP)
				}(),
				Tips: []string{lang.T("你连的是提交服务器，真正连对方 MX 的是服务商的出口 IP 池，PTR 由服务商负责", "You connect to a submission host. The provider's egress pool is what talks to the recipient's MX, and the provider owns those PTR records.")}})
		case !info.HasPTR:
			emit(Step{Name: lang.T("发信 IP 反向解析", "Sending IP Reverse DNS"), Status: "fail",
				Detail:   lang.F("%s 没有 PTR 记录", "%s has no PTR record", info.IP),
				Response: info.Note,
				Tips: []string{
					lang.T("自建邮件服务器必须有 PTR，否则 163/QQ/Gmail 等会直接拒收或判垃圾", "A self-hosted mail server must have a PTR record; without one, 163 / QQ / Gmail will reject or junk the mail."),
					lang.T("PTR 只能由 IP 的持有方设置：云服务器在控制台「反向解析/PTR」处提交工单或自助配置", "Only the IP's owner can set a PTR record - on a cloud server, use the console's reverse-DNS/PTR page or file a ticket."),
					lang.T("PTR 应指向你的 HELO 域名（如 mail.example.com），并保证该域名正查回同一个 IP", "The PTR should point at your HELO name (e.g. mail.example.com), and that name must resolve back to the same IP."),
				}})
		case !info.FCrDNS:
			emit(Step{Name: lang.T("发信 IP 反向解析", "Sending IP Reverse DNS"), Status: "warn",
				Detail:   lang.F("%s → %s，但正向解析对不上", "%s -> %s, but the forward lookup does not match", info.IP, info.PTR),
				Response: info.Note,
				Tips:     []string{lang.T("把 PTR 指向的域名加一条 A 记录指回这个 IP，使正反解析闭环（FCrDNS）", "Add an A record for the PTR hostname pointing back to this IP so forward and reverse agree (FCrDNS).")}})
		default:
			emit(Step{Name: lang.T("发信 IP 反向解析", "Sending IP Reverse DNS"), Status: "ok",
				Detail:   lang.F("%s → %s，正反解析一致", "%s -> %s, forward and reverse agree", info.IP, info.PTR),
				Response: lang.T("FCrDNS 通过", "FCrDNS verified")})
		}
	}

	// ── SPF 求值 ──
	// 真正展开 include/redirect 判断发信 IP 是否被授权，而不是只看记录存不存在
	{
		ctxSPF, cancelSPF := context.WithTimeout(context.Background(), 8*time.Second)
		if provider != nil {
			// 走中继：出口 IP 是服务商的池子，该验的是 SPF 里有没有包含服务商
			ev := &SPFEval{Domain: fromDomain, IP: result.ServerIP}
			ev.Record = spfRecordOf(ctxSPF, fromDomain)
			ev.Found = ev.Record != ""
			matched := ""
			for _, inc := range provider.Includes {
				if SPFHasInclude(ctxSPF, fromDomain, inc, 0) {
					matched = inc
					break
				}
			}
			if !ev.Found {
				ev.Result = "none"
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "fail",
					Detail: lang.F("%s 没有 SPF 记录", "%s has no SPF record", fromDomain),
					Tips: []string{
						lang.F("添加 TXT 记录: v=spf1 include:%s ~all", "Add a TXT record: v=spf1 include:%s ~all", provider.Includes[0]),
						lang.T("没有 SPF，收件方无法验证发信来源，进垃圾箱概率大幅上升", "Without SPF the receiver cannot verify the sending source, which sharply raises the odds of landing in spam."),
					}})
			} else if matched != "" {
				ev.Result = "pass"
				ev.MatchedBy = "include:" + matched
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "ok",
					Detail:   lang.F("已授权 %s (include:%s)", "authorized for %s (include:%s)", providerName, matched),
					Response: ev.Record})
			} else {
				ev.Result = "fail"
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "fail",
					Detail:   lang.F("SPF 未包含 %s 的发信来源", "SPF does not cover %s's sending sources", providerName),
					Response: ev.Record,
					Tips: []string{
						lang.F("在 SPF 中加入 include:%s", "Add include:%s to your SPF record.", provider.Includes[0]),
						lang.T("当前记录没有授权该服务商的出口 IP，收件方 SPF 校验会失败", "The current record does not authorize this provider's egress IPs, so SPF checks will fail at the receiver."),
					}})
			}
			result.SPF = ev
		} else if result.ServerIP != "" {
			ev := EvalSPF(ctxSPF, fromDomain, result.ServerIP)
			result.SPF = ev
			resp := ev.Record
			if len(ev.Chain) > 0 {
				resp += lang.T("\n\n展开过程:\n", "\n\nExpansion:\n") + strings.Join(ev.Chain, "\n")
			}
			if ev.Note != "" {
				resp += "\n\n" + ev.Note
			}
			switch ev.Result {
			case "pass":
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "ok",
					Detail:   lang.F("pass — %s 已被授权（匹配 %s，%d 次 DNS 查询）", "pass - %s is authorized (matched %s, %d DNS lookups)", ev.IP, ev.MatchedBy, ev.Lookups),
					Response: resp})
			case "fail":
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "fail",
					Detail:   lang.F("fail — %s 未被 %s 的 SPF 授权，且策略为 -all（硬失败）", "fail - %s is not authorized by %s's SPF, and the policy is -all (hard fail)", ev.IP, fromDomain),
					Response: resp,
					Tips: []string{
						lang.F("SPF 声明 -all 表示「除列出的 IP 外一律拒收」，而实际发信 IP %s 不在授权范围内", "-all means \"reject everything not listed\", and the actual sending IP %s is not in the authorized set.", ev.IP),
						lang.F("修法一：把发信 IP 加进去 —— v=spf1 ip4:%s include:... -all", "Fix 1: add the sending IP - v=spf1 ip4:%s include:... -all", ev.IP),
						lang.T("修法二：改为通过被授权的服务商中继投递", "Fix 2: relay through a provider that the record already authorizes."),
						lang.T("这是比黑名单更致命的问题：SPF 硬失败会被多数收件方直接拒收", "This is more damaging than a blocklist hit: an SPF hard fail is rejected outright by most receivers."),
					}})
			case "softfail":
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "warn",
					Detail:   lang.F("softfail — %s 未被授权，策略为 ~all（标记但不拒收）", "softfail - %s is not authorized; policy is ~all (mark, do not reject)", ev.IP),
					Response: resp,
					Tips:     []string{lang.T("~all 下邮件通常不会被拒，但会显著提高进垃圾箱的概率", "Under ~all mail is usually accepted but is far more likely to be filed as spam."), lang.F("把 %s 加入 SPF，或改走已授权的中继", "Add %s to the SPF record, or relay through an authorized service.", ev.IP)}})
			case "neutral":
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "warn",
					Detail:   lang.F("neutral — SPF 对 %s 未作表态", "neutral - SPF takes no position on %s", ev.IP),
					Response: resp,
					Tips:     []string{lang.T("?all 或缺少 all 机制等于没有保护，建议收紧为 ~all 或 -all 并列全发信 IP", "?all, or a missing all mechanism, gives no protection. Tighten to ~all or -all and list every sending IP.")}})
			case "none":
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "fail",
					Detail:   lang.F("%s 没有 SPF 记录", "%s has no SPF record", fromDomain),
					Response: ev.Note,
					Tips:     []string{lang.F("添加 TXT 记录: v=spf1 ip4:%s ~all", "Add a TXT record: v=spf1 ip4:%s ~all", ev.IP), lang.T("无 SPF 的域名在 163/QQ/Gmail 处信誉极低", "Domains without SPF have very poor reputation at 163, QQ and Gmail.")}})
			default:
				emit(Step{Name: lang.T("SPF 验证", "SPF Evaluation"), Status: "warn",
					Detail:   lang.F("permerror — SPF 记录无法正确求值（%d 次 DNS 查询）", "permerror - the SPF record cannot be evaluated (%d DNS lookups)", ev.Lookups),
					Response: resp,
					Tips:     []string{lang.T("RFC 7208 规定 SPF 求值最多 10 次 DNS 查询，超限的记录会被当作无效", "RFC 7208 caps SPF evaluation at 10 DNS lookups; records that exceed it are treated as invalid."), lang.T("合并或减少 include，改用 ip4 段直接列出", "Merge or drop includes and list ip4 ranges directly instead.")}})
			}
		}
		cancelSPF()
	}

	// Send TLS cert info
	if result.TLSCert != nil {
		data, _ := json.Marshal(SSEEvent{Type: "tls", Data: result.TLSCert})
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	// Send extensions
	if len(result.Extensions) > 0 {
		data, _ := json.Marshal(SSEEvent{Type: "extensions", Data: result.Extensions})
		fmt.Fprintf(w, "data: %s\n\n", data)
		flusher.Flush()
	}

	// Send DNS
	data, _ := json.Marshal(SSEEvent{Type: "dns", Data: result.DNS})
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()

	// Final result
	data, _ = json.Marshal(SSEEvent{Type: "done", Data: result})
	fmt.Fprintf(w, "data: %s\n\n", data)
	flusher.Flush()
}

// JSON endpoint (fallback)
func handleTest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// 请求体上限，避免超大 JSON 打满内存
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)

	var cfg Config
	if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}

	if cfg.Host == "" || cfg.Username == "" || cfg.Password == "" || cfg.From == "" || cfg.To == "" {
		http.Error(w, `{"error":"请填写所有必填字段 / all fields are required"}`, 400)
		return
	}

	if cfg.Port == 0 {
		cfg.Port = 587
	}

	// 端口白名单 + 内网地址拦截 + CRLF 注入拦截。
	// 缺了这一步，本服务等于一个「任意 host:port 探测并回显 banner」的对外扫描器，
	// 且 From/To 中的 CRLF 可以注入任意 SMTP 命令和邮件头。
	if err := ValidateConfig(&cfg); err != nil {
		msg, _ := json.Marshal(map[string]string{"error": err.Error()})
		http.Error(w, string(msg), 400)
		return
	}

	// 步骤由 testSMTPStream 自己记进 result.Steps，这里不需要额外收集
	result := testSMTPStream(cfg, func(Step) {})

	fromDomain := cfg.From[strings.Index(cfg.From, "@")+1:]
	toDomain := cfg.To[strings.Index(cfg.To, "@")+1:]
	result.DNS["from"] = resolveDNS(fromDomain)
	result.DNS["to"] = resolveDNS(toDomain)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}

// ── Utils ──────────────────────────────────────────────────────────────────────

func boolToStatus(ok bool) string {
	if ok {
		return "ok"
	}
	return "fail"
}

func getHostname() string {
	h, _ := os.Hostname()
	if h == "" {
		h = "localhost"
	}
	return h
}

// ── Rate Limiter ───────────────────────────────────────────────────────────────

type RateLimiter struct {
	client  *redis.Client
	maxReq  int
	window  time.Duration
	enabled bool
}

func NewRateLimiter(rdb *redis.Client, maxReq int, window time.Duration) *RateLimiter {
	return &RateLimiter{client: rdb, maxReq: maxReq, window: window, enabled: rdb != nil}
}

func (rl *RateLimiter) Allow(ctx context.Context, key string) (bool, int, error) {
	if !rl.enabled {
		return true, 0, nil
	}
	fullKey := "mail-trace:rl:" + key
	pipe := rl.client.TxPipeline()
	incr := pipe.Incr(ctx, fullKey)
	pipe.Expire(ctx, fullKey, rl.window)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, 0, err
	}
	count := int(incr.Val())
	remaining := rl.maxReq - count
	if remaining < 0 {
		remaining = 0
	}
	return count <= rl.maxReq, remaining, nil
}

func rateLimitMiddleware(rl *RateLimiter, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !rl.enabled {
			next(w, r)
			return
		}
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = "unknown"
		}
		ctx := context.Background()
		allowed, remaining, err := rl.Allow(ctx, ip)
		if err != nil {
			// Redis error: fail open
			next(w, r)
			return
		}
		w.Header().Set("X-RateLimit-Limit", strconv.Itoa(rl.maxReq))
		w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
		w.Header().Set("X-RateLimit-Window", rl.window.String())
		if !allowed {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", strconv.Itoa(int(rl.window.Seconds())))
			w.WriteHeader(http.StatusTooManyRequests)
			json.NewEncoder(w).Encode(map[string]string{
				"error": fmt.Sprintf("请求过于频繁，请 %d 秒后重试 / Too many requests, retry in %d seconds", int(rl.window.Seconds()), int(rl.window.Seconds())),
			})
			return
		}
		next(w, r)
	}
}

// ── Main ───────────────────────────────────────────────────────────────────────

func main() {
	// Load .env (ignore error if file doesn't exist)
	godotenv.Load()

	listen := "127.0.0.1:9013"
	if v := os.Getenv("LISTEN"); v != "" {
		listen = v
	}
	if len(os.Args) > 1 {
		listen = os.Args[1]
	}

	// Redis rate limiter (optional)
	var rl *RateLimiter
	if redisURL := os.Getenv("REDIS_URL"); redisURL != "" {
		opts, err := redis.ParseURL(redisURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "REDIS_URL 格式错误: %v\n", err)
			os.Exit(1)
		}
		rdb := redis.NewClient(opts)
		ctx := context.Background()
		if err := rdb.Ping(ctx).Err(); err != nil {
			fmt.Printf("Redis 连接失败，限流已跳过: %v\n", err)
		} else {
			maxReq := 10
			if v := os.Getenv("RATE_LIMIT_MAX"); v != "" {
				if n, err := strconv.Atoi(v); err == nil && n > 0 {
					maxReq = n
				}
			}
			window := time.Minute
			if v := os.Getenv("RATE_LIMIT_WINDOW"); v != "" {
				if d, err := time.ParseDuration(v); err == nil {
					window = d
				}
			}
			rl = NewRateLimiter(rdb, maxReq, window)
			fmt.Printf("Redis 限流已启用: %d 次 / %s\n", maxReq, window)
		}
	} else {
		fmt.Printf("未配置 REDIS_URL，限流已跳过\n")
	}

	http.HandleFunc("/", handleIndex)

	testStream := handleTestSSE
	testJSON := handleTest
	if rl != nil {
		testStream = rateLimitMiddleware(rl, handleTestSSE)
		testJSON = rateLimitMiddleware(rl, handleTest)
	}
	http.HandleFunc("/api/test", testJSON)
	http.HandleFunc("/api/test-stream", testStream)

	// 仅查记录，不需要凭据、不建立 SMTP 会话
	recordsJSON := handleRecords
	if rl != nil {
		recordsJSON = rateLimitMiddleware(rl, handleRecords)
	}
	http.HandleFunc("/api/records", recordsJSON)

	// SEO / AI 抓取
	http.HandleFunc("/robots.txt", handleRobots)
	http.HandleFunc("/sitemap.xml", handleSitemap)
	http.HandleFunc("/llms.txt", handleLLMs)
	http.HandleFunc("/og.svg", handleOGImage)

	fmt.Printf("Mail Trace 邮件链路诊断工具 已启动\n")
	fmt.Printf("访问地址: http://%s\n", listen)
	fmt.Printf("按 Ctrl+C 退出\n\n")

	if err := http.ListenAndServe(listen, nil); err != nil {
		fmt.Fprintf(os.Stderr, "启动失败: %v\n", err)
		os.Exit(1)
	}
}
