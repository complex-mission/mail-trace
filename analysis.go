package main

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// ── DNS 小工具 ─────────────────────────────────────────────────────────────────

func lookupTXT(ctx context.Context, name string) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeTXT)
	resp, err := dnsQueryContext(ctx, m)
	if err != nil || resp == nil {
		return nil
	}
	var out []string
	for _, ans := range resp.Answer {
		if txt, ok := ans.(*dns.TXT); ok {
			out = append(out, strings.Join(txt.Txt, ""))
		}
	}
	return out
}

func lookupIPs(ctx context.Context, name string) []net.IP {
	var ips []net.IP
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	if resp, err := dnsQueryContext(ctx, m); err == nil && resp != nil {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.A); ok {
				ips = append(ips, a.A)
			}
		}
	}
	m6 := new(dns.Msg)
	m6.SetQuestion(dns.Fqdn(name), dns.TypeAAAA)
	if resp, err := dnsQueryContext(ctx, m6); err == nil && resp != nil {
		for _, ans := range resp.Answer {
			if a, ok := ans.(*dns.AAAA); ok {
				ips = append(ips, a.AAAA)
			}
		}
	}
	return ips
}

func lookupMXHosts(ctx context.Context, name string) []string {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeMX)
	resp, err := dnsQueryContext(ctx, m)
	if err != nil || resp == nil {
		return nil
	}
	var out []string
	for _, ans := range resp.Answer {
		if mx, ok := ans.(*dns.MX); ok {
			out = append(out, strings.TrimSuffix(mx.Mx, "."))
		}
	}
	return out
}

func lookupPTR(ctx context.Context, ipStr string) []string {
	arpa, err := dns.ReverseAddr(ipStr)
	if err != nil {
		return nil
	}
	m := new(dns.Msg)
	m.SetQuestion(arpa, dns.TypePTR)
	resp, qerr := dnsQueryContext(ctx, m)
	if qerr != nil || resp == nil {
		return nil
	}
	var out []string
	for _, ans := range resp.Answer {
		if p, ok := ans.(*dns.PTR); ok {
			out = append(out, strings.TrimSuffix(p.Ptr, "."))
		}
	}
	return out
}

// ── 发信 IP 的反向解析 ─────────────────────────────────────────────────────────

// SendingIPInfo 针对「实际建立 SMTP 连接的那个 IP」做检查。
// 注意：不是域名的 A 记录——域名 A 记录通常指向网站，与发信毫无关系。
type SendingIPInfo struct {
	IP       string `json:"ip"`
	PTR      string `json:"ptr,omitempty"`
	HasPTR   bool   `json:"has_ptr"`
	FCrDNS   bool   `json:"fcrdns"`
	HELOHost string `json:"helo_host,omitempty"`
	Note     string `json:"note,omitempty"`
}

func checkSendingIP(ctx context.Context, ip string) *SendingIPInfo {
	info := &SendingIPInfo{IP: ip}
	names := lookupPTR(ctx, ip)
	if len(names) == 0 {
		info.Note = "该 IP 没有 PTR 记录。多数收件方（尤其 163/QQ/Gmail）会因此直接拒收或判垃圾。"
		return info
	}
	info.PTR = names[0]
	info.HasPTR = true
	// FCrDNS：PTR 指向的域名再正查回来，必须能解析回同一个 IP
	for _, got := range lookupIPs(ctx, info.PTR) {
		if got.String() == ip {
			info.FCrDNS = true
			break
		}
	}
	if !info.FCrDNS {
		info.Note = "PTR 存在但正向解析对不上（FCrDNS 失败），收件方仍可能判为不可信。"
	}
	return info
}

// ── SPF 求值（RFC 7208）─────────────────────────────────────────────────────────

// SPFEval 是真正的 SPF 求值结果，而不是「字符串以 v=spf1 开头」这种表面检查。
type SPFEval struct {
	Domain    string   `json:"domain"`
	IP        string   `json:"ip"`
	Record    string   `json:"record,omitempty"`
	Found     bool     `json:"found"`
	Result    string   `json:"result"` // pass / fail / softfail / neutral / none / permerror
	AllQual   string   `json:"all_qual,omitempty"`
	MatchedBy string   `json:"matched_by,omitempty"`
	Lookups   int      `json:"lookups"`
	Chain     []string `json:"chain,omitempty"`
	Note      string   `json:"note,omitempty"`
}

const spfMaxLookups = 10

func spfRecordOf(ctx context.Context, domain string) string {
	for _, t := range lookupTXT(ctx, domain) {
		s := strings.TrimSpace(t)
		if strings.HasPrefix(strings.ToLower(s), "v=spf1") {
			return s
		}
	}
	return ""
}

func qualResult(q byte) string {
	switch q {
	case '-':
		return "fail"
	case '~':
		return "softfail"
	case '?':
		return "neutral"
	default:
		return "pass"
	}
}

func cidrContains(ip net.IP, spec string, defV4, defV6 int) bool {
	host := spec
	bits := ""
	if i := strings.LastIndex(spec, "/"); i >= 0 {
		host, bits = spec[:i], spec[i+1:]
	}
	base := net.ParseIP(host)
	if base == nil {
		return false
	}
	if bits == "" {
		if base.To4() != nil {
			bits = strconv.Itoa(defV4)
		} else {
			bits = strconv.Itoa(defV6)
		}
	}
	n, err := strconv.Atoi(bits)
	if err != nil {
		return false
	}
	size := 32
	if base.To4() == nil {
		size = 128
	} else {
		base = base.To4()
	}
	if n < 0 || n > size {
		return false
	}
	mask := net.CIDRMask(n, size)
	cmp := ip
	if size == 32 {
		cmp = ip.To4()
	}
	if cmp == nil {
		return false
	}
	return cmp.Mask(mask).Equal(base.Mask(mask))
}

// EvalSPF 展开 include/redirect/a/mx/ip4/ip6/exists，判断 ip 是否被 domain 授权。
func EvalSPF(ctx context.Context, domain, ipStr string) *SPFEval {
	ev := &SPFEval{Domain: domain, IP: ipStr}
	rec := spfRecordOf(ctx, domain)
	if rec == "" {
		ev.Result = "none"
		ev.Note = "该域名没有 SPF 记录。收件方无法验证发信 IP，多数会扣信誉分。"
		return ev
	}
	ev.Found = true
	ev.Record = rec
	ip := net.ParseIP(ipStr)
	if ip == nil {
		ev.Result = "permerror"
		ev.Note = "未能确定发信 IP，无法求值。"
		return ev
	}
	lookups := 0
	res, matched := spfEvalRecord(ctx, domain, rec, ip, &lookups, 0, ev)
	ev.Lookups = lookups
	ev.Result = res
	ev.MatchedBy = matched
	return ev
}

func spfEvalRecord(ctx context.Context, domain, rec string, ip net.IP, lookups *int, depth int, ev *SPFEval) (string, string) {
	if depth > 10 {
		return "permerror", "include 递归层数超限"
	}
	if strings.Contains(rec, "%{") && ev.Note == "" {
		ev.Note = "记录中含宏（%{...}），本工具未展开宏，结果仅供参考。"
	}

	redirect := ""
	for _, term := range strings.Fields(rec) {
		if strings.EqualFold(term, "v=spf1") {
			continue
		}
		low := strings.ToLower(term)
		if strings.HasPrefix(low, "redirect=") {
			redirect = term[len("redirect="):]
			continue
		}
		if strings.HasPrefix(low, "exp=") {
			continue
		}

		qual := byte('+')
		if len(term) > 0 && (term[0] == '+' || term[0] == '-' || term[0] == '~' || term[0] == '?') {
			qual = term[0]
			term = term[1:]
			low = strings.ToLower(term)
		}

		name, arg := low, ""
		if i := strings.IndexAny(term, ":="); i >= 0 {
			name = strings.ToLower(term[:i])
			arg = term[i+1:]
		} else if i := strings.Index(term, "/"); i >= 0 {
			name = strings.ToLower(term[:i])
			arg = term[i:]
		}

		switch name {
		case "all":
			ev.AllQual = string(qual)
			ev.Chain = append(ev.Chain, fmt.Sprintf("%s%sall → %s", strings.Repeat("  ", depth), string(qual), qualResult(qual)))
			return qualResult(qual), string(qual) + "all"

		case "ip4", "ip6":
			if cidrContains(ip, arg, 32, 128) {
				ev.Chain = append(ev.Chain, fmt.Sprintf("%s%s:%s ✓ 命中", strings.Repeat("  ", depth), name, arg))
				return qualResult(qual), name + ":" + arg
			}

		case "a", "mx":
			*lookups++
			if *lookups > spfMaxLookups {
				ev.Note = fmt.Sprintf("SPF 的 DNS 查询次数超过 RFC 7208 上限 %d 次，严格的收件方会判 permerror 并当作没有 SPF。", spfMaxLookups)
				return "permerror", "查询次数超限"
			}
			target, cidr := domain, ""
			if arg != "" {
				t := arg
				if i := strings.Index(t, "/"); i >= 0 {
					cidr, t = t[i:], t[:i]
				}
				if t != "" {
					target = t
				}
			}
			var hosts []string
			if name == "a" {
				hosts = []string{target}
			} else {
				hosts = lookupMXHosts(ctx, target)
			}
			for _, h := range hosts {
				for _, got := range lookupIPs(ctx, h) {
					spec := got.String() + cidr
					if cidrContains(ip, spec, 32, 128) {
						ev.Chain = append(ev.Chain, fmt.Sprintf("%s%s:%s ✓ 命中 (%s)", strings.Repeat("  ", depth), name, target, h))
						return qualResult(qual), name + ":" + target
					}
				}
			}

		case "include":
			*lookups++
			if *lookups > spfMaxLookups {
				ev.Note = fmt.Sprintf("SPF 的 DNS 查询次数超过 RFC 7208 上限 %d 次，严格的收件方会判 permerror 并当作没有 SPF。", spfMaxLookups)
				return "permerror", "查询次数超限"
			}
			sub := spfRecordOf(ctx, arg)
			if sub == "" {
				ev.Chain = append(ev.Chain, fmt.Sprintf("%sinclude:%s ✗ 无 SPF 记录", strings.Repeat("  ", depth), arg))
				continue
			}
			ev.Chain = append(ev.Chain, fmt.Sprintf("%sinclude:%s → %s", strings.Repeat("  ", depth), arg, sub))
			subRes, subBy := spfEvalRecord(ctx, arg, sub, ip, lookups, depth+1, ev)
			if subRes == "permerror" {
				return "permerror", subBy
			}
			if subRes == "pass" {
				return qualResult(qual), "include:" + arg + " → " + subBy
			}

		case "exists":
			*lookups++
			if *lookups > spfMaxLookups {
				return "permerror", "查询次数超限"
			}
			if len(lookupIPs(ctx, arg)) > 0 {
				return qualResult(qual), "exists:" + arg
			}

		case "ptr":
			*lookups++
			if ev.Note == "" {
				ev.Note = "记录中使用了已废弃的 ptr 机制（RFC 7208 不建议），部分收件方会忽略它。"
			}
		}
	}

	if redirect != "" {
		*lookups++
		if *lookups > spfMaxLookups {
			return "permerror", "查询次数超限"
		}
		sub := spfRecordOf(ctx, redirect)
		if sub == "" {
			return "permerror", "redirect=" + redirect + " 无 SPF 记录"
		}
		ev.Chain = append(ev.Chain, fmt.Sprintf("%sredirect=%s", strings.Repeat("  ", depth), redirect))
		return spfEvalRecord(ctx, redirect, sub, ip, lookups, depth+1, ev)
	}

	return "neutral", "无匹配机制且无 all"
}

// ── DNSBL ──────────────────────────────────────────────────────────────────────

// dnsblKind 区分三类结果，混为一谈是大多数在线检测工具的通病：
//
//	spam   真·垃圾源/被入侵主机，命中才是硬问题
//	policy 策略列表（如 Spamhaus PBL），只在「直连对方 MX」时生效
//	blocked 查询被拒（用了公共 DNS 或超过免费额度），结果不可信
const (
	dnsblClean   = "clean"
	dnsblSpam    = "spam"
	dnsblPolicy  = "policy"
	dnsblBlocked = "blocked"
	dnsblError   = "error"
)

type DNSBLResult struct {
	Blacklist string   `json:"blacklist"`
	Zone      string   `json:"zone"`
	Kind      string   `json:"kind"`
	Listed    bool     `json:"listed"`
	Codes     []string `json:"codes,omitempty"`
	Meaning   string   `json:"meaning,omitempty"`
	Advisory  bool     `json:"advisory"` // 参考性列表，误报率高，不作为判定依据
	Error     string   `json:"error,omitempty"`
	LatencyMs int64    `json:"latency_ms"`
}

type dnsblZone struct {
	host     string
	label    string
	advisory bool
	classify func(code string) (kind string, meaning string)
}

func spamhausClassify(code string) (string, string) {
	switch code {
	case "127.0.0.2":
		return dnsblSpam, "SBL：已知垃圾邮件源"
	case "127.0.0.3":
		return dnsblSpam, "SBL CSS：疑似 snowshoe 垃圾邮件源"
	case "127.0.0.4", "127.0.0.5", "127.0.0.6", "127.0.0.7":
		return dnsblSpam, "XBL：被入侵/被利用的主机（僵尸网络、开放代理）"
	case "127.0.0.9":
		return dnsblSpam, "SBL DROP/EDROP：整段被劫持或专供滥用的地址段"
	case "127.0.0.10":
		return dnsblPolicy, "PBL（ISP 提交）：该 IP 段被其运营商声明为「不应直连 MX 发信」"
	case "127.0.0.11":
		return dnsblPolicy, "PBL（Spamhaus 维护）：该 IP 段被判定为终端/云主机通用段，不应直连 MX 发信"
	}
	if strings.HasPrefix(code, "127.255.255.") {
		return dnsblBlocked, "查询被 Spamhaus 拒绝（使用了公共 DNS 或超出免费额度），此结果不代表被列入"
	}
	return dnsblSpam, "返回码 " + code
}

func genericClassify(code string) (string, string) {
	if strings.HasPrefix(code, "127.255.255.") {
		return dnsblBlocked, "查询被拒绝（公共 DNS 或超出额度），结果不可信"
	}
	if strings.HasPrefix(code, "127.") {
		return dnsblSpam, "命中，返回码 " + code
	}
	return dnsblClean, ""
}

func uceprotectClassify(code string) (string, string) {
	if strings.HasPrefix(code, "127.255.255.") {
		return dnsblBlocked, "查询被拒绝，结果不可信"
	}
	return dnsblSpam, "UCEPROTECT L1：单 IP 命中（该列表误报率高，仅供参考）"
}

var dnsblZones = []dnsblZone{
	{"zen.spamhaus.org", "Spamhaus ZEN", false, spamhausClassify},
	{"bl.spamcop.net", "SpamCop", false, genericClassify},
	{"b.barracudacentral.org", "Barracuda", false, genericClassify},
	{"psbl.surriel.com", "PSBL", false, genericClassify},
	{"dnsbl-1.uceprotect.net", "UCEPROTECT L1", true, uceprotectClassify},
}

func CheckDNSBL(ctx context.Context, ip string) []DNSBLResult {
	rev := reverseIP(ip)
	results := make([]DNSBLResult, len(dnsblZones))
	if rev == "" {
		// 构造不出查询名。发畸形查询只会全部无应答，在界面上伪装成「未列入」——
		// 显式报错才不会让用户拿着一个假的「干净」结论去排查。
		for i, z := range dnsblZones {
			results[i] = DNSBLResult{Blacklist: z.label, Zone: z.host, Advisory: z.advisory,
				Kind: dnsblError, Error: "无法解析发信 IP / unparsable sending IP"}
		}
		return results
	}
	var wg sync.WaitGroup

	for i, z := range dnsblZones {
		wg.Add(1)
		go func(idx int, zone dnsblZone) {
			defer wg.Done()
			start := time.Now()
			r := DNSBLResult{Blacklist: zone.label, Zone: zone.host, Advisory: zone.advisory, Kind: dnsblClean}

			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn(rev+"."+zone.host), dns.TypeA)
			resp, err := dnsQueryContext(ctx, m)
			r.LatencyMs = time.Since(start).Milliseconds()

			if err != nil {
				r.Kind = dnsblError
				r.Error = err.Error()
				results[idx] = r
				return
			}
			for _, ans := range resp.Answer {
				if a, ok := ans.(*dns.A); ok {
					r.Codes = append(r.Codes, a.A.String())
				}
			}
			if len(r.Codes) == 0 {
				results[idx] = r
				return
			}
			// 多个返回码时，按严重度取最高：spam > policy > blocked
			var meanings []string
			for _, c := range r.Codes {
				kind, meaning := zone.classify(c)
				if meaning != "" {
					meanings = append(meanings, meaning)
				}
				switch {
				case kind == dnsblSpam:
					r.Kind = dnsblSpam
				case kind == dnsblPolicy && r.Kind != dnsblSpam:
					r.Kind = dnsblPolicy
				case kind == dnsblBlocked && r.Kind == dnsblClean:
					r.Kind = dnsblBlocked
				}
			}
			r.Meaning = strings.Join(meanings, "；")
			r.Listed = r.Kind == dnsblSpam || r.Kind == dnsblPolicy
			results[idx] = r
		}(i, z)
	}

	wg.Wait()
	return results
}

// ── 现代邮件安全策略记录 ───────────────────────────────────────────────────────

type PolicyRecords struct {
	MTASTS     string `json:"mta_sts,omitempty"`
	MTASTSMode string `json:"mta_sts_mode,omitempty"`
	TLSRPT     string `json:"tls_rpt,omitempty"`
	BIMI       string `json:"bimi,omitempty"`
	DANE       bool   `json:"dane"`
}

func checkPolicyRecords(ctx context.Context, domain string, mxHosts []string) *PolicyRecords {
	p := &PolicyRecords{}
	var wg sync.WaitGroup
	var mu sync.Mutex

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, t := range lookupTXT(ctx, "_mta-sts."+domain) {
			if strings.HasPrefix(strings.ToLower(t), "v=stsv1") {
				mu.Lock()
				p.MTASTS = t
				mu.Unlock()
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, t := range lookupTXT(ctx, "_smtp._tls."+domain) {
			if strings.HasPrefix(strings.ToLower(t), "v=tlsrptv1") {
				mu.Lock()
				p.TLSRPT = t
				mu.Unlock()
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for _, t := range lookupTXT(ctx, "default._bimi."+domain) {
			if strings.HasPrefix(strings.ToLower(t), "v=bimi1") {
				mu.Lock()
				p.BIMI = t
				mu.Unlock()
			}
		}
	}()

	// DANE：MX 主机上是否有 TLSA 记录
	if len(mxHosts) > 0 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := new(dns.Msg)
			m.SetQuestion(dns.Fqdn("_25._tcp."+mxHosts[0]), dns.TypeTLSA)
			if resp, err := dnsQueryContext(ctx, m); err == nil && resp != nil && len(resp.Answer) > 0 {
				mu.Lock()
				p.DANE = true
				mu.Unlock()
			}
		}()
	}

	wg.Wait()
	return p
}

// ── 服务商识别 ─────────────────────────────────────────────────────────────────

// 关键区别：用第三方提交服务器（587/465 + AUTH）时，真正连对方 MX 的是服务商的
// 出口 IP 池，不是你连的那台提交服务器。所以对这类配置，拿提交服务器 IP 去查
// SPF 和 DNSBL 都是错的——该查的是 SPF 里有没有包含服务商的 include。
type MailProvider struct {
	Name      string   `json:"name"`
	Hosts     []string `json:"-"`
	Includes  []string `json:"includes,omitempty"`
	SelfHosth bool     `json:"-"`
	Note      string   `json:"note,omitempty"`
}

var knownProviders = []MailProvider{
	{Name: "腾讯企业邮", Hosts: []string{"exmail.qq.com"}, Includes: []string{"spf.mail.qq.com"}},
	{Name: "QQ 邮箱", Hosts: []string{"smtp.qq.com"}, Includes: []string{"spf.mail.qq.com"}},
	{Name: "阿里企业邮（万网）", Hosts: []string{"mxhichina.com", "qiye.aliyun.com"}, Includes: []string{"spf.mxhichina.com"}},
	{Name: "阿里云邮件推送 DirectMail", Hosts: []string{"smtpdm.aliyun.com", "smtpdm-ap-southeast-1.aliyun.com", "dm.aliyun.com"}, Includes: []string{"spf1.dm.aliyun.com"}},
	{Name: "网易企业邮", Hosts: []string{"ym.163.com", "qiye.163.com"}, Includes: []string{"spf.163.com"}},
	{Name: "163/126 个人邮箱", Hosts: []string{"smtp.163.com", "smtp.126.com"}, Includes: []string{"spf.163.com"}},
	{Name: "263 企业邮", Hosts: []string{"263.net"}, Includes: []string{"263.net"}},
	{Name: "Gmail / Google Workspace", Hosts: []string{"smtp.gmail.com", "google.com"}, Includes: []string{"_spf.google.com"}},
	{Name: "Microsoft 365 / Outlook", Hosts: []string{"office365.com", "outlook.com", "hotmail.com"}, Includes: []string{"spf.protection.outlook.com"}},
	{Name: "SendGrid", Hosts: []string{"sendgrid.net"}, Includes: []string{"sendgrid.net"}},
	{Name: "Mailgun", Hosts: []string{"mailgun.org"}, Includes: []string{"mailgun.org"}},
	{Name: "Amazon SES", Hosts: []string{"amazonaws.com"}, Includes: []string{"amazonses.com"}},
	{Name: "Postmark", Hosts: []string{"postmarkapp.com"}, Includes: []string{"spf.mtasv.net"}},
	{Name: "Mailjet", Hosts: []string{"mailjet.com"}, Includes: []string{"spf.mailjet.com"}},
	{Name: "Zoho Mail", Hosts: []string{"zoho.com", "zoho.com.cn", "zoho.eu"}, Includes: []string{"zoho.com", "zohomail.com"}},
	{Name: "Xserver", Hosts: []string{"xserver.jp"}, Includes: []string{"xserver.jp"}},
	{Name: "SendCloud", Hosts: []string{"sendcloud.net", "sendcloud.org"}, Includes: []string{"sendcloud.org"}},
}

func DetectProvider(smtpHost string) *MailProvider {
	h := strings.ToLower(strings.TrimSuffix(smtpHost, "."))
	for i := range knownProviders {
		for _, suf := range knownProviders[i].Hosts {
			if h == suf || strings.HasSuffix(h, "."+suf) {
				return &knownProviders[i]
			}
		}
	}
	return nil
}

// SPFHasInclude 递归查找 SPF 链里是否出现某个 include 目标。
func SPFHasInclude(ctx context.Context, domain, want string, depth int) bool {
	if depth > 6 {
		return false
	}
	rec := spfRecordOf(ctx, domain)
	if rec == "" {
		return false
	}
	want = strings.ToLower(want)
	for _, term := range strings.Fields(rec) {
		low := strings.ToLower(strings.TrimLeft(term, "+-~?"))
		var target string
		if strings.HasPrefix(low, "include:") {
			target = low[len("include:"):]
		} else if strings.HasPrefix(low, "redirect=") {
			target = low[len("redirect="):]
		} else {
			continue
		}
		if target == want || strings.HasSuffix(target, "."+want) {
			return true
		}
		if SPFHasInclude(ctx, target, want, depth+1) {
			return true
		}
	}
	return false
}
