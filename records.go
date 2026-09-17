package main

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ── 仅查记录模式 ───────────────────────────────────────────────────────────────
//
// 用户刚改完 DNS，想知道「记录生效了吗、配对了吗、Gmail 会不会收」，
// 这时候不该要求他交出邮箱密码。本接口只做 DNS 侧检查：不建 SMTP 会话、不需要凭据。

type RecordsRequest struct {
	Domain    string   `json:"domain"`
	IP        string   `json:"ip"`        // 可选：实际发信 IP，用于 SPF 求值 / PTR / DNSBL
	Selectors []string `json:"selectors"` // 可选：额外的 DKIM 选择器
	Lang      string   `json:"lang"`
}

// ReceiverCheck 表示某一条「收件方准入要求」的核对结果。
type ReceiverCheck struct {
	Key      string `json:"key"`
	Label    string `json:"label"`
	Status   string `json:"status"` // ok / fail / warn / na
	Detail   string `json:"detail"`
	Required string `json:"required"` // all / bulk —— 对所有发件人还是仅对大批量发件人强制
}

type ReceiverReadiness struct {
	Receiver string          `json:"receiver"`
	Note     string          `json:"note"`
	Verdict  string          `json:"verdict"` // ok / warn / fail
	Checks   []ReceiverCheck `json:"checks"`
}

type RecordsResult struct {
	Domain    string               `json:"domain"`
	IP        string               `json:"ip,omitempty"`
	DNS       *DNSResult           `json:"dns"`
	SPF       *SPFEval             `json:"spf,omitempty"`
	SendingIP *SendingIPInfo       `json:"sending_ip,omitempty"`
	DNSBL     []DNSBLResult        `json:"dnsbl,omitempty"`
	Readiness []*ReceiverReadiness `json:"readiness"`
	Summary   string               `json:"summary"`
	TotalMs   int64                `json:"total_ms"`
}

func handleRecords(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":"method not allowed"}`, 405)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 16*1024)

	var req RecordsRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, `{"error":"invalid json"}`, 400)
		return
	}

	req.Domain = strings.TrimSpace(strings.ToLower(req.Domain))
	// 允许直接粘邮箱地址
	if i := strings.LastIndex(req.Domain, "@"); i >= 0 {
		req.Domain = req.Domain[i+1:]
	}
	req.Domain = strings.TrimSuffix(req.Domain, ".")

	if err := ValidateHost(req.Domain); err != nil || !strings.Contains(req.Domain, ".") {
		http.Error(w, `{"error":"请填写有效的域名 / please provide a valid domain"}`, 400)
		return
	}
	req.IP = strings.TrimSpace(req.IP)
	if req.IP != "" && net.ParseIP(req.IP) == nil {
		http.Error(w, `{"error":"发信 IP 格式不正确 / malformed sending IP"}`, 400)
		return
	}
	if len(req.Selectors) > 8 {
		req.Selectors = req.Selectors[:8]
	}
	for i, sel := range req.Selectors {
		sel = strings.TrimSpace(strings.ToLower(sel))
		if ctlChars.MatchString(sel) || len(sel) > 63 {
			http.Error(w, `{"error":"DKIM 选择器不合法 / invalid DKIM selector"}`, 400)
			return
		}
		req.Selectors[i] = sel
	}

	lang := L(req.Lang)
	start := time.Now()
	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	res := &RecordsResult{Domain: req.Domain, IP: req.IP}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); res.DNS = resolveDNSContext(ctx, req.Domain) }()

	if req.IP != "" {
		wg.Add(1)
		go func() { defer wg.Done(); res.SendingIP = checkSendingIP(ctx, req.IP) }()
		wg.Add(1)
		go func() { defer wg.Done(); res.DNSBL = CheckDNSBL(ctx, req.IP) }()
	}
	wg.Wait()

	// 额外的 DKIM 选择器（用户自己知道选择器名时，比盲探准确得多）
	if len(req.Selectors) > 0 && res.DNS != nil {
		seen := map[string]bool{}
		for _, d := range res.DNS.DKIM {
			seen[d.Selector] = true
		}
		for _, sel := range req.Selectors {
			if sel == "" || seen[sel] {
				continue
			}
			if txts := lookupTXT(ctx, sel+"._domainkey."+req.Domain); len(txts) > 0 {
				res.DNS.DKIM = append(res.DNS.DKIM, DKIMRecord{Selector: sel, Found: true, Record: strings.Join(txts, "")})
			} else {
				res.DNS.DKIM = append(res.DNS.DKIM, DKIMRecord{Selector: sel, Found: false})
			}
		}
	}

	// SPF：有 IP 就真求值；没有 IP 只能做语法与查询次数的静态检查
	if req.IP != "" {
		res.SPF = EvalSPF(ctx, req.Domain, req.IP)
	} else {
		res.SPF = staticSPF(ctx, req.Domain)
	}

	res.Readiness = buildReadiness(lang, res)
	res.Summary = readinessSummary(lang, res.Readiness)
	res.TotalMs = time.Since(start).Milliseconds()

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	json.NewEncoder(w).Encode(res)
}

// staticSPF 在不知道发信 IP 时，仍然把记录展开一遍，
// 以便报告「语法是否有效」和「是否超过 10 次 DNS 查询上限」这两个与 IP 无关的问题。
func staticSPF(ctx context.Context, domain string) *SPFEval {
	ev := &SPFEval{Domain: domain}
	rec := spfRecordOf(ctx, domain)
	if rec == "" {
		ev.Result = "none"
		ev.Note = "该域名没有 SPF 记录 / no SPF record"
		return ev
	}
	ev.Found = true
	ev.Record = rec
	// 用一个不可能命中的文档地址走一遍，只为统计查询次数和拿到 all 的限定符
	lookups := 0
	probe := net.ParseIP("192.0.2.1")
	res, _ := spfEvalRecord(ctx, domain, rec, probe, &lookups, 0, ev)
	ev.Lookups = lookups
	ev.Chain = nil // 探测地址的展开过程对用户没有意义
	if lookups > spfMaxLookups {
		ev.Result = "permerror"
	} else {
		ev.Result = "unknown" // 未提供 IP，无法给出 pass/fail
		_ = res
	}
	return ev
}

// ── 收件方准入检查 ─────────────────────────────────────────────────────────────
//
// 依据各家公开的发件人要求。Google 与 Yahoo 自 2024 年 2 月起、
// Microsoft 自 2025 年 5 月起，对大批量发件人强制 SPF + DKIM + DMARC 三件套。

func buildReadiness(lang L, res *RecordsResult) []*ReceiverReadiness {
	d := res.DNS
	if d == nil {
		d = &DNSResult{}
	}

	hasSPF := d.SPF != ""
	spfOK := hasSPF && (res.SPF == nil || res.SPF.Result != "permerror")
	spfIPOK := res.SPF != nil && res.SPF.Result == "pass"
	spfIPBad := res.SPF != nil && (res.SPF.Result == "fail" || res.SPF.Result == "softfail")

	hasDKIM := false
	for _, k := range d.DKIM {
		if k.Found {
			hasDKIM = true
			break
		}
	}
	hasDMARC := d.DMARC != ""
	pol := strings.ToLower(d.DMARCPol)

	hasPTR := res.SendingIP != nil && res.SendingIP.HasPTR
	fcrdns := res.SendingIP != nil && res.SendingIP.FCrDNS
	ipKnown := res.IP != ""

	spamListed := false
	for _, b := range res.DNSBL {
		if b.Kind == dnsblSpam && !b.Advisory {
			spamListed = true
		}
	}

	mk := func(key, label, status, detail, req string) ReceiverCheck {
		return ReceiverCheck{Key: key, Label: label, Status: status, Detail: detail, Required: req}
	}

	spfCheck := func() ReceiverCheck {
		switch {
		case !hasSPF:
			return mk("spf", "SPF", "fail", lang.T("没有 SPF 记录", "No SPF record"), "all")
		case !spfOK:
			return mk("spf", "SPF", "fail",
				lang.F("SPF 求值 permerror（%d 次 DNS 查询，超过 RFC 7208 上限 10 次），收件方会当作没有 SPF",
					"SPF permerror (%d DNS lookups, over the RFC 7208 limit of 10); receivers treat this as no SPF", res.SPF.Lookups), "all")
		case spfIPBad:
			return mk("spf", "SPF", "fail",
				lang.F("记录有效，但发信 IP %s 未被授权（结果 %s）",
					"Record is valid, but sending IP %s is not authorized (result: %s)", res.IP, res.SPF.Result), "all")
		case spfIPOK:
			return mk("spf", "SPF", "ok", lang.F("发信 IP %s 已被授权", "Sending IP %s is authorized", res.IP), "all")
		default:
			return mk("spf", "SPF", "warn",
				lang.T("记录存在且语法有效。填入发信 IP 后可验证该 IP 是否真的被授权",
					"Record exists and parses. Provide a sending IP to verify that the IP is actually authorized"), "all")
		}
	}

	dkimCheck := func() ReceiverCheck {
		if hasDKIM {
			return mk("dkim", "DKIM", "ok", lang.T("已找到公钥记录", "Public key record found"), "all")
		}
		return mk("dkim", "DKIM", "warn",
			lang.T("未探测到。DKIM 选择器无法枚举——如果你知道选择器名，填进去再测一次",
				"Not detected. DKIM selectors cannot be enumerated - if you know yours, enter it and re-check"), "all")
	}

	dmarcCheck := func() ReceiverCheck {
		switch {
		case !hasDMARC:
			return mk("dmarc", "DMARC", "fail", lang.T("没有 _dmarc 记录", "No _dmarc record"), "bulk")
		case pol == "reject" || pol == "quarantine":
			return mk("dmarc", "DMARC", "ok", lang.F("p=%s", "p=%s", pol), "bulk")
		case pol == "none":
			return mk("dmarc", "DMARC", "ok",
				lang.T("p=none —— 满足最低要求，但不提供任何拦截保护，建议逐步收紧到 quarantine / reject",
					"p=none - meets the minimum bar but blocks nothing; tighten towards quarantine / reject"), "bulk")
		default:
			return mk("dmarc", "DMARC", "warn", lang.T("记录存在但策略无法识别", "Record exists but the policy is unrecognised"), "bulk")
		}
	}

	ptrCheck := func() ReceiverCheck {
		if !ipKnown {
			return mk("ptr", lang.T("发信 IP 反向解析", "Sending IP reverse DNS"), "na",
				lang.T("未提供发信 IP，无法检查。走第三方投递服务时由服务商负责",
					"No sending IP provided. When relaying through a provider, this is their responsibility"), "all")
		}
		if !hasPTR {
			return mk("ptr", lang.T("发信 IP 反向解析", "Sending IP reverse DNS"), "fail",
				lang.F("%s 没有 PTR 记录", "%s has no PTR record", res.IP), "all")
		}
		if !fcrdns {
			return mk("ptr", lang.T("发信 IP 反向解析", "Sending IP reverse DNS"), "warn",
				lang.F("PTR 为 %s，但正向解析对不上（FCrDNS 失败）", "PTR is %s but the forward lookup does not match (FCrDNS fails)", res.SendingIP.PTR), "all")
		}
		return mk("ptr", lang.T("发信 IP 反向解析", "Sending IP reverse DNS"), "ok",
			lang.F("%s，正反解析一致", "%s, forward and reverse agree", res.SendingIP.PTR), "all")
	}

	blCheck := func() ReceiverCheck {
		if !ipKnown {
			return mk("dnsbl", lang.T("IP 信誉", "IP reputation"), "na", lang.T("未提供发信 IP", "No sending IP provided"), "all")
		}
		if spamListed {
			return mk("dnsbl", lang.T("IP 信誉", "IP reputation"), "fail",
				lang.T("命中垃圾源类黑名单", "Listed on a spam-source blocklist"), "all")
		}
		return mk("dnsbl", lang.T("IP 信誉", "IP reputation"), "ok",
			lang.T("未命中垃圾源类黑名单", "Not on any spam-source blocklist"), "all")
	}

	manual := func(key, label, detail, req string) ReceiverCheck {
		return mk(key, label, "na", detail, req)
	}

	unsub := manual("unsub", lang.T("一键退订", "One-click unsubscribe"),
		lang.T("需在邮件头包含 List-Unsubscribe 与 List-Unsubscribe-Post。DNS 层无法检测，请自行核对",
			"Requires List-Unsubscribe and List-Unsubscribe-Post headers. Not detectable from DNS - verify yourself"), "bulk")
	complaint := manual("complaint", lang.T("投诉率", "Spam complaint rate"),
		lang.T("需持续低于 0.3%（建议低于 0.1%）。只能在各家的发件人工具里查看",
			"Must stay under 0.3% (aim for under 0.1%). Only visible in each provider's postmaster tools"), "bulk")
	tlsReq := manual("tls", lang.T("传输加密", "Transport encryption"),
		lang.T("投递时须使用 TLS。完整链路诊断模式会实测这一项",
			"TLS is required when delivering. The full delivery test measures this"), "all")

	gmail := &ReceiverReadiness{
		Receiver: "Gmail / Google Workspace",
		Note: lang.T("自 2024 年 2 月起：所有发件人须有 SPF 或 DKIM；每日向 Gmail 发送 5000 封以上的发件人须同时具备 SPF、DKIM、DMARC 与对齐、一键退订，且投诉率低于 0.3%。",
			"Since February 2024: every sender needs SPF or DKIM. Senders of 5,000+ messages a day to Gmail additionally need SPF, DKIM, aligned DMARC, one-click unsubscribe, and a spam rate under 0.3%."),
		Checks: []ReceiverCheck{spfCheck(), dkimCheck(), dmarcCheck(), ptrCheck(), blCheck(), tlsReq, unsub, complaint},
	}
	yahoo := &ReceiverReadiness{
		Receiver: "Yahoo Mail",
		Note: lang.T("与 Google 同期发布、要求基本一致的发件人规范。",
			"Published alongside Google's and, in substance, the same set of requirements."),
		Checks: []ReceiverCheck{spfCheck(), dkimCheck(), dmarcCheck(), ptrCheck(), blCheck(), unsub, complaint},
	}
	ms := &ReceiverReadiness{
		Receiver: "Microsoft Outlook / Hotmail",
		Note: lang.T("自 2025 年 5 月起：每日向 Outlook 系发送 5000 封以上的发件人，须具备 SPF、DKIM、DMARC（至少 p=none 且与 From 对齐）、有效 PTR 与可用的退订方式。",
			"Since May 2025: senders of 5,000+ messages a day to Outlook-family mailboxes need SPF, DKIM, DMARC (p=none minimum, aligned with From), a valid PTR record and a working unsubscribe path."),
		Checks: []ReceiverCheck{spfCheck(), dkimCheck(), dmarcCheck(), ptrCheck(), blCheck(), unsub},
	}
	cn := &ReceiverReadiness{
		Receiver: lang.T("国内收件方（163 / QQ / 阿里）", "Chinese receivers (163 / QQ / Alibaba)"),
		Note: lang.T("不公开发件人规范，也不使用公开黑名单，依赖自有信誉库。实践中对缺失 PTR 极为严格，新 IP 需要低量预热。",
			"They publish no sender requirements and do not use public blocklists, relying on in-house reputation instead. In practice they are very strict about a missing PTR, and new IPs need low-volume warm-up."),
		Checks: []ReceiverCheck{spfCheck(), dkimCheck(), dmarcCheck(), ptrCheck(),
			manual("warmup", lang.T("IP 预热", "IP warm-up"),
				lang.T("新 IP 需要数周低量爬坡，突然放量会被限速或拒收", "A new IP needs weeks of gradual ramp-up; a sudden burst gets throttled or rejected"), "bulk")},
	}

	for _, rr := range []*ReceiverReadiness{gmail, yahoo, ms, cn} {
		rr.Verdict = "ok"
		for _, c := range rr.Checks {
			if c.Status == "fail" {
				rr.Verdict = "fail"
				break
			}
			if c.Status == "warn" {
				rr.Verdict = "warn"
			}
		}
	}
	return []*ReceiverReadiness{gmail, yahoo, ms, cn}
}

func readinessSummary(lang L, rs []*ReceiverReadiness) string {
	var failed []string
	for _, r := range rs {
		if r.Verdict == "fail" {
			failed = append(failed, r.Receiver)
		}
	}
	if len(failed) == 0 {
		return lang.T("DNS 侧没有发现阻断性问题。注意：一键退订、投诉率这类要求无法从 DNS 检测，仍需自行核对。",
			"No blocking problems on the DNS side. Note that one-click unsubscribe and complaint rate cannot be checked from DNS and still need your own verification.")
	}
	return lang.F("以下收件方存在阻断性问题：%s", "Blocking problems for: %s", strings.Join(failed, ", "))
}
