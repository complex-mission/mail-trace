package main

import (
	"testing"

	"github.com/miekg/dns"
)

// TestStepsRecorded 锁住一个曾经让主流程静默说谎的 bug：
// testSMTPStream 只把步骤流给 emit、不写进 result.Steps，于是 SSE 的 done 事件、
// JSON 端点和末尾的失败汇总全部拿到空列表——某一步 fail 了，界面照样显示「全部通过」。
func TestStepsRecorded(t *testing.T) {
	emitted := 0
	res := testSMTPStream(
		t.Context(),
		Config{Host: "192.0.2.1", Port: 587, Username: "u", Password: "p", From: "a@b.com", To: "c@d.com"},
		func(Step) { emitted++ },
	)
	if emitted == 0 {
		t.Fatal("没有产生任何步骤，用例本身失效了")
	}
	if len(res.Steps) != emitted {
		t.Errorf("result.Steps 未记全: emit 了 %d 步，只记下 %d 步", emitted, len(res.Steps))
	}
}

// TestExtractDMARCPolicy 锁住 sp= 误判：子串匹配会把子域策略 sp=reject
// 当成域策略 p=reject，把一个毫无拦截保护的 p=none 域名报成 Reject。
func TestExtractDMARCPolicy(t *testing.T) {
	cases := []struct{ in, want string }{
		{"v=DMARC1; p=none; sp=reject; rua=mailto:a@b.com", "None"},
		{"v=DMARC1; sp=quarantine; p=none", "None"},
		{"v=DMARC1; p=quarantine; pct=100", "Quarantine"},
		{"v=DMARC1;p=reject", "Reject"},
		{"v=DMARC1; P=Reject ", "Reject"},
		{"v=DMARC1; sp=reject", ""},                 // 只有子域策略，域策略缺失
		{"v=DMARC1; p=bogus", ""},                   // 无法识别的值不猜
		{"v=DMARC1; rua=mailto:p=reject@x.com", ""}, // 不能被别的标签值骗到
	}
	for _, c := range cases {
		if got := extractDMARCPolicy(c.in); got != c.want {
			t.Errorf("extractDMARCPolicy(%q) = %q, 期望 %q", c.in, got, c.want)
		}
	}
}

// TestReverseIP 锁住 DNSBL 查询名的构造。IPv6 走错会让查询全部无应答，
// 在界面上伪装成「未列入任何黑名单」——一个假的干净结论比报错更糟。
func TestReverseIP(t *testing.T) {
	if got, want := reverseIP("1.2.3.4"), "4.3.2.1"; got != want {
		t.Errorf("IPv4: reverseIP = %q, 期望 %q", got, want)
	}
	for _, ip := range []string{"2001:db8::1", "::1", "fe80::1234:5678:9abc:def0"} {
		arpa, err := dns.ReverseAddr(ip)
		if err != nil {
			t.Fatalf("dns.ReverseAddr(%s): %v", ip, err)
		}
		want := arpa[:len(arpa)-len(".ip6.arpa.")]
		if got := reverseIP(ip); got != want {
			t.Errorf("IPv6 %s:\n 得到 %q\n 期望 %q", ip, got, want)
		}
	}
	if got := reverseIP("not-an-ip"); got != "" {
		t.Errorf("非法 IP 应返回空串以便调用方报错，实际 %q", got)
	}
}

// TestCheckDNSBLRejectsBadIP：构造不出查询名时必须显式报错，
// 不能返回一串默认的 clean 让用户以为 IP 是干净的。
func TestCheckDNSBLRejectsBadIP(t *testing.T) {
	for _, r := range CheckDNSBL(t.Context(), "not-an-ip") {
		if r.Kind != dnsblError {
			t.Errorf("%s: kind = %q, 期望 %q", r.Blacklist, r.Kind, dnsblError)
		}
		if r.Listed {
			t.Errorf("%s: 不该标记为已列入", r.Blacklist)
		}
	}
}

// TestImplicitTLSPorts 锁住「连上即 TLS」的端口集合。
// 465 与 994 上服务器会立刻发起握手，按明文读 banner 只会读到握手字节；
// 放开端口白名单却漏掉这一步，网易系依然测不了，只是失败得更难解释。
func TestImplicitTLSPorts(t *testing.T) {
	for _, p := range []int{465, 994} {
		if !IsImplicitTLSPort(p) {
			t.Errorf("端口 %d 应按隐式 TLS 处理", p)
		}
	}
	for _, p := range []int{25, 587, 2525} {
		if IsImplicitTLSPort(p) {
			t.Errorf("端口 %d 不应按隐式 TLS 处理", p)
		}
	}
}
