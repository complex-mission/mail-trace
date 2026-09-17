package main

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"
	"syscall"
)

// ── 输入校验 ───────────────────────────────────────────────────────────────────

// SMTP 命令以 CRLF 分隔。任何进入命令行或邮件头的用户输入若含 CR/LF，
// 攻击者就能注入任意 SMTP 命令或邮件头（抄送、附加正文、提前结束 DATA）。
var ctlChars = regexp.MustCompile(`[\x00-\x1f\x7f]`)

// 保守的地址形状校验：本工具只需要判断「能不能安全地放进 SMTP 命令」，
// 不追求完整实现 RFC 5321 的 addr-spec。
var addrRe = regexp.MustCompile(`^[A-Za-z0-9._%+\-!#$&'*/=?^` + "`" + `{|}~]+@[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)+$`)

var hostRe = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?)*\.?$`)

func ValidateEmail(field, s string) error {
	if len(s) == 0 || len(s) > 254 {
		return fmt.Errorf("%s 长度非法 / invalid %s length", field, field)
	}
	if ctlChars.MatchString(s) {
		return fmt.Errorf("%s 含非法控制字符 / %s contains control characters", field, field)
	}
	if !addrRe.MatchString(s) {
		return fmt.Errorf("%s 不是合法邮箱地址 / %s is not a valid email address", field, field)
	}
	return nil
}

func ValidateHost(s string) error {
	if len(s) == 0 || len(s) > 253 {
		return errors.New("SMTP 服务器地址长度非法 / invalid SMTP host length")
	}
	if ctlChars.MatchString(s) {
		return errors.New("SMTP 服务器地址含非法字符 / SMTP host contains illegal characters")
	}
	if net.ParseIP(s) != nil {
		return nil
	}
	if !hostRe.MatchString(s) {
		return errors.New("SMTP 服务器地址格式非法 / malformed SMTP host")
	}
	return nil
}

// 只放行真实存在的邮件提交端口。不加限制的话，本服务就是一个
// 「输入任意 host:port，回显对方 banner」的对外端口扫描器。
var allowedPorts = map[int]bool{25: true, 465: true, 587: true, 2525: true}

func ValidatePort(p int) error {
	if AllowPrivateTargets && p > 0 && p < 65536 {
		return nil
	}
	if !allowedPorts[p] {
		return fmt.Errorf("端口 %d 不被允许，仅支持 25/465/587/2525 / port %d not allowed", p, p)
	}
	return nil
}

func ValidateCredential(field, s string) error {
	if len(s) == 0 || len(s) > 512 {
		return fmt.Errorf("%s 长度非法 / invalid %s length", field, field)
	}
	if strings.ContainsAny(s, "\r\n\x00") {
		return fmt.Errorf("%s 含非法控制字符 / %s contains control characters", field, field)
	}
	return nil
}

// ── SSRF 防护 ──────────────────────────────────────────────────────────────────

var blockedNets = func() []*net.IPNet {
	cidrs := []string{
		"0.0.0.0/8",          // 本网络
		"10.0.0.0/8",         // 私有
		"100.64.0.0/10",      // CGNAT
		"127.0.0.0/8",        // 回环
		"169.254.0.0/16",     // 链路本地（含云厂商元数据 169.254.169.254）
		"172.16.0.0/12",      // 私有
		"192.0.0.0/24",       // IETF 保留
		"192.0.2.0/24",       // TEST-NET-1
		"192.168.0.0/16",     // 私有
		"198.18.0.0/15",      // 基准测试
		"198.51.100.0/24",    // TEST-NET-2
		"203.0.113.0/24",     // TEST-NET-3
		"224.0.0.0/4",        // 组播
		"240.0.0.0/4",        // 保留
		"255.255.255.255/32", // 广播
		"::/128",             // 未指定
		"::1/128",            // 回环
		"fc00::/7",           // 唯一本地
		"fe80::/10",          // 链路本地
		"ff00::/8",           // 组播
	}
	var out []*net.IPNet
	for _, c := range cidrs {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

// AllowPrivateTargets 由环境变量 MAIL_TRACE_ALLOW_PRIVATE=1 打开，默认关闭。
// 只有在内网自部署、需要诊断内部邮件服务器时才应开启；
// 公网部署开启它等于把服务变成对外的内网扫描器。
var AllowPrivateTargets = os.Getenv("MAIL_TRACE_ALLOW_PRIVATE") == "1"

func IsBlockedIP(ip net.IP) bool {
	if AllowPrivateTargets {
		return false
	}
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	for _, n := range blockedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var ErrBlockedTarget = errors.New("目标地址指向内网或保留地址段，已拒绝 / target resolves to a private or reserved address")

// GuardResolve 在建连前做一次解析检查，把明显的内网目标挡在门外。
func GuardResolve(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if IsBlockedIP(ip) {
			return ErrBlockedTarget
		}
		return nil
	}
	ips, err := net.LookupIP(host)
	if err != nil {
		return nil // 解析失败留给后续步骤报告，这里不冒充 DNS 错误
	}
	for _, ip := range ips {
		if IsBlockedIP(ip) {
			return ErrBlockedTarget
		}
	}
	return nil
}

// dialControl 在 socket 真正 connect 之前拿到最终 IP 再查一次。
// 只做 GuardResolve 是不够的：攻击者可以让域名第一次解析成公网 IP、
// 第二次解析成 127.0.0.1（DNS rebinding），这个钩子能挡住。
func dialControl(network, address string, _ syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return err
	}
	if IsBlockedIP(net.ParseIP(host)) {
		return ErrBlockedTarget
	}
	return nil
}

// ValidateConfig 是所有对外请求的统一入口校验。
func ValidateConfig(cfg *Config) error {
	if err := ValidateHost(cfg.Host); err != nil {
		return err
	}
	if err := ValidatePort(cfg.Port); err != nil {
		return err
	}
	if err := ValidateCredential("用户名/username", cfg.Username); err != nil {
		return err
	}
	if err := ValidateCredential("密码/password", cfg.Password); err != nil {
		return err
	}
	if err := ValidateEmail("发件人/from", cfg.From); err != nil {
		return err
	}
	if err := ValidateEmail("收件人/to", cfg.To); err != nil {
		return err
	}
	return GuardResolve(cfg.Host)
}
