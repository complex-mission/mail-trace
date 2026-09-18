package main

import (
	"fmt"
	"testing"
)

// TestSecurity 锁住三类攻击面：SSRF/内网探测、端口扫描、CRLF 注入。
// 任何一条被放行都说明 ValidateConfig 被改坏了。
func TestSecurity(t *testing.T) {
	base := func(f func(*Config)) Config {
		c := Config{Host: "example.com", Port: 587, Username: "u", Password: "p",
			From: "a@b.com", To: "c@d.com"}
		f(&c)
		return c
	}

	cases := []struct {
		name      string
		cfg       Config
		wantBlock bool
	}{
		{"正常配置", base(func(c *Config) { c.Host = "example.com"; c.Port = 465 }), false},
		{"内网直连 127.0.0.1", base(func(c *Config) { c.Host = "127.0.0.1" }), true},
		{"内网 192.168", base(func(c *Config) { c.Host = "192.168.1.1" }), true},
		{"云元数据 169.254.169.254", base(func(c *Config) { c.Host = "169.254.169.254" }), true},
		{"CGNAT 100.64", base(func(c *Config) { c.Host = "100.64.0.1" }), true},
		{"IPv6 回环", base(func(c *Config) { c.Host = "::1" }), true},
		{"域名指向 localhost", base(func(c *Config) { c.Host = "localhost" }), true},
		// 994 是 163/126 官方给的 SSL 端口，曾因不在白名单里让网易系用户完全测不了
		{"网易 SSL 端口 994", base(func(c *Config) { c.Port = 994 }), false},
		{"备用提交端口 2525", base(func(c *Config) { c.Port = 2525 }), false},
		{"端口扫描 :22", base(func(c *Config) { c.Port = 22 }), true},
		{"端口扫描 :3306", base(func(c *Config) { c.Port = 3306 }), true},
		{"端口扫描 :6379", base(func(c *Config) { c.Port = 6379 }), true},
		{"From 注入 SMTP 命令", base(func(c *Config) { c.From = "a@b.com>\r\nRCPT TO:<victim@x.com" }), true},
		{"To 注入邮件头", base(func(c *Config) { c.To = "c@d.com\r\nBcc: mass@list.com" }), true},
		{"密码含 CRLF", base(func(c *Config) { c.Password = "p\r\nQUIT" }), true},
		{"Host 含 CRLF", base(func(c *Config) { c.Host = "a.com\r\nX" }), true},
		{"超长密码", base(func(c *Config) { c.Password = string(make([]byte, 513)) }), true},
	}

	for _, c := range cases {
		err := ValidateConfig(&c.cfg)
		blocked := err != nil
		verdict := "放行"
		if blocked {
			verdict = "拦截"
		}
		fmt.Printf("%-26s %s   %v\n", c.name, verdict, err)
		if blocked != c.wantBlock {
			t.Errorf("%s: 期望拦截=%v 实际=%v (err=%v)", c.name, c.wantBlock, blocked, err)
		}
	}
}
