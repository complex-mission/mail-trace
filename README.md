<div align="center">

<img src="docs/logo.svg" width="88" alt="Mail Trace">

# Mail Trace

**邮件发送全链路诊断 — 逐跳定位发不出去或进垃圾箱的原因**

*Trace every SMTP hop. Find out exactly why your mail bounces or lands in spam.*

[![Go](https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-5b9cf6)](LICENSE)
[![Single binary](https://img.shields.io/badge/deploy-single%20binary-8b7df6)](#自建部署)
[![i18n](https://img.shields.io/badge/i18n-中文%20%7C%20English-d67df6)](#)

[在线使用](https://mail-trace.complexmission.com) · [自建部署](#自建部署) · [它跟别的工具有什么不同](#为什么又造一个轮子)

</div>

---

## 它解决什么问题

邮件「发不出去」和「发出去了但进垃圾箱」是两类完全不同的故障，但大多数在线检测工具只查一半，还经常查错对象。Mail Trace 两件事都做，而且把判断依据摊开给你看。

<table>
<tr><td width="50%" valign="top">

### 仅查记录 · 不需要密码

刚改完 DNS，想确认记录生效没有、Gmail 会不会收？填一个域名就够。

- MX / A / AAAA
- **SPF 按 RFC 7208 完整求值** —— 递归展开 `include`、`redirect`、`a`、`mx`、`ip4`、`ip6`、`exists`，判定你给的发信 IP 到底在不在授权范围内，并统计 10 次 DNS 查询上限
- DKIM 选择器探测（内置 40+ 常见选择器，也可手填）
- DMARC 记录与 `p=` 策略
- MTA-STS / TLS-RPT / BIMI / DANE
- 发信 IP 的 **PTR 与 FCrDNS 闭环**
- 5 个 DNSBL，**按返回码分类**而不是笼统报「命中」
- **Gmail / Yahoo / Microsoft / 国内收件方的准入要求逐条核对**

</td><td width="50%" valign="top">

### 完整链路诊断 · 真跑一次 SMTP

记录都对但还是发不出去？那问题在会话里。

- DNS 解析 → TCP 连接 → Banner → EHLO
- SSL/TLS 或 STARTTLS 握手（含证书链、有效期、协议与加密套件）
- AUTH（LOGIN / PLAIN）
- MAIL FROM → RCPT TO → DATA
- 每一跳的耗时与**服务器原始应答**
- 失败时给出按错误码定制的排查建议
- 可选「仅检测不发送」模式

</td></tr>
</table>

<div align="center">
<img src="docs/records-check.jpg" width="49%" alt="记录检测与收件方准入检查">
<img src="docs/pipeline.jpg" width="49%" alt="完整链路逐跳诊断">
</div>

---

## 为什么又造一个轮子

市面上的邮件检测工具很多，但下面这三件事，多数都做错了。Mail Trace 的存在理由就是这三条。

### 1. DNSBL 命中 ≠ 被拉黑

Spamhaus 的返回码有三类完全不同的含义，把它们混为一谈会得出完全相反的结论：

| 返回码 | 类型 | 含义 | 严重程度 |
|---|---|---|---|
| `127.0.0.2` – `127.0.0.9` | SBL / CSS / XBL | 有真实垃圾邮件或主机被入侵的记录 | **硬问题** |
| `127.0.0.10` / `127.0.0.11` | **PBL（策略列表）** | 「这个 IP 段不应直连对方 MX」。云主机 IP 段默认全在里面，**与垃圾邮件无关** | 仅在自建直投时生效 |
| `127.255.255.x` | 查询被拒 | 你用了公共 DNS 或超出免费额度，**结果无效** | 不是命中 |

很多工具看到有 A 记录返回就报「已列入黑名单，请申请解除」——如果那是 `127.255.255.254`，这条建议毫无意义；如果是 PBL 而你走的是服务商中继，同样毫无意义。

### 2. 反向解析要查发信 IP，不是域名的 A 记录

`example.com` 的 A 记录通常指向网站服务器，跟发邮件没有任何关系。该查的是**实际建立 SMTP 连接的那个 IP** 的 PTR 记录，并验证正向解析能回到同一个 IP（FCrDNS）。

### 3. SPF 不是「有没有记录」，而是「这个 IP 过不过」

最常见、也最致命的翻车姿势：SPF 里写着服务商的 `include`，邮件却从自建服务器直接发出——那台机器的 IP 根本不在授权范围内，配上 `-all` 就是被收件方直接拒收。只检查「记录存在且以 `v=spf1` 开头」完全发现不了这个问题。

Mail Trace 会把整条 include 链展开给你看：

```
v=spf1 include:spf1.dm.aliyun.com -all

include:spf1.dm.aliyun.com → v=spf1 ip4:115.124.21.0/24 ip4:140.205.208.0/24 … -all
  include:spfdm-global-1.aliyun.com → v=spf1 ip4:115.124.24.0/24 … -all
    -all → fail
  -all → fail
-all → fail

结论：fail — 8.152.153.28 未被授权，且策略为 -all（硬失败）
```

### 另外：提交服务器和出口 IP 不是一回事

走服务商的 465/587 提交时，真正连对方 MX 的是服务商的**出口 IP 池**，不是你连的那台提交机。所以此时该验的是「SPF 里有没有 include 服务商」，而不是拿提交机 IP 去比对；提交机的 PTR 和 PBL 状态也与你无关。Mail Trace 内置 17 家服务商识别（腾讯企业邮、阿里企业邮/DirectMail、网易、263、Gmail、Microsoft 365、SendGrid、Mailgun、Amazon SES、Postmark、Mailjet、Zoho、Xserver、SendCloud 等），会自动切换判定口径。

---

## 隐私与安全

这是一个要你输入邮箱密码的工具，所以安全边界必须说清楚。

**对凭据的处理**

- **不落盘**：用户名和密码只存在于处理该次请求的内存中，请求结束即释放。不写入任何数据库、日志或文件。
- **不记录**：服务端日志只有来源 IP 与限流计数。
- **不转发**：凭据只用于向你自己填写的那台 SMTP 服务器认证。
- **无会话**：没有账号体系、不设 Cookie、不做用户画像、不缓存。

这些话你不必相信——代码在这里，`grep` 一下就能验证；更彻底的做法是自己部署一份。

**服务端自身的防护**（见 [`security.go`](security.go) 与 [`sec_test.go`](sec_test.go)）

| 攻击面 | 处理 |
|---|---|
| SSRF / 内网探测 | 拦截回环、私有、链路本地（含 `169.254.169.254` 云元数据）、CGNAT 与保留段；并在 `Dialer.Control` 里对**最终 connect 的 IP** 再查一次，挡住 DNS rebinding |
| 端口扫描 | 端口白名单，仅 25 / 465 / 587 / 2525 |
| SMTP 命令与邮件头注入 | 所有字段拒绝 CR/LF 及控制字符，地址做形状校验 |
| 资源耗尽 | 请求体上限 16 KB，全链路 I/O deadline，可选 Redis 限流 |

`sec_test.go` 里 15 条用例锁住上述行为，`go test` 可复现。

> `MAIL_TRACE_ALLOW_PRIVATE=1` 会同时放开内网地址与端口白名单，**仅供内网自部署**。公网开启等于把这个服务变成对外的端口扫描器。

---

## 自建部署

只有一个二进制，没有运行时依赖。Redis 可选（只用于限流）。

```bash
git clone https://github.com/complex-mission/mail-trace.git
cd mail-trace
go build -o mail-trace .

cp .env.example .env    # 按需修改
./mail-trace            # 默认监听 127.0.0.1:9013
```

也可以直接传监听地址：`./mail-trace 0.0.0.0:9013`

### 环境变量

| 变量 | 默认值 | 说明 |
|---|---|---|
| `LISTEN` | `127.0.0.1:9013` | 监听地址 |
| `SITE_URL` | `https://mail-trace.complexmission.com` | 写进 canonical / sitemap / OG / llms.txt |
| `REDIS_URL` | 空 | 配置后启用限流。公网部署建议开启 |
| `RATE_LIMIT_MAX` | `10` | 每窗口最大请求数 |
| `RATE_LIMIT_WINDOW` | `1m` | 限流窗口 |
| `MAIL_TRACE_ALLOW_PRIVATE` | 关闭 | 允许内网目标与任意端口，**仅限内网部署** |

### 反向代理

务必走 HTTPS——这个工具会传输密码，明文部署时所有隐私承诺都不成立。

```nginx
server {
    listen 443 ssl http2;
    server_name mail-trace.example.com;

    add_header Strict-Transport-Security "max-age=63072000" always;

    location / {
        proxy_pass http://127.0.0.1:9013;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

        # 完整链路诊断走 SSE，必须关掉缓冲
        proxy_buffering off;
        proxy_read_timeout 120s;
    }
}
```

### 出站端口

完整链路诊断需要能连到目标 SMTP 端口。**中国大陆的云厂商默认封禁出站 25 端口且很少批准开通**，465/587 一般不受影响。如果要覆盖 25 端口直投场景，建议部署在境外节点。

---

## API

两个端点都接受 JSON POST，`lang` 取 `zh` 或 `en`。

### `POST /api/records` — 仅查记录，不需要凭据

```bash
curl -s https://mail-trace.complexmission.com/api/records \
  -H 'Content-Type: application/json' \
  -d '{"domain":"example.com","ip":"203.0.113.10","selectors":["s1"],"lang":"zh"}'
```

返回 DNS 记录、SPF 求值过程、PTR/FCrDNS、DNSBL 明细，以及各收件方的准入检查矩阵。

### `POST /api/test-stream` — 完整链路诊断（SSE）

```bash
curl -N https://mail-trace.complexmission.com/api/test-stream \
  -H 'Content-Type: application/json' \
  -d '{"host":"smtp.example.com","port":587,"username":"u","password":"p",
       "from":"a@example.com","to":"b@example.com","dry_run":true,"lang":"zh"}'
```

逐步推送 `step` / `tls` / `extensions` / `dns` / `done` 事件。`POST /api/test` 是一次性返回结果的非流式版本。

---

## 项目结构

```
main.go        HTTP 路由、SMTP 会话、逐跳诊断、i18n
analysis.go    SPF 求值、DNSBL 分类、PTR/FCrDNS、策略记录、服务商识别
records.go     仅查记录模式与收件方准入检查
security.go    输入校验、SSRF 防护、端口白名单
seo.go         robots.txt / sitemap.xml / llms.txt / OG 图
templates/     单文件前端（无构建步骤、无外部依赖）
```

前端是一个自包含的 HTML 文件：不引入任何 CDN、不需要打包，图标全部是内联 SVG（[Lucide](https://lucide.dev)，ISC）。

---

## 贡献

欢迎 issue 和 PR。特别欢迎这两类：

- **补充服务商识别**：`analysis.go` 的 `knownProviders`，需要提交服务器域名和对应的 SPF include。
- **补充 DKIM 选择器**：`main.go` 的选择器列表。选择器无法枚举，这张表越全，探测命中率越高。

提 PR 前请跑 `go test ./...` 与 `gofmt -l .`。

---

## 免责声明

本工具仅用于诊断你自己拥有或已获授权的邮件服务。诊断结果基于公开 DNS 数据和一次真实 SMTP 会话，反映查询时刻的状态，不构成任何保证——收件方的实际过滤策略不公开，任何工具都无法预测。非「仅检测」模式会向收件人地址实际投递一封诊断邮件。

---

<div align="center">

MIT © [complex mission](https://github.com/complex-mission)

</div>
