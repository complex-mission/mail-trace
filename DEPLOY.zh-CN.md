# 部署

[English](DEPLOY.md) · [简体中文](DEPLOY.zh-CN.md)

## 上线前必做

有四项配置决定这个服务在生产环境是否正确。其中三项配错时**不会报错**——
服务照常应答，只是答案是错的。

### 1. 确认解析器真的能返回完整的 TXT 记录

这一条最要紧。SPF 与 DMARC 走并集查询，因为国内公共 DNS 会从大 TXT RRset
里静默丢记录。如果你配的解析器没有一个能返回完整结果，工具就会把配置完全
正确的域名报成「没有 SPF 记录」并判定所有收件方不合格——而且没有任何报错
提示你。

**在服务器上**跑（不是在你本机）：

```bash
for r in 1.1.1.1 223.5.5.5; do
  printf '%-12s TXT=%s SPF=%s\n' "$r" \
    "$(dig +short TXT github.com @$r | wc -l)" \
    "$(dig +short TXT github.com @$r | grep -c spf1)"
done
```

健康的解析器会返回约 24 条 TXT、其中 1 条是 SPF。若 `1.1.1.1` 显示
`SPF=0` 或超时，就把 `MAIL_TRACE_DNS` 指向该机器上确实可用的解析器。最好
是自建递归 DNS：它同时能让 DNSBL 那一项变得可信，因为 Spamhaus 会拒绝来自
公共解析器的查询。

### 2. 声明反向代理

```bash
MAIL_TRACE_TRUSTED_PROXIES=127.0.0.1,::1
```

不配的话，所有访客都会被算成代理那一个 IP、共用同一个限流桶——十次请求就
锁死全站。反过来，服务也**刻意不会**在对端不在此名单时相信
`X-Forwarded-For`：否则谁都能伪造这个头，限流等于不存在。

### 3. 让优雅退出时间与进程管理器对齐

`SHUTDOWN_GRACE` 默认 90 秒，保证进行中的 SMTP 会话不会被拦腰砍断。但
supervisor 到 `stopwaitsecs`（默认 10 秒）就强杀，systemd 到
`TimeoutStopSec`（默认 90 秒）也一样。管理器的超时更短时，优雅退出这条路
根本走不完。要么调大管理器的超时，要么把这个值调小对齐。

### 4. 走 HTTPS

这个工具会传输邮箱密码。明文部署时，它所有的隐私承诺都不成立。

---

## 构建

页面、图标和社交卡片全部内嵌在二进制里，所以部署物就是**一个文件**——
服务器上不需要 `templates/` 和 `docs/`。

任意平台交叉编译：

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath \
  -ldflags "-s -w -X main.version=v1.0.0" -o mail-trace .
```

产出约 9 MB 的静态 ELF。`./mail-trace -version` 可确认传上去的是哪一版。

## 反向代理

```nginx
location / {
    proxy_pass http://127.0.0.1:9013;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    # 完整链路诊断走 SSE：必须关掉缓冲与缓存，
    # 读超时也要长过一次慢速 SMTP 会话
    proxy_buffering off;
    proxy_cache off;
    proxy_read_timeout 180s;
}
```

`proxy_buffering off` 不是可选项。开着缓冲时，浏览器要等整个诊断跑完才收到
数据，逐跳推进的那个过程——也就是这个工具的核心体验——根本不会动。

## 宝塔面板部署

宝塔的 Go 项目管理底层用 supervisor 托管二进制。和手写 systemd 单元相比有
两点不同：

**环境变量。** 程序从工作目录读 `.env`。面板不一定把工作目录设成项目目录，
而 `.env` 读不到**不算错误**——服务会以默认值启动，也就是没有 Redis 限流、
没有可信代理。建议直接用面板自带的环境变量配置项，不要依赖 `.env`；无论用
哪种方式，都要从启动日志确认（见下面的「验证」）。

**停止超时。** supervisor 的 `stopwaitsecs` 默认 10 秒。把
`SHUTDOWN_GRACE=10s` 设成一致，或者在生成的 supervisor 配置里调大
`stopwaitsecs`。

建议配置：

```bash
LISTEN=127.0.0.1:9013
SITE_URL=https://你的域名
REDIS_URL=redis://127.0.0.1:6379/0
MAIL_TRACE_TRUSTED_PROXIES=127.0.0.1,::1
SHUTDOWN_GRACE=10s
RATE_LIMIT_MAX=10
RATE_LIMIT_WINDOW=1m
```

宝塔的 Redis 若设了密码，URL 写成
`redis://:密码@127.0.0.1:6379/0`；密码里若有 `@ : / ?` 需要百分号编码。

`LISTEN` 要保持 `127.0.0.1`。这个服务本就该待在面板的 nginx 后面，绑公网口
等于绕过 TLS，也拿不到限流所依赖的代理头。

---

## 出站 25 端口

完整链路诊断需要连到目标 SMTP 端口。多数云厂商默认封禁出站 25——腾讯云、
阿里云都封，**境外地域同样封**，且很少批准开通。465/587 一般不受影响，所以
走提交服务器的测试到处都能用；只有 25 端口直投 MX 的场景需要解封。

别猜，在服务器上实测：

```bash
timeout 5 bash -c 'cat < /dev/null > /dev/tcp/gmail-smtp-in.l.google.com/25' \
  && echo "25 出站可用" || echo "25 出站被封"
timeout 5 bash -c 'cat < /dev/null > /dev/tcp/smtp.qq.com/465' \
  && echo "465 出站可用" || echo "465 出站被封"
```

## 验证

启动日志会如实说明服务实际加载了什么。每次改配置后都读一遍——`.env` 被静默
忽略这件事，就是在这里暴露出来的：

```
Redis 限流已启用: 10 次 / 1m0s
已配置 2 个可信代理网段，限流将采信 X-Forwarded-For
Mail Trace v1.0.0 已启动，监听 http://127.0.0.1:9013
```

如果看到的是下面这两行，说明对应配置没生效：

```
未配置 REDIS_URL，限流已跳过
未配置 MAIL_TRACE_TRUSTED_PROXIES，限流按 RemoteAddr 计数（...）
```

然后端到端验一遍行为：

```bash
# 1. 页面可访问，且 canonical 跟随 SITE_URL
curl -s https://你的域名/ | grep -o 'rel="canonical" href="[^"]*"'

# 2. 安全头就位
curl -sI https://你的域名/ | grep -iE 'content-security-policy|x-frame-options'

# 3. 记录接口能取到真实 SPF —— 这是 DNS 并集修复生效的标志；
#    spf 字段为空说明你的解析器在丢数据
curl -s -X POST https://你的域名/api/records \
  -H 'Content-Type: application/json' \
  -d '{"domain":"github.com","lang":"zh"}' | grep -o '"spf":"[^"]*"' | head -c 120

# 4. 限流按真实客户端 IP 计数，而不是代理 IP
for i in $(seq 1 12); do
  curl -s -o /dev/null -w '%{http_code} ' -X POST \
    https://你的域名/api/records \
    -H 'Content-Type: application/json' -d '{"domain":"example.com"}'
done; echo
# 期望先 200 后 429。若全是 200，或换个人访问第一次就 429，
# 说明可信代理配错了

# 5. 优雅退出确实走到了（重启服务后查日志）
#    应看到：收到退出信号，停止接受新请求，最多等待 ...
```

## 运维须知

- **限流故障时放行。** Redis 不可达时服务会记 `限流查询失败，本次放行`
  并照常处理请求。此时兜底的是 `MAX_CONCURRENT`。
- **DNSBL 结果的可信度取决于解析器。** 走公共解析器时 Spamhaus 返回
  `127.255.255.x`，工具会如实报「查询被拒，结果不可信」，而不是假装成命中。
  换自建递归解析器才能去掉这个前提。
- **诊断会真的发信。** 除非请求里带 `dry_run: true`，否则每次完整诊断都会
  向填写的收件人地址实际投递一封邮件。
