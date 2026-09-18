# ── 构建 ───────────────────────────────────────────────────────────────────────
FROM golang:1.26-alpine AS build

WORKDIR /src

# 先只拷依赖清单，让依赖层能被缓存
COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=docker
# CGO_ENABLED=0 换来一个静态二进制，才能直接塞进 scratch
RUN CGO_ENABLED=0 go build -trimpath \
        -ldflags "-s -w -X main.version=${VERSION}" \
        -o /out/mail-trace .

# ── 运行 ───────────────────────────────────────────────────────────────────────
# 需要 CA 根证书来校验 SMTP 服务器的 TLS 证书，以及 tzdata 让报告里的时间正确。
FROM alpine:3.21

RUN apk add --no-cache ca-certificates tzdata \
    && adduser -D -u 10001 mailtrace

COPY --from=build /out/mail-trace /usr/local/bin/mail-trace

USER mailtrace
EXPOSE 9013
ENV LISTEN=0.0.0.0:9013

# 容器里跑必须监听 0.0.0.0，否则端口映射进不来
ENTRYPOINT ["/usr/local/bin/mail-trace"]
