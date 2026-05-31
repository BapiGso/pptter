# PPTTER · 零信任匿名聊天室

端到端加密的匿名聊天室，单 Go 二进制。消息在浏览器内加解密，服务端只转发密文——不落库、不写盘、不记 IP，进程退出不留痕。

- **匿名**：无注册/账号。浏览器现场生成 Ed25519+X25519 密钥作为临时身份，刷新即销毁。
- **E2EE**：每条消息对每个接收者用 X25519 ECDH + HKDF 派生一次性 AES-256-GCM 密钥；服务端无密钥，无法解密。
- **零外部依赖**：JS/CSS/图标全部本地内嵌，无第三方 CDN；严格 CSP（`script-src 'self'`，无 `unsafe-eval`）。
- **P2P 大文件**：私聊自动尝试 WebRTC DataChannel 直传，不经服务端中转（群聊不建 P2P，避免 O(N²)）。

不做持久化：无聊天记录、无离线消息、无历史找回。需要这些请用别的项目。

## 功能

群聊 + 私聊 · 文字/图片/文件（均 E2EE）· P2P 大文件直传 · 多主题亮暗配色 · 移动端抽屉式侧栏 · 本地昵称/提示音/背景图（不上传）· 身份指纹带外核对（防 MITM）。

## 运行

```bash
# 二进制：见 Releases，下载后直接运行
./pptter                      # 默认 :8080

# Docker（distroless，非 root）
docker build -t pptter .
docker run -d -p 8080:8080 -p 3478:3478/udp pptter

# 源码（Go 1.26+，Node 用于构建 CSS）
npm install && npm run build:css
go build -ldflags="-s -w" -o pptter ./cmd/server
```

浏览器打开 `http://localhost:8080`。**Web Crypto 仅在安全上下文可用**：`localhost` 直连可以，公网访问必须 HTTPS，否则加密 API 被禁用、页面不可用。

## 部署（公网 + HTTPS）

反代终止 TLS，PPTTER 监听本地。Caddy 示例：

```caddy
chat.example.com {
    reverse_proxy localhost:8080
    header Strict-Transport-Security "max-age=31536000; includeSubDomains"
}
```

```bash
./pptter -addr 127.0.0.1:8080 -stun-host chat.example.com
```

Nginx 反代需透传 WebSocket 头（`Upgrade` / `Connection: upgrade`）。PPTTER 自身也输出 HSTS 头（浏览器仅 HTTPS 下采纳），可叠加 [HSTS preload](https://hstspreload.org/)。

清单：

- `8080/tcp` 经反代对外走 443。
- `3478/udp`（STUN）须在防火墙/安全组放行，否则 P2P 退化为仅同局域网。
- `-stun-host` 填公网域名/IP，浏览器据此找 STUN。

## 配置

| 参数 | 环境变量 | 默认 | 说明 |
| --- | --- | --- | --- |
| `-addr` | `ADDR` | `:8080` | HTTP 监听地址 |
| `-stun` | `STUN_ENABLED` | `true` | 内置 STUN 开关 |
| `-stun-port` | `STUN_PORT` | `3478` | STUN UDP 端口（`0`=随机） |
| `-stun-host` | `STUN_HOST` | 空 | 对外宣告的 STUN 主机名（空=用当前网址） |
| `-title` | `CHAT_TITLE` | `PPTTER Zero Trust` | 页面/关于弹窗标题 |

房间名仅 `[A-Za-z0-9_-]`，写在 URL `#` 后（`#team`），仅存在于内存。

## 安全边界

- 服务端不生成/接收/保存任何私钥或对称密钥，不解析明文，只校验包结构并按 `dest` 转发密文。
- 运行时不连库、不写盘，不保存房间/成员/消息。
- 不打印聊天内容、IP、`User-Agent` 或代理转发头，并主动剥离这些请求头。
- 成员身份由前端随机公钥派生；服务端仅持有公钥、公钥哈希 ID 和连接指针。
- 信封含单调计数器 `ctr` + 时间戳 `ts` 防重放；明文按 256 字节分桶填充抗长度分析。

> 限制：TCP 远端地址仍存在于 OS 网络栈（任何服务都如此）；本项目保证的是应用层不读取/转发/记录。强匿名请自行叠加 Tor/VPN。

## 技术栈

- 后端：Go + [Echo v5](https://github.com/labstack/echo) + [coder/websocket](https://github.com/coder/websocket)，内置 STUN。
- 前端：[Alpine.js (CSP build)](https://alpinejs.dev/) + [Tailwind v4](https://tailwindcss.com/) + [daisyUI](https://daisyui.com/)，全本地。
- 加密：Web Crypto——Ed25519 签名 + X25519 ECDH + HKDF → 一次性 AES-256-GCM。
- 打包：单二进制（`go:embed` 内嵌前端），多平台交叉编译，Docker distroless。

## 开发

```bash
npm run watch:css            # 改样式时自动重建 CSS
go test ./...                # 缓存受限时：GOCACHE=$(pwd)/.gocache go test ./...
```

发布：推 tag 触发 GitHub Actions（`.github/workflows/release.yaml`）自动构建 CSS、交叉编译并发布到 Releases。

<details>
<summary><b>协议细节</b></summary>

**加密**：页面初始化生成 Ed25519 身份密钥 + X25519 会话密钥，私钥仅留内存；公钥与身份签名经 `hello` 上报。发送时对每个接收者 X25519 ECDH + HKDF 派生 AES-GCM 密钥并签名信封。服务端只见 `dest` 与密文 `payload`。

**HTTP**

| 路径 | 说明 |
| --- | --- |
| `GET /` `/index.html` | SPA |
| `GET /ws/:room` | WebSocket 入口 |
| `GET /webrtc-config` | `{"enabled":true,"stunPort":3478,"stunHost":"..."}` |
| `GET /healthz` | 204 |

**WebSocket**

```json
// 客户端首发
{"type":"hello","idKey":"Ed25519 pub b64","dhKey":"X25519 pub b64","dhSig":"sig b64"}
// 服务端回 welcome（自身+成员列表），成员变动广播 peer_joined / peer_left

// 发送：对每个接收者分别加密
{"type":"send","messages":[{"dest":"recipient id","payload":"ciphertext b64"}]}
// 接收
{"type":"ciphertext","from":"sender id","payload":"ciphertext b64"}
```

`payload` 对服务端不透明，写入 WS 后对持有密文尽力清零。

</details>

## License

见 [LICENSE](LICENSE)（MIT）。
