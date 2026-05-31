# PPTTER · 零信任匿名聊天室

> 打开网页就能用的端到端加密聊天室。服务器只是一个「不认识你、看不懂你说什么、也不记录任何东西」的密文搬运工。

PPTTER 是一个用 Go 写的单文件聊天服务器：把它跑起来，用浏览器打开就能匿名聊天、发图、传文件。所有消息在你的浏览器里加密，服务器拿到的只是一串看不懂的密文，转发完就尽量从内存里抹掉——不写数据库、不落磁盘、不记 IP。

---

## 这是什么？（一分钟看懂）

- **匿名**：没有注册、没有账号、没有密码。一打开页面，浏览器现场生成一把「钥匙」当你的临时身份；刷新页面身份和聊天记录就消失。
- **端到端加密**：消息在你这边加密，只有收件人能解开。服务器、网管、甚至部署服务器的人都看不到内容。
- **不留痕**：服务器不连数据库、不写文件、不打印 IP 和聊天内容。进程一关，什么都不剩。
- **零外部依赖**：页面所有资源（JS / CSS / 图标）都来自服务器本机，不加载任何第三方 CDN，适合内网或强隐私环境。
- **能传大文件**：私聊时自动尝试 WebRTC P2P 直连，大文件点对点直传，不经过服务器中转。

> 适合：临时安全沟通、内网小团队、隐私演示、自建私密聊天室。
> 不适合：需要保存聊天记录、离线消息、找回历史的场景（本项目「阅后即焚」，刻意不存任何东西）。

---

## 功能一览

| 功能 | 说明 |
| --- | --- |
| 群聊 + 私聊 | 同一房间所有人是群聊；点某个成员进入一对一私聊 |
| 文字 / 图片 / 文件 | 都经过端到端加密 |
| P2P 大文件直传 | 私聊走 WebRTC 数据通道，不占服务器带宽 |
| 多套主题 | 青绿 / 葡萄紫 / 海蓝 / 暖橙 / 午夜蓝等亮暗配色 |
| 移动端适配 | 手机上侧栏变抽屉，单手可用 |
| 自定义昵称 / 提示音 / 背景图 | 仅存在你本机浏览器，不上传 |
| 身份指纹核对 | 可带外核对对方身份，防中间人冒充 |

---

## 快速开始

### 方式一：下载现成的程序（最简单，推荐新手）

1. 打开本项目的 **[Releases](../../releases)** 页面。
2. 根据你的系统下载对应文件：
   - Windows：`pptter_windows_amd64.exe`
   - Linux：`pptter_linux_amd64`
   - macOS：`pptter_mac_amd64`
   - 树莓派等 ARM 设备：`pptter_linux_arm`
3. 运行它：

   ```bash
   # Linux / macOS：先给执行权限，再运行
   chmod +x pptter_linux_amd64
   ./pptter_linux_amd64
   ```

   ```text
   :: Windows：双击 exe，或在命令行里运行
   pptter_windows_amd64.exe
   ```

4. 浏览器打开 **http://localhost:8080** 即可。把链接发给同一网络的朋友就能一起聊。

> ⚠️ **重要**：浏览器的加密功能只在「安全环境」下可用。`localhost` 本机访问没问题；但如果要让别人通过公网域名访问，**必须配置 HTTPS**（见下方「上线部署」），否则页面无法加密、无法使用。

### 方式二：用 Docker 跑（适合服务器部署）

```bash
# 1. 构建镜像
docker build -t pptter .

# 2. 运行（8080 是网页端口，3478/udp 是 P2P 用的 STUN 端口）
docker run -d --name pptter -p 8080:8080 -p 3478:3478/udp pptter
```

镜像基于 `distroless`，体积小、无 shell、以非 root 用户运行。

### 方式三：从源码编译（适合开发者）

需要 **Go 1.26+** 和 **Node.js（用来生成 CSS）**。

```bash
# 1. 生成前端 CSS（Tailwind + daisyUI）
npm install
npm run build:css

# 2. 直接运行
go run ./cmd/server

# 或编译成一个二进制文件
go build -ldflags="-s -w" -o pptter ./cmd/server
```

---

## 上线部署（公网访问 + HTTPS）

公网访问必须走 HTTPS，否则浏览器禁用加密 API。推荐用 Caddy 或 Nginx 做反向代理来自动处理证书。

### 用 Caddy（最省心，自动申请证书）

`Caddyfile`：

```caddy
chat.example.com {
    reverse_proxy localhost:8080
}
```

然后启动 PPTTER 时告诉它你的公网域名（让浏览器知道去哪找 STUN 做 P2P）：

```bash
./pptter_linux_amd64 -addr 127.0.0.1:8080 -stun-host chat.example.com
```

### 用 Nginx

```nginx
server {
    listen 443 ssl;
    server_name chat.example.com;

    # ssl_certificate / ssl_certificate_key 填你的证书路径

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;   # WebSocket 必需
        proxy_set_header Connection "upgrade";     # WebSocket 必需
    }
}
```

### 部署清单（别漏了）

- [ ] **8080/tcp**：网页和 WebSocket，由反向代理转发，对外走 443(HTTPS)。
- [ ] **3478/udp**：P2P 用的 STUN 端口，**要在防火墙 / 云安全组放行**，否则大文件 P2P 直连会退化成只能同局域网。
- [ ] 用 `-stun-host` 填你的公网域名或 IP。

---

## 配置参数

启动参数（也支持同名环境变量）：

| 参数 | 环境变量 | 默认值 | 说明 |
| --- | --- | --- | --- |
| `-addr` | `ADDR` | `:8080` | 网页 HTTP 监听地址 |
| `-stun` | `STUN_ENABLED` | `true` | 是否开启内置 STUN |
| `-stun-port` | `STUN_PORT` | `3478` | STUN 的 UDP 端口（`0` = 随机） |
| `-stun-host` | `STUN_HOST` | 空 | 告诉浏览器的公网 STUN 主机名（留空则用当前网址） |
| `-title` | `CHAT_TITLE` | `PPTTER Zero Trust` | 浏览器标题和「关于」弹窗标题 |

示例：

```bash
# 自定义端口和标题
./pptter -addr :9000 -title "我的小黑屋"

# 关掉内置 STUN（不需要 P2P 大文件时）
./pptter -stun=false
```

房间名只允许字母、数字、`-`、`_`，写在网址的 `#` 后面（如 `http://localhost:8080/#team`），只存在于内存里。

---

## 常见问题

**Q：聊天记录存在哪？**
不存。消息只在各自浏览器内存里，刷新或关页面就没了，服务器从不保存。

**Q：为什么公网访问打不开 / 报错？**
几乎都是没配 HTTPS。浏览器的加密 API 只在 `https://` 或 `localhost` 下可用。

**Q：大文件传不动 / 很慢？**
P2P 需要 `3478/udp` 可达，检查防火墙是否放行；并确认启动时填了正确的 `-stun-host`。群聊不做 P2P（避免连接数爆炸），大文件请进私聊发。

**Q：服务器管理员能看到我的消息吗？**
看不到。服务器拿到的是端到端加密后的密文，没有密钥无法解开。

**Q：怎么确认对方不是被冒充的？**
打开「关于」弹窗能看到本机身份指纹，双方通过其他渠道（当面、电话）核对一致即可。

---

## 隐私与安全边界

- 服务端**不生成、不接收、不保存**任何私钥或对称密钥。
- 服务端**不解析明文**，只校验包结构并按目标转发密文。
- 服务端运行时**不连数据库、不写磁盘**，不保存房间 / 成员 / 消息。
- 服务端**不打印**聊天内容、IP、`User-Agent` 或代理转发头，并主动剥离这些请求头。
- 成员身份由前端随机生成的公钥派生；服务端只持有公钥、公钥哈希 ID 和连接指针。
- 前端**不使用第三方 CDN**，配合严格 CSP（`script-src 'self'`，无 `unsafe-eval`）。
- WebRTC 只在私聊会话中尝试；群聊不建 P2P 网状连接，避免连接数 O(N²) 膨胀。

> 诚实的限制：TCP 远端地址仍存在于操作系统网络栈中（任何网络服务都如此）。本项目保证的是**应用层不读取、不转发、不记录**这些信息。强匿名需求请自行叠加 Tor / VPN 等网络层方案。

---

## 技术栈

- **后端**：Go + [Echo v5](https://github.com/labstack/echo) + [coder/websocket](https://github.com/coder/websocket)，内置 STUN 服务器。
- **前端**：[Alpine.js (CSP 构建)](https://alpinejs.dev/) + [Tailwind CSS v4](https://tailwindcss.com/) + [daisyUI](https://daisyui.com/)，全部本地离线，无 CDN。
- **加密**：浏览器原生 Web Crypto API —— Ed25519 身份签名 + X25519 ECDH + HKDF 派生一次性 AES-256-GCM 密钥。
- **打包**：单二进制（前端资源通过 `go:embed` 内嵌），多平台交叉编译，Docker 用 distroless 镜像。

---

## 开发

```bash
# 监听并自动重建 CSS（改前端样式时开着）
npm run watch:css

# 运行测试
go test ./...
```

如果本地不允许写系统 Go 缓存，可用项目内缓存：

```bash
GOCACHE=$(pwd)/.gocache go test ./...
```

发布：本项目配置了 GitHub Actions（`.github/workflows/release.yaml`），**推送一个 tag 即自动**重建 CSS、交叉编译四个平台的二进制并发布到 Releases。

---

<details>
<summary><b>附：底层协议细节（一般用户无需关心）</b></summary>

### 加密流程

- 页面初始化时，浏览器用 Web Crypto API 生成 Ed25519 身份密钥和 X25519 会话密钥。
- 私钥只留在当前页面内存中；身份公钥、会话公钥和身份签名通过 `hello` 发给服务端。
- 发送消息时，前端对每个接收者用 X25519 ECDH + HKDF 派生 AES-GCM 密钥，并对信封签名。
- 信封含单调计数器 `ctr` + 时间戳 `ts` 防重放；明文按 256 字节分桶填充，抗长度分析。
- 服务端只看到 `dest` 和密文 `payload`，不解码、不解密、不记录。

### HTTP 接口

| 路径 | 说明 |
| --- | --- |
| `GET /` `GET /index.html` | 前端单页应用 |
| `GET /ws/:room` | WebSocket 房间入口 |
| `GET /webrtc-config` | 返回 STUN 配置 `{"enabled":true,"stunPort":3478,"stunHost":"..."}` |
| `GET /healthz` | 健康检查（返回 204，不暴露细节） |

### WebSocket 消息

客户端连接后先发 `hello`：

```json
{"type":"hello","idKey":"Ed25519 身份公钥 Base64","dhKey":"X25519 会话公钥 Base64","dhSig":"身份私钥对会话公钥的签名 Base64"}
```

服务端回 `welcome`（含自己和成员列表）；成员变动时广播 `peer_joined` / `peer_left`。

发送消息时，客户端为每个接收者分别加密后提交：

```json
{"type":"send","messages":[{"dest":"接收者 ID","payload":"Base64 密文"}]}
```

接收者收到：

```json
{"type":"ciphertext","from":"发送者 ID","payload":"Base64 密文"}
```

`payload` 对服务端是不透明字符串；写入 WebSocket 后会对持有的密文做尽力清零。

</details>

---

## License

见 [LICENSE](LICENSE)。
