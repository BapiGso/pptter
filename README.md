# 零信任匿名聊天室后端

这是从零开始的 Go + Echo + nhooyr WebSocket 匿名聊天室。后端只负责内存中的匿名连接管理与密文转发；前端使用原生 HTML/JS、Alpine.js、本地离线 CSS 和 Web Crypto API。

## 安全边界

- 服务端不生成、不接收、不保存私钥或对称密钥。
- 服务端不解析明文聊天内容，只校验 JSON 包结构并按 `dest` 转发 `payload`。
- 服务端运行时不连接数据库，不把房间、成员或消息写入磁盘。
- 服务端不打印聊天内容、用户 IP、`User-Agent` 或代理转发头。
- 所有成员身份由前端随机生成的公钥派生，服务端只保存公钥、公钥哈希 ID 和 WebSocket 连接指针。
- 前端不使用第三方 CDN，不加载外部字体；页面刷新后身份密钥与聊天记录自然丢失。

## 运行

```bash
go run ./cmd/server
```

默认监听 `:8080`，可通过环境变量覆盖：

```bash
ADDR=:9000 go run ./cmd/server
```

健康检查：

```text
GET /healthz
```

WebSocket 入口：

```text
GET /ws/:room
```

前端页面：

```text
GET /
GET /r/:room
```

房间名只允许字母、数字、`-`、`_`，且只存在于进程内存中。进程退出后，所有房间与成员状态都会消失。

## 前端加密流程

- 页面初始化时，浏览器用 Web Crypto API 生成 RSA-OAEP/SHA-256 密钥对。
- 私钥只留在当前页面内存中；公钥以 SPKI Base64 形式通过 `hello` 发给服务端。
- 发送消息时，前端为每个接收者生成一次性 AES-GCM 密钥，加密正文后再用接收者 RSA 公钥包裹 AES 密钥。
- 服务端只看到 `dest` 和 JSON 字符串形式的密文 `payload`，不会解码、解密或记录聊天内容。
- 页面样式参考旧 PPTTER 的青绿色侧栏、半透明群组栏和玻璃拟态聊天区域，但所有资源都从本地 `/static` 加载。

## WebSocket 协议

客户端连接后必须先发送 `hello`：

```json
{"type":"hello","publicKey":"前端生成的 SPKI Base64 或 JWK 字符串"}
```

服务端返回当前成员列表：

```json
{
  "type": "welcome",
  "self": {"id": "自己的公钥哈希 ID", "publicKey": "自己的公钥"},
  "peers": [{"id": "成员 ID", "publicKey": "成员公钥"}]
}
```

新成员加入时，已有成员会收到：

```json
{"type":"peer_joined","peer":{"id":"成员 ID","publicKey":"成员公钥"}}
```

成员离开时，其他成员会收到：

```json
{"type":"peer_left","id":"成员 ID"}
```

发送聊天消息时，客户端必须先为每个接收者分别加密，再把密文数组交给服务端：

```json
{
  "type": "send",
  "messages": [
    {"dest": "接收者 ID 或接收者公钥", "payload": "Base64 密文"}
  ]
}
```

接收者收到：

```json
{"type":"ciphertext","from":"发送者 ID","payload":"Base64 密文"}
```

`payload` 对服务端是不透明 JSON 字符串。服务端不会 Base64 解码、不会解密、不会尝试识别消息内容；写入 WebSocket 后会对本层持有的密文 `[]byte` 做尽力清零。

## 开发校验

```bash
go test ./...
```

如果本地沙箱不允许写系统 Go 编译缓存，可临时使用项目内缓存：

```bash
GOCACHE=$(pwd)/.gocache go test ./...
```
