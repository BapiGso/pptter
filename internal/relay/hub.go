package relay

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/labstack/echo/v5"
)

const (
	defaultMaxRoomMembers       = 5
	defaultMaxPublicKeyBytes    = 16 * 1024
	defaultMaxInboundBytes      = 4 * 1024 * 1024
	defaultMaxCiphertextBytes   = 3 * 1024 * 1024
	defaultMaxFanoutPerEnvelope = 8
	defaultHandshakeTimeout     = 10 * time.Second
	defaultWriteTimeout         = 5 * time.Second
	defaultRateLimitPerSecond   = 10
	defaultRateLimitBurst       = 20
	defaultMaxRooms             = 128
	defaultMaxClients           = defaultMaxRoomMembers * defaultMaxRooms
	defaultGlobalJoinRate       = 20
	defaultGlobalJoinBurst      = 40
	defaultGlobalMessageRate    = 200
	defaultGlobalMessageBurst   = 400
	defaultRoomJoinRate         = 3
	defaultRoomJoinBurst        = 8
	defaultRoomMessageRate      = 40
	defaultRoomMessageBurst     = 80
	defaultClientJoinRate       = 2
	defaultClientJoinBurst      = 6
	defaultClientBlacklistTTL   = 5 * time.Minute
	defaultNoteTTL              = 30 * time.Minute
	defaultMaxNotesPerRoom      = 50
	defaultMaxRoomNoteBytes     = 8 * 1024 * 1024
)

// Config 只描述内存中 WebSocket 转发层的安全边界。
//
// 注意：这些限制不是为了“解密”或“理解”消息，而是为了防止匿名连接提交
// 过大的 JSON 包导致服务端内存被滥用。服务端始终只把 payload 当作不透明密文。
type Config struct {
	MaxRoomMembers       int
	MaxRooms             int
	MaxClients           int
	MaxPublicKeyBytes    int
	MaxInboundBytes      int64
	MaxCiphertextBytes   int
	MaxFanoutPerEnvelope int
	HandshakeTimeout     time.Duration
	WriteTimeout         time.Duration
	GlobalJoinRate       int
	GlobalJoinBurst      int
	GlobalMessageRate    int
	GlobalMessageBurst   int
	RoomJoinRate         int
	RoomJoinBurst        int
	RoomMessageRate      int
	RoomMessageBurst     int
	ClientJoinRate       int
	ClientJoinBurst      int
	ClientBlacklistTTL   time.Duration
	// 留言（离线消息）信箱：服务端只暂存不可解密的密文字符串，带 TTL 与容量上限，进程退出即清空。
	NoteTTL          time.Duration
	MaxNotesPerRoom  int
	MaxNoteBytes     int
	MaxRoomNoteBytes int
}

// NewConfig 返回适合 3-5 人匿名房间的保守默认值。
func NewConfig() Config {
	return Config{
		MaxRoomMembers:       defaultMaxRoomMembers,
		MaxRooms:             defaultMaxRooms,
		MaxClients:           defaultMaxClients,
		MaxPublicKeyBytes:    defaultMaxPublicKeyBytes,
		MaxInboundBytes:      defaultMaxInboundBytes,
		MaxCiphertextBytes:   defaultMaxCiphertextBytes,
		MaxFanoutPerEnvelope: defaultMaxFanoutPerEnvelope,
		HandshakeTimeout:     defaultHandshakeTimeout,
		WriteTimeout:         defaultWriteTimeout,
		GlobalJoinRate:       defaultGlobalJoinRate,
		GlobalJoinBurst:      defaultGlobalJoinBurst,
		GlobalMessageRate:    defaultGlobalMessageRate,
		GlobalMessageBurst:   defaultGlobalMessageBurst,
		RoomJoinRate:         defaultRoomJoinRate,
		RoomJoinBurst:        defaultRoomJoinBurst,
		RoomMessageRate:      defaultRoomMessageRate,
		RoomMessageBurst:     defaultRoomMessageBurst,
		ClientJoinRate:       defaultClientJoinRate,
		ClientJoinBurst:      defaultClientJoinBurst,
		ClientBlacklistTTL:   defaultClientBlacklistTTL,
		NoteTTL:              defaultNoteTTL,
		MaxNotesPerRoom:      defaultMaxNotesPerRoom,
		MaxNoteBytes:         defaultMaxCiphertextBytes,
		MaxRoomNoteBytes:     defaultMaxRoomNoteBytes,
	}
}

// Hub 是进程内唯一的房间注册表。
//
// 零信任约束：
//   - Hub 不连接数据库；
//   - Hub 不写磁盘；
//   - Hub 不保存明文聊天内容；
//   - Hub 只保存房间名、公钥字符串、公钥哈希 ID 和 WebSocket 连接指针。
//
// 一旦进程退出，所有房间与成员状态都会自然消失。
type Hub struct {
	cfg Config

	mu                   sync.Mutex
	rooms                map[string]*room
	clients              int
	globalJoinLimiter    *tokenBucket
	globalMessageLimiter *tokenBucket
	clientJoinLimiters   map[string]*clientLimiter
	clientBlacklist      map[string]time.Time
}

// NewHub 创建一个新的纯内存转发中心。
func NewHub(cfg Config) *Hub {
	cfg = normalizeConfig(cfg)

	return &Hub{
		cfg:                  cfg,
		rooms:                make(map[string]*room),
		globalJoinLimiter:    newTokenBucket(cfg.GlobalJoinRate, cfg.GlobalJoinBurst, time.Now()),
		globalMessageLimiter: newTokenBucket(cfg.GlobalMessageRate, cfg.GlobalMessageBurst, time.Now()),
		clientJoinLimiters:   make(map[string]*clientLimiter),
		clientBlacklist:      make(map[string]time.Time),
	}
}

type clientKeyContextKey struct{}

// WithClientKey stores a short-lived, in-memory client limiter key on the request context.
func WithClientKey(ctx context.Context, key string) context.Context {
	key = strings.TrimSpace(key)
	if key == "" {
		return ctx
	}
	return context.WithValue(ctx, clientKeyContextKey{}, key)
}

// ClientKeyFromRequest returns the limiter key captured by the HTTP layer, falling back
// to the TCP peer address. The value is only used in memory for TTL rate limiting.
func ClientKeyFromRequest(request *http.Request) string {
	if request == nil {
		return ""
	}
	if value, ok := request.Context().Value(clientKeyContextKey{}).(string); ok && value != "" {
		return value
	}
	return NormalizeClientKey(request.RemoteAddr)
}

// NormalizeClientKey canonicalizes an IP-ish value for in-memory rate limiting.
// IPv6 addresses are aggregated to /64 to avoid trivial per-address rotation.
func NormalizeClientKey(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if idx := strings.IndexByte(value, ','); idx >= 0 {
		value = strings.TrimSpace(value[:idx])
	}
	value = strings.Trim(value, "[]\"'")
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = strings.Trim(host, "[]")
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return ""
	}
	if addr.Is4() || addr.Is4In6() {
		return addr.Unmap().String()
	}
	return netip.PrefixFrom(addr, 64).Masked().String()
}

// HandleWebSocket 是 Echo 路由处理函数。
//
// 协议入口：
//
//	GET /ws/:room
//
// 握手阶段客户端必须首先发送：
//
//	{"type":"hello","idKey":"Ed25519 身份公钥 Base64","dhKey":"X25519 会话公钥 Base64","dhSig":"身份私钥对会话公钥的签名 Base64"}
//
// 服务端只对身份公钥做 SHA-256 派生匿名 ID，不验证签名、不保存任何私钥或会话密钥。
func (h *Hub) HandleWebSocket(c *echo.Context) error {
	roomName := c.Param("room")
	if !validRoomName(roomName) {
		return c.NoContent(http.StatusNotFound)
	}
	clientKey := ClientKeyFromRequest(c.Request())
	if !h.allowJoinRequest(roomName, clientKey, time.Now()) {
		return c.NoContent(http.StatusTooManyRequests)
	}

	conn, err := websocket.Accept(c.Response(), c.Request(), &websocket.AcceptOptions{
		// 禁用压缩：压缩会把不同消息放进压缩上下文，隐私系统中通常不应让密文
		// 和协议字段共享压缩状态，也避免额外的内存驻留面。
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		return err
	}
	defer conn.Close(websocket.StatusNormalClosure, "")

	conn.SetReadLimit(h.cfg.MaxInboundBytes)

	requestCtx := c.Request().Context()
	client, err := h.acceptHello(requestCtx, conn)
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "invalid hello")
		return nil
	}
	client.hub = h
	client.clientKey = clientKey

	peers, err := h.join(roomName, client)
	if err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, "room rejected")
		return nil
	}

	joined := true
	defer func() {
		if joined {
			h.leave(client, true)
		}
	}()

	if err := client.writeJSON(requestCtx, welcomeFrame{
		Type: "welcome",
		Self: publicPeer{
			ID:    client.id,
			IDKey: client.idKey,
			DHKey: client.dhKey,
			DHSig: client.dhSig,
		},
		Peers: peers,
		Notes: client.room.snapshotNotes(time.Now()),
	}, true); err != nil {
		return nil
	}

	h.broadcastPeerJoined(client)

	rateLimiter := newMessageRateLimiter(time.Now())
	for {
		msgType, data, err := conn.Read(requestCtx)
		if err != nil {
			return nil
		}

		if !rateLimiter.allow(time.Now()) {
			zeroBytes(data)
			h.blacklistClient(client.clientKey, time.Now())
			_ = conn.Close(websocket.StatusPolicyViolation, "rate")
			return nil
		}

		if !h.allowMessage(client, time.Now()) {
			zeroBytes(data)
			h.blacklistClient(client.clientKey, time.Now())
			_ = conn.Close(websocket.StatusPolicyViolation, "rate")
			return nil
		}

		if msgType != websocket.MessageText {
			zeroBytes(data)
			_ = conn.Close(websocket.StatusUnsupportedData, "text only")
			return nil
		}

		err = h.handleClientEnvelope(requestCtx, client, data)
		zeroBytes(data)
		if err != nil {
			_ = conn.Close(websocket.StatusPolicyViolation, "invalid envelope")
			return nil
		}
	}
}

// acceptHello 只读取第一帧握手信息，并由身份公钥派生匿名 ID。
//
// 这里没有注册、登录、密码或服务端身份数据库；身份公钥本身就是匿名身份材料。
func (h *Hub) acceptHello(parent context.Context, conn *websocket.Conn) (*client, error) {
	ctx, cancel := context.WithTimeout(parent, h.cfg.HandshakeTimeout)
	defer cancel()

	msgType, data, err := conn.Read(ctx)
	if err != nil {
		return nil, err
	}
	defer zeroBytes(data)

	if msgType != websocket.MessageText {
		return nil, errors.New("hello must be text")
	}

	var hello helloEnvelope
	if err := json.Unmarshal(data, &hello); err != nil {
		return nil, err
	}
	if hello.Type != "hello" {
		return nil, errors.New("first frame must be hello")
	}
	if !validPublicKey(hello.IDKey, h.cfg.MaxPublicKeyBytes) {
		return nil, errors.New("invalid identity key")
	}
	if !validPublicKey(hello.DHKey, h.cfg.MaxPublicKeyBytes) {
		return nil, errors.New("invalid dh key")
	}
	if !validPublicKey(hello.DHSig, h.cfg.MaxPublicKeyBytes) {
		return nil, errors.New("invalid dh signature")
	}

	return &client{
		id:    publicKeyID(hello.IDKey),
		idKey: hello.IDKey,
		dhKey: hello.DHKey,
		dhSig: hello.DHSig,
		conn:  conn,
	}, nil
}

// handleClientEnvelope 先窥视 type，再分派：send（密文扇出）或 note_put（留言入信箱）。
func (h *Hub) handleClientEnvelope(ctx context.Context, sender *client, data []byte) error {
	var peek struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(data, &peek); err != nil {
		return err
	}
	switch peek.Type {
	case "send":
		return h.handleSend(ctx, sender, data)
	case "note_put":
		return h.handleNotePut(sender, data)
	default:
		return errors.New("unsupported envelope type")
	}
}

// handleSend 处理客户端扇出包。
//
// 客户端示例：
//
//	{
//	  "type": "send",
//	  "messages": [
//	    {"dest":"接收者公钥哈希 ID 或接收者公钥本身","payload":"密文 Base64"}
//	  ]
//	}
//
// 服务端只做三件事：
//   - 根据 dest 定位内存中的 WebSocket 连接；
//   - 原样转发 payload 这个 JSON 字符串值；
//   - 写入完成后立刻清零本层持有的 []byte。
func (h *Hub) handleSend(ctx context.Context, sender *client, data []byte) error {
	var envelope sendEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	defer zeroFanoutPayloads(envelope.Messages)

	if envelope.Type != "send" {
		return errors.New("unsupported envelope type")
	}
	if len(envelope.Messages) == 0 || len(envelope.Messages) > h.cfg.MaxFanoutPerEnvelope {
		return errors.New("invalid fanout size")
	}

	for idx := range envelope.Messages {
		item := &envelope.Messages[idx]
		if !validDest(item.Dest, h.cfg.MaxPublicKeyBytes) {
			zeroBytes(item.Payload)
			return errors.New("invalid destination")
		}
		if !validCiphertextPayload(item.Payload, h.cfg.MaxCiphertextBytes) {
			zeroBytes(item.Payload)
			return errors.New("invalid payload")
		}

		recipient := sender.room.resolveRecipient(item.Dest)
		if recipient == nil {
			zeroBytes(item.Payload)
			continue
		}
		if recipient.id == sender.id {
			zeroBytes(item.Payload)
			continue
		}

		frame := buildCiphertextFrame(sender.id, item.Payload)
		zeroBytes(item.Payload)

		if err := recipient.writeRaw(ctx, frame, true); err != nil {
			h.leave(recipient, true)
		}
	}

	return nil
}

// handleNotePut 把一条留言（不可解密的密文字符串）存入当前房间信箱，并实时广播给其他在线成员。
//
// 客户端示例：{"type":"note_put","note":"<不透明密文字符串>"}
//
// 留言安全性弱于实时端到端消息：服务端持有密文、无前向保密、同房间任何人都能解（用房间预共享密钥），
// 因此前端会以醒目样式区分。服务端依旧零知识：只校验长度与「是 JSON 字符串值」，绝不解码内容。
func (h *Hub) handleNotePut(sender *client, data []byte) error {
	var envelope notePutEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return err
	}
	if envelope.Type != "note_put" {
		zeroBytes(envelope.Note)
		return errors.New("unsupported envelope type")
	}
	if !validCiphertextPayload(envelope.Note, h.cfg.MaxNoteBytes) {
		zeroBytes(envelope.Note)
		return errors.New("invalid note")
	}

	// note 别名指向即将被调用方清零的 data，必须先拷贝出独立副本再入信箱。
	noteCopy := append(json.RawMessage(nil), envelope.Note...)
	zeroBytes(envelope.Note)

	r := sender.room
	if r == nil {
		return errors.New("note without room")
	}
	r.addNote(noteCopy, time.Now())
	r.broadcastExcept(sender.id, noteFrame{Type: "note", Note: noteCopy})
	return nil
}

func normalizeConfig(cfg Config) Config {
	if cfg.MaxRoomMembers <= 0 {
		cfg.MaxRoomMembers = defaultMaxRoomMembers
	}
	if cfg.MaxRooms <= 0 {
		cfg.MaxRooms = defaultMaxRooms
	}
	if cfg.MaxClients <= 0 {
		cfg.MaxClients = cfg.MaxRoomMembers * cfg.MaxRooms
	}
	if cfg.MaxPublicKeyBytes <= 0 {
		cfg.MaxPublicKeyBytes = defaultMaxPublicKeyBytes
	}
	if cfg.MaxInboundBytes <= 0 {
		cfg.MaxInboundBytes = defaultMaxInboundBytes
	}
	if cfg.MaxCiphertextBytes <= 0 {
		cfg.MaxCiphertextBytes = defaultMaxCiphertextBytes
	}
	if cfg.MaxFanoutPerEnvelope <= 0 {
		cfg.MaxFanoutPerEnvelope = defaultMaxFanoutPerEnvelope
	}
	if cfg.HandshakeTimeout <= 0 {
		cfg.HandshakeTimeout = defaultHandshakeTimeout
	}
	if cfg.WriteTimeout <= 0 {
		cfg.WriteTimeout = defaultWriteTimeout
	}
	if cfg.GlobalJoinRate <= 0 {
		cfg.GlobalJoinRate = defaultGlobalJoinRate
	}
	if cfg.GlobalJoinBurst <= 0 {
		cfg.GlobalJoinBurst = defaultGlobalJoinBurst
	}
	if cfg.GlobalMessageRate <= 0 {
		cfg.GlobalMessageRate = defaultGlobalMessageRate
	}
	if cfg.GlobalMessageBurst <= 0 {
		cfg.GlobalMessageBurst = defaultGlobalMessageBurst
	}
	if cfg.RoomJoinRate <= 0 {
		cfg.RoomJoinRate = defaultRoomJoinRate
	}
	if cfg.RoomJoinBurst <= 0 {
		cfg.RoomJoinBurst = defaultRoomJoinBurst
	}
	if cfg.RoomMessageRate <= 0 {
		cfg.RoomMessageRate = defaultRoomMessageRate
	}
	if cfg.RoomMessageBurst <= 0 {
		cfg.RoomMessageBurst = defaultRoomMessageBurst
	}
	if cfg.ClientJoinRate <= 0 {
		cfg.ClientJoinRate = defaultClientJoinRate
	}
	if cfg.ClientJoinBurst <= 0 {
		cfg.ClientJoinBurst = defaultClientJoinBurst
	}
	if cfg.ClientBlacklistTTL <= 0 {
		cfg.ClientBlacklistTTL = defaultClientBlacklistTTL
	}
	if cfg.NoteTTL <= 0 {
		cfg.NoteTTL = defaultNoteTTL
	}
	if cfg.MaxNotesPerRoom <= 0 {
		cfg.MaxNotesPerRoom = defaultMaxNotesPerRoom
	}
	if cfg.MaxNoteBytes <= 0 {
		cfg.MaxNoteBytes = defaultMaxCiphertextBytes
	}
	if cfg.MaxRoomNoteBytes <= 0 {
		cfg.MaxRoomNoteBytes = defaultMaxRoomNoteBytes
	}

	return cfg
}

func (h *Hub) join(roomName string, c *client) ([]publicPeer, error) {
	now := time.Now()
	reserved := false

	h.mu.Lock()
	r := h.rooms[roomName]
	if r == nil {
		if len(h.rooms) >= h.cfg.MaxRooms {
			// 容量吃紧时，先回收「已无人且无未过期留言」的空房间（留言信箱可能让空房间续命到 TTL）。
			h.sweepEmptyRoomsLocked(now)
		}
		if len(h.rooms) >= h.cfg.MaxRooms {
			h.mu.Unlock()
			return nil, errors.New("too many rooms")
		}
		r = &room{
			name:           roomName,
			hub:            h,
			clients:        make(map[string]*client),
			joinLimiter:    newTokenBucket(h.cfg.RoomJoinRate, h.cfg.RoomJoinBurst, now),
			messageLimiter: newTokenBucket(h.cfg.RoomMessageRate, h.cfg.RoomMessageBurst, now),
		}
		h.rooms[roomName] = r
	}
	if h.clients >= h.cfg.MaxClients {
		h.mu.Unlock()
		return nil, errors.New("too many clients")
	}
	h.clients++
	reserved = true
	h.mu.Unlock()
	defer func() {
		if reserved {
			h.releaseClientReservation(r)
		}
	}()

	r.mu.Lock()
	defer r.mu.Unlock()

	if !r.joinLimiter.allow(now) {
		return nil, errors.New("room join rate exceeded")
	}
	if len(r.clients) >= h.cfg.MaxRoomMembers {
		return nil, errors.New("room full")
	}
	if _, exists := r.clients[c.id]; exists {
		return nil, errors.New("duplicate public key")
	}

	peers := make([]publicPeer, 0, len(r.clients))
	for _, existing := range r.clients {
		peers = append(peers, publicPeer{
			ID:    existing.id,
			IDKey: existing.idKey,
			DHKey: existing.dhKey,
			DHSig: existing.dhSig,
		})
	}

	c.room = r
	r.clients[c.id] = c
	reserved = false

	return peers, nil
}

func (h *Hub) leave(c *client, notify bool) {
	if c == nil || c.room == nil {
		return
	}

	r := c.room
	removed := false

	r.mu.Lock()
	if current := r.clients[c.id]; current == c {
		delete(r.clients, c.id)
		removed = true
	}
	empty := len(r.clients) == 0
	r.mu.Unlock()

	if !removed {
		return
	}

	if empty {
		h.mu.Lock()
		if h.clients > 0 {
			h.clients--
		}
		// 房间空了，但若信箱里还有未过期留言，则保留房间，让离线成员之后仍能取到留言。
		if h.rooms[r.name] == r && !r.hasLiveNotes(time.Now()) {
			delete(h.rooms, r.name)
		}
		h.mu.Unlock()
	} else {
		h.mu.Lock()
		if h.clients > 0 {
			h.clients--
		}
		h.mu.Unlock()
	}

	_ = c.conn.Close(websocket.StatusNormalClosure, "")

	if notify {
		h.broadcastPeerLeft(r, c.id)
	}
}

func (h *Hub) releaseClientReservation(r *room) {
	empty := false
	if r != nil {
		r.mu.RLock()
		empty = len(r.clients) == 0
		r.mu.RUnlock()
	}

	h.mu.Lock()
	if h.clients > 0 {
		h.clients--
	}
	if empty && r != nil && h.rooms[r.name] == r && !r.hasLiveNotes(time.Now()) {
		delete(h.rooms, r.name)
	}
	h.mu.Unlock()
}

// sweepEmptyRoomsLocked 在持有 h.mu 时回收「无人在线且无未过期留言」的房间。
// MaxRooms 有上限（默认 128），遍历开销很小；这是无后台协程的惰性清理。
func (h *Hub) sweepEmptyRoomsLocked(now time.Time) {
	for name, r := range h.rooms {
		r.mu.RLock()
		empty := len(r.clients) == 0
		live := r.hasLiveNotesLocked(now)
		r.mu.RUnlock()
		if empty && !live {
			delete(h.rooms, name)
		}
	}
}

func (h *Hub) broadcastPeerJoined(joined *client) {
	joined.room.broadcastExcept(joined.id, peerJoinedFrame{
		Type: "peer_joined",
		Peer: publicPeer{
			ID:    joined.id,
			IDKey: joined.idKey,
			DHKey: joined.dhKey,
			DHSig: joined.dhSig,
		},
	})
}

func (h *Hub) broadcastPeerLeft(r *room, id string) {
	r.broadcastExcept(id, peerLeftFrame{
		Type: "peer_left",
		ID:   id,
	})
}

type room struct {
	name string
	hub  *Hub

	mu             sync.RWMutex
	clients        map[string]*client
	joinLimiter    *tokenBucket
	messageLimiter *tokenBucket
	notes          []storedNote
}

// storedNote 是房间信箱里一条留言：服务端只持有不透明密文字符串、留存时间与字节数，永不解密。
type storedNote struct {
	payload  json.RawMessage
	storedAt time.Time
	size     int
}

// addNote 把一条留言写入房间信箱：先清掉过期项，再按条数/总字节上限淘汰最旧的留言。
func (r *room) addNote(payload json.RawMessage, now time.Time) {
	cfg := r.hub.cfg
	r.mu.Lock()
	defer r.mu.Unlock()

	r.purgeExpiredLocked(now)
	r.notes = append(r.notes, storedNote{payload: payload, storedAt: now, size: len(payload)})

	if cfg.MaxNotesPerRoom > 0 && len(r.notes) > cfg.MaxNotesPerRoom {
		r.notes = append(r.notes[:0], r.notes[len(r.notes)-cfg.MaxNotesPerRoom:]...)
	}
	if cfg.MaxRoomNoteBytes > 0 {
		total := 0
		for _, note := range r.notes {
			total += note.size
		}
		for total > cfg.MaxRoomNoteBytes && len(r.notes) > 1 {
			total -= r.notes[0].size
			r.notes = r.notes[1:]
		}
	}
}

// snapshotNotes 清掉过期留言后，返回剩余留言密文的拷贝，用于随 welcome 投递给新加入者。
func (r *room) snapshotNotes(now time.Time) []json.RawMessage {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.purgeExpiredLocked(now)
	if len(r.notes) == 0 {
		return nil
	}
	out := make([]json.RawMessage, 0, len(r.notes))
	for _, note := range r.notes {
		out = append(out, append(json.RawMessage(nil), note.payload...))
	}
	return out
}

// hasLiveNotes 报告房间是否仍有未过期留言；房间空了但还有留言时不能被回收。
func (r *room) hasLiveNotes(now time.Time) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hasLiveNotesLocked(now)
}

func (r *room) hasLiveNotesLocked(now time.Time) bool {
	ttl := r.hub.cfg.NoteTTL
	for _, note := range r.notes {
		if now.Sub(note.storedAt) < ttl {
			return true
		}
	}
	return false
}

func (r *room) purgeExpiredLocked(now time.Time) {
	ttl := r.hub.cfg.NoteTTL
	kept := r.notes[:0]
	for _, note := range r.notes {
		if now.Sub(note.storedAt) < ttl {
			kept = append(kept, note)
		}
	}
	for i := len(kept); i < len(r.notes); i++ {
		r.notes[i] = storedNote{}
	}
	r.notes = kept
}

func (r *room) resolveRecipient(dest string) *client {
	r.mu.RLock()
	defer r.mu.RUnlock()

	if c := r.clients[dest]; c != nil {
		return c
	}
	return r.clients[publicKeyID(dest)]
}

func (r *room) broadcastExcept(excludedID string, frame any) {
	targets := r.snapshotExcept(excludedID)
	for _, target := range targets {
		if err := target.writeJSON(context.Background(), frame, true); err != nil {
			r.hub.leave(target, false)
		}
	}
}

func (r *room) snapshotExcept(excludedID string) []*client {
	r.mu.RLock()
	defer r.mu.RUnlock()

	targets := make([]*client, 0, len(r.clients))
	for id, c := range r.clients {
		if id == excludedID {
			continue
		}
		targets = append(targets, c)
	}

	return targets
}

type client struct {
	hub *Hub

	id        string
	idKey     string
	dhKey     string
	dhSig     string
	conn      *websocket.Conn
	room      *room
	clientKey string

	writeMu sync.Mutex
}

func (c *client) writeJSON(parent context.Context, value any, zeroAfterWrite bool) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return c.writeRaw(parent, data, zeroAfterWrite)
}

func (c *client) writeRaw(parent context.Context, data []byte, zeroAfterWrite bool) error {
	if zeroAfterWrite {
		defer zeroBytes(data)
	}

	timeout := c.hub.cfg.WriteTimeout
	if timeout <= 0 {
		timeout = defaultWriteTimeout
	}

	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	c.writeMu.Lock()
	defer c.writeMu.Unlock()

	return c.conn.Write(ctx, websocket.MessageText, data)
}

type helloEnvelope struct {
	Type  string `json:"type"`
	IDKey string `json:"idKey"`
	DHKey string `json:"dhKey"`
	DHSig string `json:"dhSig"`
}

type sendEnvelope struct {
	Type     string       `json:"type"`
	Messages []fanoutItem `json:"messages"`
}

type notePutEnvelope struct {
	Type string          `json:"type"`
	Note json.RawMessage `json:"note"`
}

type noteFrame struct {
	Type string          `json:"type"`
	Note json.RawMessage `json:"note"`
}

type fanoutItem struct {
	Dest    string          `json:"dest"`
	Payload json.RawMessage `json:"payload"`
}

type welcomeFrame struct {
	Type  string            `json:"type"`
	Self  publicPeer        `json:"self"`
	Peers []publicPeer      `json:"peers"`
	Notes []json.RawMessage `json:"notes,omitempty"`
}

type peerJoinedFrame struct {
	Type string     `json:"type"`
	Peer publicPeer `json:"peer"`
}

type peerLeftFrame struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type publicPeer struct {
	ID    string `json:"id"`
	IDKey string `json:"idKey"`
	DHKey string `json:"dhKey"`
	DHSig string `json:"dhSig"`
}

// buildCiphertextFrame 手写最小 JSON，避免把 payload 解码成 Go string。
//
// payload 是 json.RawMessage，内容必须已经由 validCiphertextPayload 确认为
// 一个 JSON 字符串值（例如 "Base64Ciphertext"）。服务端不解码这个字符串，
// 因而不会接触明文，也不会尝试识别密文格式。
func buildCiphertextFrame(from string, payload json.RawMessage) []byte {
	frame := make([]byte, 0, len(from)+len(payload)+48)
	frame = append(frame, `{"type":"ciphertext","from":"`...)
	frame = append(frame, from...)
	frame = append(frame, `","payload":`...)
	frame = append(frame, payload...)
	frame = append(frame, '}')
	return frame
}

func (h *Hub) allowJoinRequest(roomName string, clientKey string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()

	h.cleanupClientLimiters(now)

	if blockedUntil, ok := h.clientBlacklist[clientKey]; ok {
		if now.Before(blockedUntil) {
			return false
		}
		delete(h.clientBlacklist, clientKey)
	}
	if !h.globalJoinLimiter.allow(now) {
		return false
	}
	if h.clients >= h.cfg.MaxClients {
		return false
	}
	if h.rooms[roomName] == nil && len(h.rooms) >= h.cfg.MaxRooms {
		return false
	}
	if clientKey == "" {
		return true
	}

	limiter := h.clientJoinLimiters[clientKey]
	if limiter == nil {
		limiter = &clientLimiter{
			joins: newTokenBucket(h.cfg.ClientJoinRate, h.cfg.ClientJoinBurst, now),
		}
		h.clientJoinLimiters[clientKey] = limiter
	}
	limiter.lastSeen = now
	if limiter.joins.allow(now) {
		return true
	}
	h.clientBlacklist[clientKey] = now.Add(h.cfg.ClientBlacklistTTL)
	return false
}

func (h *Hub) allowMessage(c *client, now time.Time) bool {
	h.mu.Lock()
	globalOK := h.globalMessageLimiter.allow(now)
	h.mu.Unlock()
	if !globalOK {
		return false
	}
	if c == nil || c.room == nil {
		return false
	}

	c.room.mu.Lock()
	defer c.room.mu.Unlock()
	return c.room.messageLimiter.allow(now)
}

func (h *Hub) blacklistClient(clientKey string, now time.Time) {
	if clientKey == "" {
		return
	}
	h.mu.Lock()
	h.clientBlacklist[clientKey] = now.Add(h.cfg.ClientBlacklistTTL)
	h.mu.Unlock()
}

func (h *Hub) cleanupClientLimiters(now time.Time) {
	expiresBefore := now.Add(-h.cfg.ClientBlacklistTTL)
	for key, limiter := range h.clientJoinLimiters {
		if limiter.lastSeen.Before(expiresBefore) {
			delete(h.clientJoinLimiters, key)
		}
	}
	for key, blockedUntil := range h.clientBlacklist {
		if !now.Before(blockedUntil) {
			delete(h.clientBlacklist, key)
		}
	}
}

func publicKeyID(idKey string) string {
	sum := sha256.Sum256([]byte(idKey))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

type clientLimiter struct {
	joins    *tokenBucket
	lastSeen time.Time
}

type tokenBucket struct {
	tokens          float64
	capacity        float64
	refillPerSecond float64
	last            time.Time
}

func newTokenBucket(ratePerSecond int, burst int, now time.Time) *tokenBucket {
	return &tokenBucket{
		tokens:          float64(burst),
		capacity:        float64(burst),
		refillPerSecond: float64(ratePerSecond),
		last:            now,
	}
}

func (bucket *tokenBucket) allow(now time.Time) bool {
	if bucket == nil {
		return true
	}
	if now.After(bucket.last) {
		bucket.tokens += now.Sub(bucket.last).Seconds() * bucket.refillPerSecond
		if bucket.tokens > bucket.capacity {
			bucket.tokens = bucket.capacity
		}
		bucket.last = now
	}
	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

type messageRateLimiter struct {
	tokens float64
	last   time.Time
}

func newMessageRateLimiter(now time.Time) *messageRateLimiter {
	return &messageRateLimiter{
		tokens: defaultRateLimitBurst,
		last:   now,
	}
}

func (bucket *messageRateLimiter) allow(now time.Time) bool {
	if now.After(bucket.last) {
		bucket.tokens += now.Sub(bucket.last).Seconds() * defaultRateLimitPerSecond
		if bucket.tokens > defaultRateLimitBurst {
			bucket.tokens = defaultRateLimitBurst
		}
		bucket.last = now
	}

	if bucket.tokens < 1 {
		return false
	}
	bucket.tokens--
	return true
}

func validRoomName(name string) bool {
	if len(name) < 1 || len(name) > 64 {
		return false
	}
	for _, ch := range name {
		switch {
		case ch >= 'a' && ch <= 'z':
		case ch >= 'A' && ch <= 'Z':
		case ch >= '0' && ch <= '9':
		case ch == '-' || ch == '_':
		default:
			return false
		}
	}
	return true
}

func validPublicKey(key string, maxBytes int) bool {
	if key == "" || len(key) > maxBytes || !utf8.ValidString(key) {
		return false
	}
	if strings.TrimSpace(key) != key {
		return false
	}
	for _, ch := range key {
		if ch < 0x20 {
			return false
		}
	}
	return true
}

func validDest(dest string, maxBytes int) bool {
	return validPublicKey(dest, maxBytes)
}

func validCiphertextPayload(payload json.RawMessage, maxBytes int) bool {
	if len(payload) < 3 || len(payload) > maxBytes {
		return false
	}
	if payload[0] != '"' || payload[len(payload)-1] != '"' {
		return false
	}
	return json.Valid(payload)
}

func zeroFanoutPayloads(messages []fanoutItem) {
	for idx := range messages {
		zeroBytes(messages[idx].Payload)
	}
}

// zeroBytes 对本应用层显式持有的 []byte 做尽力清零。
//
// 重要限制：
//   - Go 运行时、WebSocket 库、内核 socket 缓冲区可能产生额外拷贝；
//   - json.Unmarshal 到 string 的字段不可原地清零，所以密文字段使用 RawMessage；
//   - 这不是“内存取证不可恢复”的绝对保证，而是服务端可控层面的最小驻留策略。
func zeroBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}
