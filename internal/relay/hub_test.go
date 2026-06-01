package relay

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/labstack/echo/v5"
)

func TestHubRelaysCiphertextOnlyToDestination(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connA := dialTestClient(t, ctx, server.URL, "room-alpha", "id-key-A", "dh-key-A", "dh-sig-A")
	defer connA.Close(websocket.StatusNormalClosure, "")

	var welcomeA welcomeFrame
	readJSONFrame(t, ctx, connA, &welcomeA)
	if welcomeA.Type != "welcome" {
		t.Fatalf("client A first frame type = %q, want welcome", welcomeA.Type)
	}
	if welcomeA.Self.ID != publicKeyID("id-key-A") {
		t.Fatalf("client A self id = %q, want derived public key id", welcomeA.Self.ID)
	}
	if welcomeA.Self.IDKey != "id-key-A" || welcomeA.Self.DHKey != "dh-key-A" || welcomeA.Self.DHSig != "dh-sig-A" {
		t.Fatalf("client A self keys = %+v, want relayed hello keys", welcomeA.Self)
	}
	if len(welcomeA.Peers) != 0 {
		t.Fatalf("client A peers = %d, want 0", len(welcomeA.Peers))
	}

	connB := dialTestClient(t, ctx, server.URL, "room-alpha", "id-key-B", "dh-key-B", "dh-sig-B")
	defer connB.Close(websocket.StatusNormalClosure, "")

	var welcomeB welcomeFrame
	readJSONFrame(t, ctx, connB, &welcomeB)
	if welcomeB.Type != "welcome" {
		t.Fatalf("client B first frame type = %q, want welcome", welcomeB.Type)
	}
	if welcomeB.Self.ID != publicKeyID("id-key-B") {
		t.Fatalf("client B self id = %q, want derived public key id", welcomeB.Self.ID)
	}
	if len(welcomeB.Peers) != 1 || welcomeB.Peers[0].ID != welcomeA.Self.ID {
		t.Fatalf("client B peers = %+v, want client A", welcomeB.Peers)
	}
	if welcomeB.Peers[0].IDKey != "id-key-A" || welcomeB.Peers[0].DHKey != "dh-key-A" || welcomeB.Peers[0].DHSig != "dh-sig-A" {
		t.Fatalf("client B peer keys = %+v, want client A hello keys", welcomeB.Peers[0])
	}

	var joined peerJoinedFrame
	readJSONFrame(t, ctx, connA, &joined)
	if joined.Type != "peer_joined" || joined.Peer.ID != welcomeB.Self.ID {
		t.Fatalf("client A peer_joined = %+v, want client B", joined)
	}
	if joined.Peer.IDKey != "id-key-B" || joined.Peer.DHKey != "dh-key-B" || joined.Peer.DHSig != "dh-sig-B" {
		t.Fatalf("client A peer_joined keys = %+v, want client B hello keys", joined.Peer)
	}

	writeJSONFrame(t, ctx, connA, sendEnvelope{
		Type: "send",
		Messages: []fanoutItem{
			{
				Dest:    welcomeB.Self.ID,
				Payload: json.RawMessage(`"ciphertext-for-B"`),
			},
		},
	})

	var ciphertext struct {
		Type    string          `json:"type"`
		From    string          `json:"from"`
		Payload json.RawMessage `json:"payload"`
	}
	readJSONFrame(t, ctx, connB, &ciphertext)

	if ciphertext.Type != "ciphertext" {
		t.Fatalf("ciphertext frame type = %q, want ciphertext", ciphertext.Type)
	}
	if ciphertext.From != welcomeA.Self.ID {
		t.Fatalf("ciphertext from = %q, want client A", ciphertext.From)
	}
	if string(ciphertext.Payload) != `"ciphertext-for-B"` {
		t.Fatalf("ciphertext payload = %s, want original opaque JSON string", ciphertext.Payload)
	}
}

func TestHubRejectsRoomsAboveGlobalLimit(t *testing.T) {
	server := newTestServerWithConfig(func(cfg Config) Config {
		cfg.MaxRooms = 1
		cfg.MaxClients = 5
		cfg.ClientJoinBurst = 5
		cfg.GlobalJoinBurst = 5
		return cfg
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connA := dialTestClient(t, ctx, server.URL, "room-alpha", "id-key-A", "dh-key-A", "dh-sig-A")
	defer connA.Close(websocket.StatusNormalClosure, "")

	var welcomeA welcomeFrame
	readJSONFrame(t, ctx, connA, &welcomeA)

	connB, response, err := dialRawTestClient(ctx, server.URL, "room-beta")
	if connB != nil {
		_ = connB.Close(websocket.StatusNormalClosure, "")
	}
	if err == nil {
		t.Fatal("dial second room succeeded, want rejection")
	}
	if response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("second room response status = %v, want 429", responseStatus(response))
	}
}

func TestHubBlacklistsClientAfterJoinBurst(t *testing.T) {
	server := newTestServerWithConfig(func(cfg Config) Config {
		cfg.MaxRooms = 5
		cfg.MaxClients = 5
		cfg.GlobalJoinBurst = 5
		cfg.ClientJoinBurst = 1
		cfg.ClientJoinRate = 1
		cfg.ClientBlacklistTTL = time.Minute
		return cfg
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connA := dialTestClient(t, ctx, server.URL, "room-alpha", "id-key-A", "dh-key-A", "dh-sig-A")
	defer connA.Close(websocket.StatusNormalClosure, "")

	var welcomeA welcomeFrame
	readJSONFrame(t, ctx, connA, &welcomeA)

	connB, response, err := dialRawTestClient(ctx, server.URL, "room-alpha")
	if connB != nil {
		_ = connB.Close(websocket.StatusNormalClosure, "")
	}
	if err == nil {
		t.Fatal("second burst join succeeded, want client blacklist rejection")
	}
	if response == nil || response.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("blacklist response status = %v, want 429", responseStatus(response))
	}
}

func newTestServer() *httptest.Server {
	return newTestServerWithConfig(func(cfg Config) Config { return cfg })
}

func dialNote(t *testing.T, ctx context.Context, baseURL, room, suffix string) *websocket.Conn {
	t.Helper()
	conn := dialTestClient(t, ctx, baseURL, room, "id-key-"+suffix, "dh-key-"+suffix, "dh-sig-"+suffix)
	var welcome welcomeFrame
	readJSONFrame(t, ctx, conn, &welcome)
	return conn
}

func TestHubStoresBroadcastsAndDeliversNotes(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connA := dialNote(t, ctx, server.URL, "room-notes", "A")
	connB := dialNote(t, ctx, server.URL, "room-notes", "B")

	// A 收到 B 加入的 peer_joined，先排掉。
	var joined peerJoinedFrame
	readJSONFrame(t, ctx, connA, &joined)

	writeJSONFrame(t, ctx, connA, notePutEnvelope{Type: "note_put", Note: json.RawMessage(`"note-one"`)})

	// 在线成员 B 实时收到留言（同时作为「已入信箱」的屏障）。
	var live noteFrame
	readJSONFrame(t, ctx, connB, &live)
	if live.Type != "note" || string(live.Note) != `"note-one"` {
		t.Fatalf("B live note = %+v, want type note with note-one", live)
	}

	// 晚到的 C 通过 welcome 拿到信箱里的留言。
	connC := dialTestClient(t, ctx, server.URL, "room-notes", "id-key-C", "dh-key-C", "dh-sig-C")
	var welcomeC welcomeFrame
	readJSONFrame(t, ctx, connC, &welcomeC)
	if len(welcomeC.Notes) != 1 || string(welcomeC.Notes[0]) != `"note-one"` {
		t.Fatalf("C welcome notes = %v, want [note-one]", welcomeC.Notes)
	}

	// 全员离开，房间应因仍有未过期留言而保留；新来的 D 仍能取到。
	_ = connA.Close(websocket.StatusNormalClosure, "")
	_ = connB.Close(websocket.StatusNormalClosure, "")
	_ = connC.Close(websocket.StatusNormalClosure, "")

	connD := dialTestClient(t, ctx, server.URL, "room-notes", "id-key-D", "dh-key-D", "dh-sig-D")
	defer connD.Close(websocket.StatusNormalClosure, "")
	var welcomeD welcomeFrame
	readJSONFrame(t, ctx, connD, &welcomeD)
	if len(welcomeD.Notes) != 1 || string(welcomeD.Notes[0]) != `"note-one"` {
		t.Fatalf("D welcome notes after empty room = %v, want [note-one]", welcomeD.Notes)
	}
}

func TestHubExpiredNotesNotDelivered(t *testing.T) {
	server := newTestServerWithConfig(func(cfg Config) Config {
		cfg.NoteTTL = 40 * time.Millisecond
		return cfg
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connA := dialNote(t, ctx, server.URL, "room-ttl", "A")
	connB := dialNote(t, ctx, server.URL, "room-ttl", "B")
	var joined peerJoinedFrame
	readJSONFrame(t, ctx, connA, &joined)

	writeJSONFrame(t, ctx, connA, notePutEnvelope{Type: "note_put", Note: json.RawMessage(`"stale"`)})
	var live noteFrame
	readJSONFrame(t, ctx, connB, &live) // 屏障：留言已入信箱。

	time.Sleep(80 * time.Millisecond) // 超过 TTL。

	connC := dialTestClient(t, ctx, server.URL, "room-ttl", "id-key-C", "dh-key-C", "dh-sig-C")
	defer connC.Close(websocket.StatusNormalClosure, "")
	var welcomeC welcomeFrame
	readJSONFrame(t, ctx, connC, &welcomeC)
	if len(welcomeC.Notes) != 0 {
		t.Fatalf("C welcome notes after TTL = %v, want none", welcomeC.Notes)
	}

	_ = connA.Close(websocket.StatusNormalClosure, "")
	_ = connB.Close(websocket.StatusNormalClosure, "")
}

func TestHubDropsOldestNoteAbovePerRoomCap(t *testing.T) {
	server := newTestServerWithConfig(func(cfg Config) Config {
		cfg.MaxNotesPerRoom = 2
		return cfg
	})
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connA := dialNote(t, ctx, server.URL, "room-cap", "A")
	connB := dialNote(t, ctx, server.URL, "room-cap", "B")
	var joined peerJoinedFrame
	readJSONFrame(t, ctx, connA, &joined)

	for _, note := range []string{`"n1"`, `"n2"`, `"n3"`} {
		writeJSONFrame(t, ctx, connA, notePutEnvelope{Type: "note_put", Note: json.RawMessage(note)})
		var live noteFrame
		readJSONFrame(t, ctx, connB, &live) // 逐条确认已入信箱。
	}

	connC := dialTestClient(t, ctx, server.URL, "room-cap", "id-key-C", "dh-key-C", "dh-sig-C")
	defer connC.Close(websocket.StatusNormalClosure, "")
	var welcomeC welcomeFrame
	readJSONFrame(t, ctx, connC, &welcomeC)
	if len(welcomeC.Notes) != 2 || string(welcomeC.Notes[0]) != `"n2"` || string(welcomeC.Notes[1]) != `"n3"` {
		t.Fatalf("C welcome notes = %v, want newest two [n2 n3]", welcomeC.Notes)
	}

	_ = connA.Close(websocket.StatusNormalClosure, "")
	_ = connB.Close(websocket.StatusNormalClosure, "")
}

func TestHubRejectsInvalidNotePut(t *testing.T) {
	server := newTestServer()
	defer server.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	connA := dialNote(t, ctx, server.URL, "room-bad", "A")
	defer connA.Close(websocket.StatusNormalClosure, "")

	// note 不是 JSON 字符串值（这里是数字）→ 服务端按策略违规关闭连接。
	writeJSONFrame(t, ctx, connA, notePutEnvelope{Type: "note_put", Note: json.RawMessage(`12345`)})

	if _, _, err := connA.Read(ctx); err == nil {
		t.Fatal("read after invalid note_put succeeded, want connection closed")
	}
}


func newTestServerWithConfig(configure func(Config) Config) *httptest.Server {
	e := echo.New()
	e.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := NewConfig()
	cfg.HandshakeTimeout = time.Second
	cfg.WriteTimeout = time.Second
	cfg = configure(cfg)

	hub := NewHub(cfg)
	e.GET("/ws/:room", hub.HandleWebSocket)

	return httptest.NewServer(e)
}

func dialTestClient(t *testing.T, ctx context.Context, baseURL, room, idKey, dhKey, dhSig string) *websocket.Conn {
	t.Helper()

	conn, _, err := dialRawTestClient(ctx, baseURL, room)
	if err != nil {
		t.Fatalf("dial websocket: %v", err)
	}

	writeJSONFrame(t, ctx, conn, helloEnvelope{
		Type:  "hello",
		IDKey: idKey,
		DHKey: dhKey,
		DHSig: dhSig,
	})

	return conn
}

func dialRawTestClient(ctx context.Context, baseURL string, room string) (*websocket.Conn, *http.Response, error) {
	wsURL := "ws" + strings.TrimPrefix(baseURL, "http") + "/ws/" + room
	return websocket.Dial(ctx, wsURL, nil)
}

func responseStatus(response *http.Response) any {
	if response == nil {
		return nil
	}
	return response.StatusCode
}

func readJSONFrame(t *testing.T, ctx context.Context, conn *websocket.Conn, dest any) {
	t.Helper()

	msgType, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatalf("read websocket frame: %v", err)
	}
	defer zeroBytes(data)

	if msgType != websocket.MessageText {
		t.Fatalf("message type = %v, want text", msgType)
	}
	if err := json.Unmarshal(data, dest); err != nil {
		t.Fatalf("unmarshal frame %s: %v", data, err)
	}
}

func writeJSONFrame(t *testing.T, ctx context.Context, conn *websocket.Conn, value any) {
	t.Helper()

	data, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("marshal frame: %v", err)
	}
	defer zeroBytes(data)

	if err := conn.Write(ctx, websocket.MessageText, data); err != nil {
		t.Fatalf("write websocket frame: %v", err)
	}
}
