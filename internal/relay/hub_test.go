package relay

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
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

func newTestServer() *httptest.Server {
	e := echo.New()
	e.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))

	cfg := NewConfig()
	cfg.HandshakeTimeout = time.Second
	cfg.WriteTimeout = time.Second

	hub := NewHub(cfg)
	e.GET("/ws/:room", hub.HandleWebSocket)

	return httptest.NewServer(e)
}

func dialTestClient(t *testing.T, ctx context.Context, baseURL, room, idKey, dhKey, dhSig string) *websocket.Conn {
	t.Helper()

	wsURL := "ws" + strings.TrimPrefix(baseURL, "http") + "/ws/" + room
	conn, _, err := websocket.Dial(ctx, wsURL, nil)
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
