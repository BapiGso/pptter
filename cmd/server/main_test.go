package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/labstack/echo/v5"

	"pptter/internal/stunserver"
)

func TestLoadServerConfigDefaults(test *testing.T) {
	cfg, err := loadServerConfig(nil, testEnv(nil), io.Discard)
	if err != nil {
		test.Fatalf("load server config: %v", err)
	}

	if cfg.HTTPAddr != defaultAddr {
		test.Fatalf("HTTPAddr = %q, want %q", cfg.HTTPAddr, defaultAddr)
	}
	if !cfg.STUNEnabled {
		test.Fatal("STUNEnabled = false, want true")
	}
	if cfg.STUNPort != stunserver.DefaultPort {
		test.Fatalf("STUNPort = %d, want %d", cfg.STUNPort, stunserver.DefaultPort)
	}
	if cfg.STUNHost != "" {
		test.Fatalf("STUNHost = %q, want empty", cfg.STUNHost)
	}
	if cfg.Title != defaultTitle {
		test.Fatalf("Title = %q, want %q", cfg.Title, defaultTitle)
	}
}

func TestLoadServerConfigFromEnvironment(test *testing.T) {
	cfg, err := loadServerConfig(nil, testEnv(map[string]string{
		"ADDR":         ":9000",
		"STUN_ENABLED": "false",
		"STUN_PORT":    "3479",
		"STUN_HOST":    "chat.example.test",
		"CHAT_TITLE":   "私有聊天室",
	}), io.Discard)
	if err != nil {
		test.Fatalf("load server config: %v", err)
	}

	if cfg.HTTPAddr != ":9000" {
		test.Fatalf("HTTPAddr = %q, want :9000", cfg.HTTPAddr)
	}
	if cfg.STUNEnabled {
		test.Fatal("STUNEnabled = true, want false")
	}
	if cfg.STUNPort != 3479 {
		test.Fatalf("STUNPort = %d, want 3479", cfg.STUNPort)
	}
	if cfg.STUNHost != "chat.example.test" {
		test.Fatalf("STUNHost = %q, want chat.example.test", cfg.STUNHost)
	}
	if cfg.Title != "私有聊天室" {
		test.Fatalf("Title = %q, want 私有聊天室", cfg.Title)
	}
}

func TestLoadServerConfigFlagsOverrideEnvironment(test *testing.T) {
	cfg, err := loadServerConfig([]string{
		"-addr", "127.0.0.1:8088",
		"-stun=true",
		"-stun-port", "0",
		"-stun-host", "public.example.test",
		"-title", "公开大厅",
	}, testEnv(map[string]string{
		"ADDR":         ":9000",
		"STUN_ENABLED": "false",
		"STUN_PORT":    "3479",
		"STUN_HOST":    "chat.example.test",
		"CHAT_TITLE":   "私有聊天室",
	}), io.Discard)
	if err != nil {
		test.Fatalf("load server config: %v", err)
	}

	if cfg.HTTPAddr != "127.0.0.1:8088" {
		test.Fatalf("HTTPAddr = %q, want 127.0.0.1:8088", cfg.HTTPAddr)
	}
	if !cfg.STUNEnabled {
		test.Fatal("STUNEnabled = false, want true")
	}
	if cfg.STUNPort != 0 {
		test.Fatalf("STUNPort = %d, want 0", cfg.STUNPort)
	}
	if cfg.STUNHost != "public.example.test" {
		test.Fatalf("STUNHost = %q, want public.example.test", cfg.STUNHost)
	}
	if cfg.Title != "公开大厅" {
		test.Fatalf("Title = %q, want 公开大厅", cfg.Title)
	}
}

func TestLoadServerConfigRejectsHTTPPortShortcut(test *testing.T) {
	_, err := loadServerConfig([]string{"-http-port", "9090"}, testEnv(nil), io.Discard)
	if err == nil {
		test.Fatal("load server config succeeded, want error")
	}
}

func TestLoadServerConfigRejectsInvalidPorts(test *testing.T) {
	for _, args := range [][]string{
		{"-stun-port", "-1"},
		{"-stun-port", "70000"},
	} {
		_, err := loadServerConfig(args, testEnv(nil), io.Discard)
		if err == nil {
			test.Fatalf("load server config with %v succeeded, want error", args)
		}
	}
}

func TestRenderIndexHTMLInjectsEscapedTitle(test *testing.T) {
	index := []byte("<title>PPTTER Zero Trust</title><h2>关于 PPTTER</h2>")
	got := string(renderIndexHTML(index, `A&B <Chat>`))
	want := "<title>A&amp;B &lt;Chat&gt;</title><h2>关于 A&amp;B &lt;Chat&gt;</h2>"
	if got != want {
		test.Fatalf("rendered index = %q, want %q", got, want)
	}
}

func TestWebRTCConfigHandlerEnabled(test *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stunServer, err := stunserver.Start(ctx, 0)
	if err != nil {
		test.Fatalf("start stun server: %v", err)
	}
	defer stunServer.Close()

	body, header := runWebRTCConfigHandler(test, stunServer, "")
	expected := fmt.Sprintf(`{"enabled":true,"stunPort":%d}`, stunServer.Port())
	if body != expected {
		test.Fatalf("body = %s, want %s", body, expected)
	}
	if header.Get("Cache-Control") != "no-store" {
		test.Fatalf("Cache-Control = %q, want no-store", header.Get("Cache-Control"))
	}
}

func TestWebRTCConfigHandlerIncludesConfiguredHost(test *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	stunServer, err := stunserver.Start(ctx, 0)
	if err != nil {
		test.Fatalf("start stun server: %v", err)
	}
	defer stunServer.Close()

	body, _ := runWebRTCConfigHandler(test, stunServer, "stun.example.test")
	expected := fmt.Sprintf(`{"enabled":true,"stunPort":%d,"stunHost":"stun.example.test"}`, stunServer.Port())
	if body != expected {
		test.Fatalf("body = %s, want %s", body, expected)
	}
}

func TestWebRTCConfigHandlerDisabled(test *testing.T) {
	body, header := runWebRTCConfigHandler(test, nil, "stun.example.test")
	if body != `{"enabled":false}` {
		test.Fatalf("body = %s, want disabled response", body)
	}
	if header.Get("Cache-Control") != "no-store" {
		test.Fatalf("Cache-Control = %q, want no-store", header.Get("Cache-Control"))
	}
}

func TestStripIdentifyingHeadersKeepsStrictCSPWithStun(test *testing.T) {
	echoServer := echo.New()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request.Header.Set("User-Agent", "secret")
	request.Header.Set("X-Forwarded-For", "192.0.2.1")
	recorder := httptest.NewRecorder()
	echoContext := echoServer.NewContext(request, recorder)

	handler := stripIdentifyingHeaders(func(echoContext *echo.Context) error {
		if request.Header.Get("User-Agent") != "" {
			test.Fatal("User-Agent header was not stripped")
		}
		if request.Header.Get("X-Forwarded-For") != "" {
			test.Fatal("X-Forwarded-For header was not stripped")
		}
		return echoContext.NoContent(http.StatusNoContent)
	})
	if err := handler(echoContext); err != nil {
		test.Fatalf("run middleware: %v", err)
	}

	expectedCSP := "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss: stun: stuns:; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests"
	if recorder.Header().Get("Content-Security-Policy") != expectedCSP {
		test.Fatalf("Content-Security-Policy = %q, want %q", recorder.Header().Get("Content-Security-Policy"), expectedCSP)
	}
	if got := recorder.Header().Get("Strict-Transport-Security"); got != "max-age=31536000; includeSubDomains" {
		test.Fatalf("Strict-Transport-Security = %q, want max-age=31536000; includeSubDomains", got)
	}
}

func runWebRTCConfigHandler(test *testing.T, stunServer *stunserver.Server, stunHost string) (string, http.Header) {
	test.Helper()

	echoServer := echo.New()
	request := httptest.NewRequest(http.MethodGet, "/webrtc-config", nil)
	request.Host = "untrusted.example.test"
	recorder := httptest.NewRecorder()
	echoContext := echoServer.NewContext(request, recorder)

	if err := webRTCConfigHandler(stunServer, stunHost)(echoContext); err != nil {
		test.Fatalf("run webrtc config handler: %v", err)
	}

	return strings.TrimSpace(recorder.Body.String()), recorder.Header()
}

func testEnv(values map[string]string) func(string) (string, bool) {
	return func(key string) (string, bool) {
		value, ok := values[key]
		return value, ok
	}
}
