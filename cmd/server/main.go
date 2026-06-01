package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"html"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v5"

	"pptter/internal/relay"
	"pptter/internal/stunserver"
	webfs "pptter/web"
)

const (
	defaultAddr  = ":8080"
	defaultTitle = "PPTTER Zero Trust"
)

func main() {
	cfg, err := loadServerConfig(os.Args[1:], os.LookupEnv, os.Stderr)
	if err != nil {
		os.Exit(2)
	}

	e := echo.New()

	// 隐私系统默认不向控制台输出请求信息。
	//
	// Echo 本身不会主动打印请求体，但默认 logger 仍可能在错误场景打印路径、
	// 远端地址等信息；这里直接丢弃框架日志，避免误把 IP / Header 写到 Console。
	e.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	e.IPExtractor = func(*http.Request) string {
		return ""
	}

	// 自定义错误处理：只返回状态码，不记录请求路径、IP、User-Agent 或消息内容。
	e.HTTPErrorHandler = func(c *echo.Context, err error) {
		response, _ := echo.UnwrapResponse(c.Response())
		if response != nil && response.Committed {
			return
		}

		status := echo.StatusCode(err)
		if status == 0 {
			status = http.StatusInternalServerError
		}

		_ = c.NoContent(status)
	}

	e.Pre(captureClientKey)
	e.Pre(stripIdentifyingHeaders)

	hub := relay.NewHub(relay.NewConfig())
	indexHTML, err := fs.ReadFile(webfs.FS(), "index.html")
	if err != nil {
		os.Exit(1)
	}
	indexHTML = renderIndexHTML(indexHTML, cfg.Title)
	faviconICO, err := fs.ReadFile(webfs.FS(), "static/img/favicon.ico")
	if err != nil {
		os.Exit(1)
	}
	serveIndex := func(c *echo.Context) error {
		return c.Blob(http.StatusOK, "text/html; charset=utf-8", indexHTML)
	}
	serveFavicon := func(c *echo.Context) error {
		return c.Blob(http.StatusOK, "image/x-icon", faviconICO)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var stunServer *stunserver.Server
	if cfg.STUNEnabled {
		stunServer, err = stunserver.Start(ctx, cfg.STUNPort)
		if err != nil {
			os.Exit(1)
		}
	}
	defer stunServer.Close()

	// 健康检查不暴露运行细节，只返回 204。
	e.GET("/healthz", func(c *echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})
	e.GET("/favicon.ico", serveFavicon)

	e.GET("/webrtc-config", webRTCConfigHandler(stunServer, cfg.STUNHost))

	// 前端只从本机静态目录加载资源，不引用任何第三方 CDN。
	e.StaticFS("/static", echo.MustSubFS(webfs.FS(), "static"))
	// 单页应用：支持 /r/:room 作为可分享入口；房间名仅用于返回同一个 SPA，
	// 真实房间解析仍在前端完成。
	e.GET("/", serveIndex)
	e.GET("/index.html", serveIndex)
	e.GET("/r/:room", serveIndex)

	// 匿名房间入口：房间名只作为内存 map 的 key，不落盘。
	e.GET("/ws/:room", hub.HandleWebSocket)

	startConfig := echo.StartConfig{
		Address:         cfg.HTTPAddr,
		HideBanner:      true,
		HidePort:        true,
		GracefulTimeout: 5 * time.Second,
		BeforeServeFunc: func(server *http.Server) error {
			server.ErrorLog = log.New(io.Discard, "", 0)
			server.ReadHeaderTimeout = 5 * time.Second
			server.IdleTimeout = 60 * time.Second
			return nil
		},
	}
	if err := startConfig.Start(ctx, e); err != nil && !errors.Is(err, http.ErrServerClosed) {
		os.Exit(1)
	}
}

type serverConfig struct {
	HTTPAddr    string
	STUNEnabled bool
	STUNPort    int
	STUNHost    string
	Title       string
}

func loadServerConfig(args []string, lookupEnv func(string) (string, bool), output io.Writer) (serverConfig, error) {
	cfg, err := defaultServerConfig(lookupEnv)
	if err != nil {
		return serverConfig{}, err
	}

	flags := flag.NewFlagSet("pptter-server", flag.ContinueOnError)
	flags.SetOutput(output)

	flags.StringVar(&cfg.HTTPAddr, "addr", cfg.HTTPAddr, "HTTP listen address, for example :8080 or 127.0.0.1:8080")
	flags.BoolVar(&cfg.STUNEnabled, "stun", cfg.STUNEnabled, "enable built-in first-party STUN server")
	flags.IntVar(&cfg.STUNPort, "stun-port", cfg.STUNPort, "UDP port for the built-in STUN server, 0 means random")
	flags.StringVar(&cfg.STUNHost, "stun-host", cfg.STUNHost, "public STUN hostname advertised to browsers")
	flags.StringVar(&cfg.Title, "title", cfg.Title, "browser title and about-dialog title for the chat")

	if err := flags.Parse(args); err != nil {
		return serverConfig{}, err
	}

	cfg.HTTPAddr = strings.TrimSpace(cfg.HTTPAddr)
	cfg.STUNHost = strings.TrimSpace(cfg.STUNHost)
	cfg.Title = normalizeTitle(cfg.Title)
	if cfg.HTTPAddr == "" {
		return serverConfig{}, errors.New("http listen address cannot be empty")
	}
	if err := validatePort(cfg.STUNPort, "stun-port", true); err != nil {
		return serverConfig{}, err
	}

	return cfg, nil
}

func defaultServerConfig(lookupEnv func(string) (string, bool)) (serverConfig, error) {
	cfg := serverConfig{
		HTTPAddr:    envFirst(lookupEnv, defaultAddr, "ADDR"),
		STUNEnabled: true,
		STUNPort:    stunserver.DefaultPort,
		STUNHost:    envFirst(lookupEnv, "", "STUN_HOST"),
		Title:       normalizeTitle(envFirst(lookupEnv, defaultTitle, "CHAT_TITLE")),
	}

	if rawEnabled := envFirst(lookupEnv, "", "STUN_ENABLED"); rawEnabled != "" {
		enabled, err := parseBool(rawEnabled, "STUN_ENABLED")
		if err != nil {
			return serverConfig{}, err
		}
		cfg.STUNEnabled = enabled
	}

	if rawPort := envFirst(lookupEnv, "", "STUN_PORT"); rawPort != "" {
		port, err := parsePort(rawPort, "STUN_PORT", true)
		if err != nil {
			return serverConfig{}, err
		}
		cfg.STUNPort = port
	}

	return cfg, nil
}

func envFirst(lookupEnv func(string) (string, bool), fallback string, names ...string) string {
	for _, name := range names {
		if value, ok := lookupEnv(name); ok {
			if clean := strings.TrimSpace(value); clean != "" {
				return clean
			}
		}
	}
	return fallback
}

func parsePort(raw string, name string, allowZero bool) (int, error) {
	port, err := strconv.Atoi(strings.TrimSpace(raw))
	if err != nil {
		return 0, fmt.Errorf("invalid %s", name)
	}
	if err := validatePort(port, name, allowZero); err != nil {
		return 0, err
	}
	return port, nil
}

func validatePort(port int, name string, allowZero bool) error {
	if port < 0 || port > 65535 || (!allowZero && port == 0) {
		return fmt.Errorf("invalid %s", name)
	}
	return nil
}

func parseBool(raw string, name string) (bool, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "t", "true", "y", "yes", "on":
		return true, nil
	case "0", "f", "false", "n", "no", "off":
		return false, nil
	default:
		return false, fmt.Errorf("invalid %s", name)
	}
}

func normalizeTitle(title string) string {
	title = strings.TrimSpace(title)
	if title == "" {
		return defaultTitle
	}
	return title
}

func renderIndexHTML(indexHTML []byte, title string) []byte {
	escapedTitle := html.EscapeString(normalizeTitle(title))
	content := string(indexHTML)
	content = strings.ReplaceAll(content, "<title>"+defaultTitle+"</title>", "<title>"+escapedTitle+"</title>")
	content = strings.ReplaceAll(content, "关于 PPTTER", "关于 "+escapedTitle)
	return []byte(content)
}

type webRTCConfigResponse struct {
	Enabled  bool   `json:"enabled"`
	STUNPort *int   `json:"stunPort,omitempty"`
	STUNHost string `json:"stunHost,omitempty"`
}

func webRTCConfigHandler(stunServer *stunserver.Server, stunHost string) echo.HandlerFunc {
	return func(c *echo.Context) error {
		c.Response().Header().Set("Cache-Control", "no-store")

		if !stunServer.Running() {
			return c.JSON(http.StatusOK, webRTCConfigResponse{
				Enabled: false,
			})
		}

		stunPort := stunServer.Port()
		return c.JSON(http.StatusOK, webRTCConfigResponse{
			Enabled:  true,
			STUNPort: &stunPort,
			STUNHost: stunHost,
		})
	}
}

// captureClientKey 在剥离代理头之前，为内存限流捕获一个短期 client key。
// key 不写日志、不落盘；若请求来自本机/内网可信反代，则优先使用代理传来的真实 IP。
func captureClientKey(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		request := c.Request()
		key := relay.NormalizeClientKey(request.RemoteAddr)
		if trustedProxyRemote(request.RemoteAddr) {
			for _, headerName := range []string{
				"CF-Connecting-IP",
				"True-Client-IP",
				"X-Real-IP",
				"X-Forwarded-For",
			} {
				if candidate := relay.NormalizeClientKey(request.Header.Get(headerName)); candidate != "" {
					key = candidate
					break
				}
			}
		}
		if key != "" {
			c.SetRequest(request.WithContext(relay.WithClientKey(request.Context(), key)))
		}
		return next(c)
	}
}

func trustedProxyRemote(remoteAddr string) bool {
	host := remoteAddr
	if splitHost, _, err := net.SplitHostPort(remoteAddr); err == nil {
		host = splitHost
	}
	addr, err := netip.ParseAddr(strings.Trim(host, "[]"))
	if err != nil {
		return false
	}
	return addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast()
}

// stripIdentifyingHeaders 尽量在应用层丢弃可识别请求头。
//
// 限制说明：TCP 远端地址仍会存在于 Go net/http 连接对象和操作系统网络栈中；
// 本中间件的目标是确保业务层不读取、不转发、不记录这些 Header。
func stripIdentifyingHeaders(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c *echo.Context) error {
		header := c.Request().Header
		for _, name := range []string{
			"Forwarded",
			"X-Forwarded-For",
			"X-Forwarded-Host",
			"X-Forwarded-Proto",
			"X-Real-IP",
			"CF-Connecting-IP",
			"True-Client-IP",
			"User-Agent",
			"Referer",
		} {
			header.Del(name)
		}

		response := c.Response().Header()
		response.Set("Cache-Control", "no-store")
		response.Set("Referrer-Policy", "no-referrer")
		response.Set("X-Content-Type-Options", "nosniff")
		// HSTS：强制后续只走 HTTPS，挡 SSL 剥离/降级。浏览器仅在通过 HTTPS 收到时才会采纳，
		// 通过明文 HTTP 收到会被规范忽略，因此即便裸 HTTP 运行也无副作用。
		response.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
		response.Set("Permissions-Policy", "camera=(), microphone=(self), geolocation=(), interest-cohort=()")
		response.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss: stun: stuns:; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; upgrade-insecure-requests")

		return next(c)
	}
}
