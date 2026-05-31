package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/labstack/echo/v5"

	"pptter"
	"pptter/internal/relay"
)

const defaultAddr = ":8080"

func main() {
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

	e.Pre(stripIdentifyingHeaders)

	hub := relay.NewHub(relay.NewConfig())
	indexHTML, err := fs.ReadFile(pptter.WebFS(), "web/index.html")
	if err != nil {
		os.Exit(1)
	}
	serveIndex := func(c *echo.Context) error {
		return c.Blob(http.StatusOK, "text/html; charset=utf-8", indexHTML)
	}

	// 健康检查不暴露运行细节，只返回 204。
	e.GET("/healthz", func(c *echo.Context) error {
		return c.NoContent(http.StatusNoContent)
	})

	// 前端只从本机静态目录加载资源，不引用任何第三方 CDN。
	e.StaticFS("/static", echo.MustSubFS(pptter.WebFS(), "web/static"))
	// 单页应用：房间号放在前端 URL hash（#room）里，纯客户端处理，
	// 服务端无需任何 /r/:room 路由重写。
	e.GET("/", serveIndex)
	e.GET("/index.html", serveIndex)

	// 匿名房间入口：房间名只作为内存 map 的 key，不落盘。
	e.GET("/ws/:room", hub.HandleWebSocket)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	startConfig := echo.StartConfig{
		Address:         listenAddr(),
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

func listenAddr() string {
	addr := strings.TrimSpace(os.Getenv("ADDR"))
	if addr == "" {
		return defaultAddr
	}
	return addr
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
		response.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), interest-cohort=()")
		response.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self' ws: wss:; img-src 'self' data:; font-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")

		return next(c)
	}
}
