package main

import (
	"crypto/tls"
	"embed"
	_ "embed"
	"flag"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"io"
	"log"
	"net/http"
	"os"
	"text/template"
)

//go:embed assets
var assets embed.FS
var temp, _ = template.ParseFS(assets, "assets/*.html")

func init() {
	if _, ok := os.Stat(".tmp"); ok == nil {
		err := os.RemoveAll(".tmp")
		if err != nil {
			fmt.Println("删除缓存文件夹出错，请检查程序权限", err)
		}
		err = os.Mkdir(".tmp", os.ModePerm)
		if err != nil {
			fmt.Println("创建缓存文件夹出错，请检查程序权限", err)
		}
	} else {
		err := os.Mkdir(".tmp", os.ModePerm)
		if err != nil {
			fmt.Println("创建缓存文件夹出错，请检查程序权限", err)
		}
	}

}

func main() {
	domain := flag.String("d", "", "绑定域名，用于自动申请ssl证书，该参数会强制占用80和443端口")
	port := flag.String("p", "80", "运行端口，默认80")
	sslport := flag.String("tlsp", "", "tls运行端口，默认不开启")
	sslcer := flag.String("tlsc", "", "tls证书路径")
	sslkey := flag.String("tlsk", "", "tls密钥路径")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/ws", handleConnections)
	mux.Handle("/.tmp/", http.StripPrefix("/.tmp/", http.FileServer(http.Dir(".tmp"))))
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/sw.js", func(w http.ResponseWriter, r *http.Request) {
		file, _ := assets.ReadFile("assets/js/sw.js")
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		//goland:noinspection GoUnhandledErrorResult
		w.Write(file)
	})
	if *domain != "" {
		certManager := autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			Cache:      autocert.DirCache("certs"),
			HostPolicy: autocert.HostWhitelist("example.com", *domain),
		}
		server := &http.Server{
			Addr:    ":443",
			Handler: mux,
			TLSConfig: &tls.Config{
				GetCertificate: certManager.GetCertificate,
			},
		}
		go log.Fatal(http.ListenAndServe(":80", certManager.HTTPHandler(nil)))
		log.Fatal(server.ListenAndServeTLS("", ""))
	}
	if *sslport != "" {
		log.Fatal(http.ListenAndServeTLS(":"+*sslport, *sslcer, *sslkey, mux))
	}
	log.Fatal(http.ListenAndServe(":"+*port, mux))
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFoundHandler()
		return
	}
	if r.Method == "POST" {
		reqbody, _ := io.ReadAll(r.Body)
		http.SetCookie(w, &http.Cookie{Name: string(reqbody[:4]), Value: string(reqbody[5:])})
		http.Redirect(w, r, "/", 302)
	}
	if _, err := r.Cookie("name"); err != nil {
		temp.ExecuteTemplate(w, "login.html", nil)
	} else {
		temp.ExecuteTemplate(w, "index.html", pptter)
	}
}

//TODO 按钮功能 发命令 灯箱bug
