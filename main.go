package main

import (
	"crypto/tls"
	"embed"
	_ "embed"
	"flag"
	"fmt"
	"golang.org/x/crypto/acme/autocert"
	"io"
	"net/http"
	"os"
	"text/template"
)

//go:embed assets
var assets embed.FS

var (
	temp, _ = template.ParseFS(assets, "assets/*.html")
)

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
	go fmt.Scan()
	domain := flag.String("domain", "", "绑定域名，用于申请ssl证书")
	usetls := flag.Bool("https", false, "该参数会自动申请证书并占用80和443端口")
	port := flag.String("port", "80", "运行端口，默认80")
	flag.Parse()
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/ws", handleConnections)
	mux.Handle("/.tmp/", http.StripPrefix("/.tmp/", http.FileServer(http.Dir(".tmp"))))
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
	mux.HandleFunc("/sw.js", func(w http.ResponseWriter, r *http.Request) {
		file, _ := assets.ReadFile("assets/js/sw.js")
		w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
		w.Write(file)
	})
	if *usetls {
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
		go http.ListenAndServe(":80", certManager.HTTPHandler(nil))
		server.ListenAndServeTLS("", "")
	} else {
		http.ListenAndServe(":"+*port, mux)
	}
}

func index(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404", 404)
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

//TODO 按钮功能 灯箱 发命令
