package main

import (
	"crypto/tls"
	"embed"
	_ "embed"
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
	port, roomname string
	temp, _        = template.ParseFS(assets, "assets/*.html")
)

func init() {
	if _, ok := os.Stat(".tmp"); ok != nil {
		err := os.Mkdir(".tmp", os.ModePerm)
		if err != nil {
			fmt.Println("创建缓存文件夹出错，请检查程序权限", err)
		}
	}
}

func welcome() {
	//flag.StringVar(&port, "p", "8443", "运行端口，默认8443")
	//flag.StringVar(&roomname, "n", "PPTTER", "聊天室名，默认PPTTER")
	//flag.Parse()
	//go fmt.Printf("Starting server at https://localhost:%v\n ", port)
	//go fmt.Scan()
}

func main() {
	//welcome()
	go fmt.Scan()
	mux := http.NewServeMux()
	mux.HandleFunc("/", index)
	mux.HandleFunc("/ws", handleConnections)
	mux.Handle("/.tmp/", http.StripPrefix("/.tmp/", http.FileServer(http.Dir(".tmp"))))
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("certs"),
		HostPolicy: autocert.HostWhitelist("example.com"),
	}

	server := &http.Server{
		Addr:    ":4480",
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	go http.ListenAndServe(":8081", mux) //certManager.HTTPHandler(nil))
	server.ListenAndServeTLS("", "")
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
	_, err := r.Cookie("name")
	if err != nil {
		temp.ExecuteTemplate(w, "login.html", nil)
	} else {
		temp.ExecuteTemplate(w, "index.html", pptter)
	}
}
