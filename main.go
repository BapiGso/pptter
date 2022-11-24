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
	"text/template"
)

//go:embed assets
var assets embed.FS

var (
	port, roomname string
	temp, _        = template.ParseFS(assets, "assets/*.html")
)

func welcome() {
	flag.StringVar(&port, "p", "8443", "运行端口，默认8443")
	flag.StringVar(&roomname, "n", "PPTTER", "聊天室名，默认PPTTER")
	flag.Parse()
	go fmt.Printf("Starting server at https://localhost:%v\n ", port)
	go fmt.Scan()
}

func main() {
	//welcome()
	//router := httprouter.New()
	//router.ServeFiles("/embed/*filepath", http.FS(assets))
	////router.GET("/assets/*filepath", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	////	http.ServeFile(w, r, r.URL.Path[1:])
	////})
	//router.GET("/", Loginget)
	//router.POST("/", Loginpost)
	//router.GET("/ws", handleConnections)
	//go handleMessages()
	//go log.Fatal(http.ListenAndServeTLS(":"+port, "crt.crt", "key.key", router))
	mux := http.NewServeMux()
	mux.HandleFunc("/", index1)
	mux.HandleFunc("/ws", handleConnections)
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
	certManager := autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Cache:      autocert.DirCache("certs"),
		HostPolicy: autocert.HostWhitelist("example.com"),
	}

	server := &http.Server{
		Addr:    ":443",
		Handler: mux,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
		},
	}

	go http.ListenAndServe(":8081", mux) //certManager.HTTPHandler(nil))
	server.ListenAndServeTLS("", "")
}

func index1(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.Error(w, "404", 404)
		return
	}
	if r.Method == "POST" {
		reqbody, _ := io.ReadAll(r.Body)
		http.SetCookie(w, &http.Cookie{Name: string(reqbody[:4]), Value: string(reqbody[5:])})
		http.Redirect(w, r, "/", 302)
	}
	a, err := r.Cookie("name")
	if err != nil {
		temp.ExecuteTemplate(w, "login.html", a)
	} else {
		temp.ExecuteTemplate(w, "ceshi.html", nil)
	}
}
