package main

import (
	"embed"
	_ "embed"
	"fmt"
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
	mux.HandleFunc("/", index)
	mux.HandleFunc("/ws", handleConnections)
	mux.HandleFunc("/test", test)
	mux.Handle("/.tmp/", http.StripPrefix("/.tmp/", http.FileServer(http.Dir(".tmp"))))
	mux.Handle("/assets/", http.FileServer(http.FS(assets)))
	//certManager := autocert.Manager{
	//	Prompt:     autocert.AcceptTOS,
	//	Cache:      autocert.DirCache("certs"),
	//	HostPolicy: autocert.HostWhitelist("example.com"),
	//}
	//
	//server := &http.Server{
	//	Addr:    ":4480",
	//	Handler: mux,
	//	TLSConfig: &tls.Config{
	//		GetCertificate: certManager.GetCertificate,
	//	},
	//}

	go http.ListenAndServe(":8080", mux) //certManager.HTTPHandler(nil))
	//server.ListenAndServeTLS("", "")
}

func test(w http.ResponseWriter, r *http.Request) {
	//keys, _ := r.URL.Query()["key"]
	//if string(keys[0]) == "l" {
	//	fmt.Println(len(pptter.GroupDb))
	//} else if string(keys[0]) == "q" {
	//	fmt.Println(<-pptter.GroupDb)
	//}
	//fmt.Println(len(pptter.GroupDb))
	//if len(pptter.GroupDb) != 0 {
	//	for elem := range pptter.GroupDb {
	//		fmt.Println(elem.Name, 123)
	//	}
	//}

	//fmt.Println(&test2, &pptter.GroupDb)
	//close(test2)
	temp.ExecuteTemplate(w, "test.html", pptter)
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
		temp.ExecuteTemplate(w, "ceshi.html", pptter)
	}
}
