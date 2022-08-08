package main

import (
	"embed"
	_ "embed"
	"flag"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
)

//go:embed assets
var assets embed.FS

var port, roomname string

func welcome() {
	flag.StringVar(&port, "p", "8443", "运行端口，默认8443")
	flag.StringVar(&roomname, "n", "PPTTER", "聊天室名，默认PPTTER")
	flag.Parse()
	go fmt.Printf("Starting server at https://localhost:%v\n ", port)
	go fmt.Scan()
	//data, _ := assets.ReadFile("assets/key.key")
	//fmt.Println(string(data))
	//fmt.Println(123)
}

func main() {
	welcome()
	router := httprouter.New()
	router.ServeFiles("/embed/*filepath", http.FS(assets))
	//router.GET("/assets/*filepath", func(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	//	http.ServeFile(w, r, r.URL.Path[1:])
	//})
	router.GET("/", Loginget)
	router.POST("/", Loginpost)
	router.GET("/ws", handleConnections)
	go handleMessages()
	go log.Fatal(http.ListenAndServeTLS(":"+port, "crt.crt", "key.key", router))
}
