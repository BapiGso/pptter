package main

import (
	"embed"
	_ "embed"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
)

//go:embed assets
var assets embed.FS

var port, roomname string

func welcome() {
	fmt.Print("请输入运行端口:")
	fmt.Scanln(&port)
	fmt.Print("请输入聊天室名称:")
	fmt.Scanln(&roomname)
	go fmt.Println("Starting server at port " + port)
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
