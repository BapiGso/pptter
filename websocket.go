package main

import (
	"github.com/gorilla/websocket"
	"log"
	"net/http"
	"net/url"
)

// var broadcast = make(chan string)
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// 解决跨域问题
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

func handleConnections(w http.ResponseWriter, r *http.Request) {
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("ws连接出错:", err)
	}
	defer ws.Close()
	pptter.GroupUser[ws] = true

	name, err := r.Cookie("name")
	if err != nil {
		log.Println("读取cookie出错", err)
	}
	namedecode, _ := url.QueryUnescape(name.Value)

	//读消息
	go func() {
		for {
			//接受数据
			messtype, message, err := ws.ReadMessage()
			if err != nil {
				log.Println("读取ws消息出错:", err)
				delete(pptter.GroupUser, ws)
				break
			}

			switch messtype {
			case websocket.TextMessage:
				pptter.crudtext(message)
			case websocket.BinaryMessage:
				pptter.crudbin(message, namedecode)
			case websocket.CloseMessage:
			case websocket.PingMessage:
			case websocket.PongMessage:
			}
			//msg, _ := json.Marshal(crud(message))
			////处理好的消息添加到go channal
			//broadcast <- string(msg)
		}
	}()
	//发消息
	for {
		msg := <-pptter.SendMessage
		for client := range pptter.GroupUser {
			err := client.WriteMessage(websocket.TextMessage, []byte(msg))
			if err != nil {
				log.Printf("client.WriteJSON error: %v", err)
				client.Close()
				delete(pptter.GroupUser, client)
			}
		}
	}
}
