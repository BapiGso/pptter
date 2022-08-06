package main

import (
	"encoding/json"
	"github.com/gorilla/websocket"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
)

var clients = make(map[*websocket.Conn]bool)
var broadcast = make(chan string)
var online = 0
var upgrader = websocket.Upgrader{
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
	// 解决跨域问题
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
}

//弃用
func socketHandler(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	// Upgrade our raw HTTP connection to a websocket based one
	conn, err := upgrader.Upgrade(w, r, nil)

	if err != nil {
		log.Print("ws连接出错:", err)
		return
	}
	defer conn.Close()

	// The event loop
	for {
		messageType, message, err := conn.ReadMessage()
		if err != nil {
			log.Println("读取ws消息出错:", err)
			break
		}
		//聊天消息处理
		crud(message)

		//log.Printf("Received: %s", message)
		err = conn.WriteMessage(messageType, message)
		if err != nil {
			log.Println("回传消息出错:", err)
			break
		}
	}
}

func handleConnections(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {

	ws, err := upgrader.Upgrade(w, r, nil)
	online++
	if err != nil {
		log.Print("ws连接出错:", err)
	}
	defer ws.Close()

	clients[ws] = true

	//不断的从页面上获取数据 然后广播发送出去
	for {
		//接受数据
		_, message, err := ws.ReadMessage()
		if err != nil {
			log.Println("读取ws消息出错:", err)
			delete(clients, ws)
			online--
			break
		}
		//聊天消息处理
		msg, _ := json.Marshal(crud(message))
		//处理好的消息添加到go channal
		broadcast <- string(msg)
	}
}

//广播发送至页面
func handleMessages() {
	for {
		msg := <-broadcast
		for client := range clients {
			err := client.WriteMessage(1, []byte(msg))
			if err != nil {
				log.Printf("client.WriteJSON error: %v", err)
				client.Close()
				delete(clients, client)
			}
		}
	}
}
