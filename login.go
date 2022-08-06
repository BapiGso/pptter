package main

import (
	"crypto/sha1"
	"encoding/hex"
	"github.com/gorilla/sessions"
	"github.com/julienschmidt/httprouter"
	"log"
	"net/http"
	"os"
	"strconv"
	"text/template"
)

// 初始化存储器（基于 Cookie）
var store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_KEY)")))

//计算密码的sha1值
func hash(passwd string) string {
	h := sha1.New() // md5加密类似md5.New()
	//写入要处理的字节。如果是一个字符串，需要使用[]byte(s) 来强制转换成字节数组。
	h.Write([]byte(passwd))
	passwdhash := h.Sum(nil)
	h.Reset()
	passwdhash16 := hex.EncodeToString(passwdhash) //转16进制
	return passwdhash16
}

func index(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	session, _ := store.Get(r, "GOSESSID")
	username, _ := session.Values["name"].(string)
	indexhtml, _ := template.ParseFS(assets, "assets/qianduan.html")
	indexhtml.Execute(w, map[string]interface{}{
		"db":       teledb,
		"roomname": roomname,
		"username": username,
		"online":   strconv.Itoa(online),
	})
}

func Loginget(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	welcome, _ := template.ParseFS(assets, "assets/login.html")
	session, _ := store.Get(r, "GOSESSID")
	//有名字进入聊天室，没有就写名字
	if session.Values["name"] != nil {
		index(w, r, ps)
	} else {
		welcome.Execute(w, nil)
	}
}

func Loginpost(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	session, _ := store.Get(r, "GOSESSID")
	session.Values["name"] = r.PostFormValue("name")
	err := session.Save(r, w)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		log.Println("写入session出错:", err)
	}
	//输了名字跳GET
	http.Redirect(w, r, "/", 302)
}
