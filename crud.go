package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/gorilla/websocket"
	"hash/crc32"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

var pptter = PPTTER{
	GroupNum:    1,
	GroupName:   "pptter",
	GroupUser:   make(map[*websocket.Conn]bool),
	GroupDb:     make(chan Message, 50),
	SendMessage: make(chan []byte),
}

type PPTTER struct {
	GroupNum    int
	GroupName   string
	GroupUser   map[*websocket.Conn]bool
	GroupDb     chan Message
	SendMessage chan []byte
	Writelock   sync.Mutex //锁我可能没用对，反正也没啥后果
}

type Message struct {
	Name     string
	Time     int64
	Say      string
	FileName string
	Filetype string
}

func (m Message) Name2avatar() string {
	//服了golang这个老六了，uint32逸出和前端半天对不上
	v := crc32.ChecksumIEEE([]byte(m.Name))
	return strconv.Itoa(int(v))[:2]
}

func (m Message) Timestr() string {
	//tm := time.Unix(m.Time, 0)
	//return tm.Format("01-02 15:04")
	var byTime = []int64{365 * 24 * 60 * 60, 24 * 60 * 60, 60 * 60, 60, 1}
	var unit = []string{"年前", "天前", "小时前", "分钟前", "秒钟前"}
	now := time.Now().Unix()
	ct := now - m.Time
	if ct < 0 {
		return "刚刚"
	}
	var res string
	for i := 0; i < len(byTime); i++ {
		if ct < byTime[i] {
			continue
		}
		var temp = math.Floor(float64(ct / byTime[i]))
		ct = ct % byTime[i]
		if temp > 0 {
			var tempStr string
			tempStr = strconv.FormatFloat(temp, 'f', -1, 64)
			res = MergeString(tempStr, unit[i])
		}
		break
	}
	return res
}

func (m Message) Filetypecut() string {
	cut := strings.Split(m.Filetype, "/")
	return cut[0]
}

func (t *PPTTER) crudtext(message []byte) {
	m := Message{}
	err := json.Unmarshal(message, &m)
	if err != nil {
		fmt.Println("Convert json message failed:", err)
		return
	}

	if len(t.GroupDb) == 50 {
		del := <-t.GroupDb
		os.Remove(".tmp/" + del.FileName)
	}
	t.GroupDb <- m
	mbyte, _ := json.Marshal(m)
	t.SendMessage <- mbyte
}

func (t *PPTTER) crudbin(message []byte, name string) {
	filename := strconv.Itoa(int(crcname(message)))
	m := Message{
		Name:     name,
		Time:     time.Now().Unix(),
		Say:      "",
		FileName: filename,
		Filetype: http.DetectContentType(message),
	}
	err := os.WriteFile(".tmp/"+filename, message, os.ModePerm)
	if err != nil {
		fmt.Println(err)
	}
	if len(t.GroupDb) == 50 {
		del := <-t.GroupDb
		os.Remove(".tmp/" + del.FileName)
	}
	t.GroupDb <- m
	mbyte, _ := json.Marshal(m)
	t.SendMessage <- mbyte
}

func (t PPTTER) Gettmp() []Message {
	tmp := make([]Message, 0, 50)
	t.Writelock.TryLock()
	for i := 0; i < len(t.GroupDb); i++ {
		v := <-t.GroupDb
		tmp = append(tmp, v)
		t.GroupDb <- v
	}
	t.Writelock.Unlock()
	return tmp
}

// 在线人数
func (t PPTTER) Usercount() int {
	return len(t.GroupUser)
}

// 字符串校验，用于生成头像
func crcname(s []byte) uint32 {
	v := crc32.ChecksumIEEE(s)
	return v
}

// 字符串拼接
func MergeString(args ...string) string {
	buffer := bytes.Buffer{}
	for i := 0; i < len(args); i++ {
		buffer.WriteString(args[i])
	}
	return buffer.String()
}
