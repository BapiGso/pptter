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
	GroupName:   "HD9990",
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
	Writelock   sync.Mutex
}

type Message struct {
	Name     string
	Time     int64
	Say      string
	FileName string
	Filetype string
}

func (m *Message) Name2avatar() string {
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
			res = MergeString(tempStr, unit[i]) //此处调用了一个我自己封装的字符串拼接的函数（你也可以自己实现）
		}
		break //我想要的形式是精确到最大单位，即："2天前"这种形式，如果想要"2天12小时36分钟48秒前"这种形式，把此处break去掉，然后把字符串拼接调整下即可（别问我怎么调整，这如果都不会我也是无语）
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

func (t PPTTER) Usercount() int {
	return len(t.GroupUser)
}

// 字符串校验，用于生成头像
func crcname(s []byte) uint32 {
	v := crc32.ChecksumIEEE(s)
	return v
}

/**
* @des 拼接字符串
* @param args ...string 要被拼接的字符串序列
* @return string
 */
func MergeString(args ...string) string {
	buffer := bytes.Buffer{}
	for i := 0; i < len(args); i++ {
		buffer.WriteString(args[i])
	}
	return buffer.String()
}
