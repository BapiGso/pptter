package main

import (
	"encoding/json"
	"fmt"
	"hash/crc32"
	"html"
	"strconv"
	"time"
)

var teledb = make([]map[string]string, 50) //聊天的数据库

//字符串校验，用于生成头像
func crcname(s string) string {
	v := int(crc32.ChecksumIEEE([]byte(s)))
	sv := strconv.Itoa(v)[1:3]
	return sv
}

func crud(message []byte) map[string]string {
	tmp := make(map[string]string)
	err := json.Unmarshal(message, &tmp)
	if err != nil {
		fmt.Println("转json出错：", err)
		return nil
	}
	tmpslice := map[string]string{
		"name":     tmp["name"],
		"say":      html.EscapeString(tmp["say"]), //防止XSS
		"time":     time.Now().Format("01/02 15:04"),
		"portrait": crcname(tmp["name"]) + ".jpg", //随机一个头像数字
	}
	//删除第一个元素
	//fmt.Println(len(teledb))
	teledb = teledb[1:]
	//新的聊天插入到最后
	//fmt.Println(len(teledb))
	teledb = append(teledb, tmpslice)
	//fmt.Println(teledb)
	//返回最后一条消息
	return teledb[49]
}
