package main

import (
	"crypto/sha1"
	"encoding/hex"
)

// 计算密码的sha1值
func hash(passwd string) string {
	h := sha1.New() // md5加密类似md5.New()
	//写入要处理的字节。如果是一个字符串，需要使用[]byte(s) 来强制转换成字节数组。
	h.Write([]byte(passwd))
	passwdhash := h.Sum(nil)
	h.Reset()
	passwdhash16 := hex.EncodeToString(passwdhash) //转16进制
	return passwdhash16
}
