# PPTTER

> 一个Golang开发的简易聊天室

## 预览及demo
![预览](https://github.com/BapiGso/pptter/blob/main/assets/QQ%E6%88%AA%E5%9B%BE20221127090457.webp)
[demo](https://pptter.onrender.com/)

## 安装

请到[releases](https://github.com/BapiGso/pptter/releases)界面下载对应平台的二进制文件

| 参数    | 默认值 | 备注                                        |
|-------|-----|-------------------------------------------|
| -d    | ""  | 绑定域名，用于自动申请ssl证书，该参数会强制占用80和443端口,与下面参数互斥 |
| -p    | 80  | 运行端口，默认80                                 |
| -tlsp |     | tls运行端口，默认不开启                             |
| -tlsc | ""  | tls证书路径                                   |
| -tlsk | ""  | tls密钥路径                                   |  

示例  

```
  ./pptter -d example.com
  ./pptter -p 8080 -tlsp 8443 -tlsc fullchain.pem -tlsk privkey.pem
```

## 开发

 - 使用text/template解析html模板
 - 使用chan队列存储数据，无需数据库
 - 使用WebSocket协议通讯
 - 使用embed打包静态文件
 - 前端来自于[fiora](https://github.com/yinxin630/fiora)

## 关于作者

[smoe](https://smoe.cc)

## License

这个项目 MIT 协议， 请点击 [LICENSE](LICENSE) 了解更多细节。

## 名字由来？

可能来源于苦瓜青椒汤的英译组合

## TODO
 - 手机端适配
 - 灯箱
 - 音效提醒
 - PWA
 - 配色