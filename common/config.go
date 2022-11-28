package config

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
)

var (
	_, b, _, _ = runtime.Caller(0)
	Root       = filepath.Join(filepath.Dir(b), "../../..")
)

var Config config

type WEBINFO struct {
	Logtype  string `yaml:"logtype"`
	Loglevel string `yaml:"loglevel"`    //日志级别
	WebPort  string `yaml:"web_port"`    //web端口
	SslPort  string `yaml:"sslweb_port"` //sslweb端口
	SslCert  string `yaml:"ssl_cert"`    //ssl配置cert
	SslKey   string `yaml:"ssl_key"`     //ssl配置key
	Domain   string `yaml:"domain"`
}

type config struct {
	WEBINFO WEBINFO `yaml:"web"`
}

func unmarshalConfig(config interface{}, configName string) {
	var env string
	if configName == "config.yaml" {
		env = "CONFIG_NAME"
	}
	cfgName := os.Getenv(env)
	if len(cfgName) != 0 {
		bytes, err := ioutil.ReadFile(filepath.Join(cfgName, "config", configName))
		if err != nil {
			bytes, err = ioutil.ReadFile(filepath.Join(Root, "config", configName))
			if err != nil {
				panic(err.Error() + " config: " + filepath.Join(cfgName, "config", configName))
			}
		} else {
			Root = cfgName
		}
		if err = yaml.Unmarshal(bytes, config); err != nil {
			panic(err.Error())
		}
	} else {
		bytes, err := ioutil.ReadFile(fmt.Sprintf("config/%s", configName))
		if err != nil {
			panic(err.Error())
		}
		if err = yaml.Unmarshal(bytes, config); err != nil {
			panic(err.Error())
		}
	}
}

func init() {
	unmarshalConfig(&Config, "config.yaml")
}
