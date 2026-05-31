package webfs

import (
	"embed"
	"io/fs"
)

//go:embed index.html static
var content embed.FS

func FS() fs.FS {
	return content
}
