package pptter

import (
	"embed"
	"io/fs"
)

//go:embed all:web
var webFS embed.FS

func WebFS() fs.FS {
	return webFS
}
