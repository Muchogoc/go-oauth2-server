package html

import (
	"embed"
	"io"
	"text/template"
)

//go:embed *
var files embed.FS

func parse(file string) *template.Template {
	return template.Must(
		template.New("layout.html").ParseFS(files, "layout.html", file))
}

type LoginParams struct {
	Title           string
	RequestedScopes []string
}

func Login(w io.Writer, p LoginParams) error {
	template := parse("login.html")
	return template.Execute(w, p)
}
