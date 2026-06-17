package main

import (
	"log"

	cflog "github.com/cloudflare/cfssl/log"
)

func init() {
	cflog.Level = cflog.LevelWarning
}

func main() {
	if err := newDefaultApp().run(); err != nil {
		log.Fatal(err)
	}
}
