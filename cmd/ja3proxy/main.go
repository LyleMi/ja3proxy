package main

import (
	cflog "github.com/cloudflare/cfssl/log"
)

func init() {
	cflog.Level = cflog.LevelWarning
}

func main() {
	newDefaultApp().run()
}
