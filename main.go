package main

import (
	"flag"
	"fmt"
	"monitor-blocker/app"
	"monitor-blocker/config"
	"os"
)

var (
	configPathParam string
)

func init() {
	flag.StringVar(&configPathParam, "config", "", "required: config path")
	flag.Parse()
}

func main() {
	err := config.Load(configPathParam)
	if err != nil {
		finishAsFailed(err)
	}
	err = app.Start()
	if err != nil {
		finishAsFailed(err)
	}
}

func finishAsFailed(err error) {
	fmt.Println(err)
	os.Exit(1)
}
