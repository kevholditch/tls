package main

import (
	"fmt"
	"os"

	"github.com/kevholditch/tls/internal/app"
)

func main() {
	err := app.Run(os.Stdout, os.Stderr, os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
