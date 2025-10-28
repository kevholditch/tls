package main

import (
	"fmt"
	"os"

	"github.com/kevholditch/tls/internal/app"
)

func main() {
	application := app.NewApp(os.Stdin, os.Stdout, os.Stderr)
	err := application.Run(os.Args[1:]...)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
