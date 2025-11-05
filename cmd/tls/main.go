package main

import (
	"fmt"
	"os"

	"github.com/kevholditch/tls/internal/cmd"
)

func main() {
	err := cmd.Run(os.Stdout, os.Stderr, os.Args[1:])
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
