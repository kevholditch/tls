package app

import (
	"fmt"
	"io"
	"time"
)

type App struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer
}

func NewApp(in io.Reader, out, err io.Writer) *App {
	return &App{
		In:  in,
		Out: out,
		Err: err,
	}
}

func (a *App) Run(args []string) error {

	switch args[0] {
	case "read":
		{
			c, err := Read(args[1])
			if err != nil {
				return err
			}
			return Print(a.Out, c, time.Now())
		}
	}

	return fmt.Errorf("unknown command: %s", args[0])

}
