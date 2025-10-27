package app

import (
	"fmt"
	"io"
	"time"

	"github.com/kevholditch/tls/internal/app/testutil"
	"github.com/kevholditch/tls/internal/app/util"
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

func (a *App) Run(args ...string) error {

	switch args[0] {
	case "read":
		{
			host, err := util.GetAddress(args[1], 443)
			if err != nil {
				return err
			}
			c, err := Read(host)
			if err != nil {
				return err
			}
			return Print(c, a.Out, time.Now())
		}
	case "print":
		{
			cert := testutil.NewCertBuilder().WithDefault().BuildCert()
			err := Print(cert, a.Out, time.Now())
			if err != nil {
				return err
			}
			return nil

		}
	}

	return fmt.Errorf("unknown command: %s", args[0])

}
