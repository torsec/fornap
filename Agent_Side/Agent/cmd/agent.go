package cmd

import (
	a "agent/cmd/Attester"
	e "agent/cmd/Register"
	"fmt"
)

func Register(print bool, verbose bool) (er error) {
	result := e.Register(print, verbose)
	if result != 0 {
		return fmt.Errorf("Endorser error")
	}
	return nil
}

func Attest(verbose bool) (er error) {
	result := a.Attest(verbose)
	if result != 0 {
		return fmt.Errorf("Attester error")
	}
	return nil
}
