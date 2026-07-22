package cmd

import (
	"fmt"
	r "verifier/cmd/Register"
	v "verifier/cmd/Verify"
)

func Register(verbose bool) (er error) {
	result := r.Register(verbose)
	if result != 0 {
		return fmt.Errorf("Register error")
	}
	return nil
}

func Verifier(verbose bool) (er error) {
	result := v.Verify(verbose)
	if result != 0 {
		return fmt.Errorf("Verifier error")
	}
	return nil
}
