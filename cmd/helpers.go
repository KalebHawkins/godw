package cmd

import (
	"fmt"
	"os"
)

func handleErr(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
	}
}
