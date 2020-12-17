package main

import (
	"context"
	"os"

	"github.com/JulienBalestra/dry/pkg/exit"
	"github.com/JulienBalestra/wireguard-stun/cmd"
)

func main() {
	root := cmd.NewRootCommand(context.TODO())
	err := root.Execute()
	os.Exit(exit.Exit(err))
}
