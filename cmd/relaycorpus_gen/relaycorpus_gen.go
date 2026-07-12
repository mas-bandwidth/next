package main

// Writes the relay conformance corpus to a file for the C differential drivers.
// Usage: relaycorpus_gen <output-path> [seed]
// The target config is fixed here so the C driver knows how to build frames:
// packet source 10.0.0.1, relay address 127.0.0.1. The magic is seed-derived and
// embedded per-entry in the file, so the driver reads it rather than hardcoding it.

import (
	"fmt"
	"os"
	"strconv"

	"github.com/networknext/next/modules/relaycorpus"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: relaycorpus_gen <output-path> [seed]")
		os.Exit(1)
	}
	seed := int64(1)
	if len(os.Args) >= 3 {
		s, err := strconv.ParseInt(os.Args[2], 10, 64)
		if err != nil {
			fmt.Fprintf(os.Stderr, "bad seed: %v\n", err)
			os.Exit(1)
		}
		seed = s
	}

	cfg := relaycorpus.Config{
		From:  [4]byte{10, 0, 0, 1},
		To:    [4]byte{127, 0, 0, 1},
		Magic: relaycorpus.DefaultConfig(seed).Magic,
	}

	entries := relaycorpus.Generate(seed, cfg)
	if err := os.WriteFile(os.Args[1], relaycorpus.Marshal(entries), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d corpus entries to %s\n", len(entries), os.Args[1])
}
