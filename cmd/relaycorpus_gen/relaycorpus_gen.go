package main

// Writes the relay conformance corpus to a file for the C differential drivers.
// Usage: relaycorpus_gen <output-path> [seed]
// The world (relay config, keys, magic, and the relay/whitelist/session map contents
// every entry runs against) is serialized into the file ahead of the entries, so the
// C driver loads it into the relay's maps rather than hardcoding anything. All of it
// is seed-derived and reproducible. See modules/relaycorpus.

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

	world := relaycorpus.DefaultWorld(seed)
	entries := relaycorpus.Generate(seed, world)
	if err := os.WriteFile(os.Args[1], relaycorpus.Marshal(world, entries), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "write failed: %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %d corpus entries to %s\n", len(entries), os.Args[1])
}
