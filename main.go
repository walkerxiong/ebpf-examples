package main

import (
	"log"

	"github.com/walkerxiong/ebpf-examples/cmd"
	"golang.org/x/sys/unix"
)

func main() {
	if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}); err != nil {
		log.Fatalf("failed to set terpory memory: %v", err)
	}
	if err := cmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
