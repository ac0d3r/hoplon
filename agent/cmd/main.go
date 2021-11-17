//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"hoplon/agent/bpf"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
)

func main() {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	var wg sync.WaitGroup

	handler := func(data bpf.OpenAtEventData) {
		filename := string(data.FileName[:])
		if strings.HasPrefix(filename, "/proc/") {
			fmt.Printf("[INFO] pid: %d, filename: %s, Comm: %s\n", data.Pid, filename, string(data.Comm[:]))
		}
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := bpf.TracepointOpentat(ctx, handler); err != nil {
			log.Fatal(err)
		}
	}()
	<-c
	cancel()
	wg.Wait()
}
