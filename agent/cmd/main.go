//go:build linux
// +build linux

package main

import (
	"context"
	"flag"
	"fmt"
	"hoplon/agent/bpf"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

var (
	pid = flag.Int("pid", 0, "Process ID to be protected")
)

func main() {
	flag.Parse()

	if *pid == 0 {
		// TODO
		// log.Fatalln("A PID must be selected")
	}

	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	var wg sync.WaitGroup

	handler := func(data bpf.OpenAtEventData) {
		procPath := fmt.Sprintf("/proc/%d", pid)
		filename := unix.ByteSliceToString(data.FileName[:])

		fmt.Printf("[INFO] uid: %d, pid: %d, filename: %s, Comm: %s\n", data.Uid, data.Pid, filename, unix.ByteSliceToString(data.Comm[:]))

		if strings.HasPrefix(filename, procPath) {
			// TODO
			// unix.Kill(int(data.Pid), syscall.SIGKILL)
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
