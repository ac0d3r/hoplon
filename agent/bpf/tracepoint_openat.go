//go:build linux
// +build linux

package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang-12 sysOpenat ./src/tracepoint_openat.c -- -nostdinc -I headers/

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"log"
	"os"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"
)

type OpenAtEventData struct {
	Pid      uint32
	FileName [64]byte
	Comm     [64]byte
}

func TracepointOpentat(ctx context.Context, handler func(OpenAtEventData)) error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return err
	}

	objs := sysOpenatObjects{}
	if err := loadSysOpenatObjects(&objs, nil); err != nil {
		return err
	}
	defer objs.Close()

	tp, err := link.Tracepoint("syscalls", "sys_enter_openat", objs.EnterOpen)
	if err != nil {
		return err
	}
	defer tp.Close()

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		return err
	}
	defer rd.Close()

	var data OpenAtEventData
	log.Println("Waiting for events..")
LOOP:
	for {
		select {
		case <-ctx.Done():
			break LOOP
		default:
			record, err := rd.Read()
			if err != nil {
				if errors.Is(err, perf.ErrClosed) {
					break LOOP
				}
				log.Printf("reading from perf event reader: %s", err)
				continue
			}

			if record.LostSamples != 0 {
				log.Printf("perf event ring buffer full, dropped %d samples", record.LostSamples)
				continue
			}
			// Parse the perf event entry into an Event structure.
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &data); err != nil {
				log.Printf("parsing perf event: %s", err)
				continue
			}

			handler(data)
		}
	}
	return nil
}
