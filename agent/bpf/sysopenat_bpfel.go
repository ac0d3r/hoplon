// Code generated by bpf2go; DO NOT EDIT.
//go:build 386 || amd64 || amd64p32 || arm || arm64 || mips64le || mips64p32le || mipsle || ppc64le || riscv64
// +build 386 amd64 amd64p32 arm arm64 mips64le mips64p32le mipsle ppc64le riscv64

package bpf

import (
	"bytes"
	_ "embed"
	"fmt"
	"io"

	"github.com/cilium/ebpf"
)

// loadSysOpenat returns the embedded CollectionSpec for sysOpenat.
func loadSysOpenat() (*ebpf.CollectionSpec, error) {
	reader := bytes.NewReader(_SysOpenatBytes)
	spec, err := ebpf.LoadCollectionSpecFromReader(reader)
	if err != nil {
		return nil, fmt.Errorf("can't load sysOpenat: %w", err)
	}

	return spec, err
}

// loadSysOpenatObjects loads sysOpenat and converts it into a struct.
//
// The following types are suitable as obj argument:
//
//     *sysOpenatObjects
//     *sysOpenatPrograms
//     *sysOpenatMaps
//
// See ebpf.CollectionSpec.LoadAndAssign documentation for details.
func loadSysOpenatObjects(obj interface{}, opts *ebpf.CollectionOptions) error {
	spec, err := loadSysOpenat()
	if err != nil {
		return err
	}

	return spec.LoadAndAssign(obj, opts)
}

// sysOpenatSpecs contains maps and programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sysOpenatSpecs struct {
	sysOpenatProgramSpecs
	sysOpenatMapSpecs
}

// sysOpenatSpecs contains programs before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sysOpenatProgramSpecs struct {
	EnterOpenat *ebpf.ProgramSpec `ebpf:"enter_openat"`
}

// sysOpenatMapSpecs contains maps before they are loaded into the kernel.
//
// It can be passed ebpf.CollectionSpec.Assign.
type sysOpenatMapSpecs struct {
	Events *ebpf.MapSpec `ebpf:"events"`
}

// sysOpenatObjects contains all objects after they have been loaded into the kernel.
//
// It can be passed to loadSysOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type sysOpenatObjects struct {
	sysOpenatPrograms
	sysOpenatMaps
}

func (o *sysOpenatObjects) Close() error {
	return _SysOpenatClose(
		&o.sysOpenatPrograms,
		&o.sysOpenatMaps,
	)
}

// sysOpenatMaps contains all maps after they have been loaded into the kernel.
//
// It can be passed to loadSysOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type sysOpenatMaps struct {
	Events *ebpf.Map `ebpf:"events"`
}

func (m *sysOpenatMaps) Close() error {
	return _SysOpenatClose(
		m.Events,
	)
}

// sysOpenatPrograms contains all programs after they have been loaded into the kernel.
//
// It can be passed to loadSysOpenatObjects or ebpf.CollectionSpec.LoadAndAssign.
type sysOpenatPrograms struct {
	EnterOpenat *ebpf.Program `ebpf:"enter_openat"`
}

func (p *sysOpenatPrograms) Close() error {
	return _SysOpenatClose(
		p.EnterOpenat,
	)
}

func _SysOpenatClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

// Do not access this directly.
//go:embed sysopenat_bpfel.o
var _SysOpenatBytes []byte
