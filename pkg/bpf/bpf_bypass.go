package bpf

// // #cgo pkg-config: bpf api-v2-c
// // #include "kmesh/include/kmesh_common.h"
import "C"
import (
	"os"
	"reflect"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"kmesh.net/kmesh/bpf/kmesh/bpf2go"
)

type BpfBypass struct {
	Info BpfInfo
	Link link.Link
	bpf2go.KmeshByPassObjects
}

var ObjBypass BpfBypass

func (sc *BpfBypass) NewBpf(cfg *Config) error {
	sc.Info.Config = *cfg
	sc.Info.MapPath = sc.Info.BpfFsPath + "bpf_bypass/map/"
	sc.Info.BpfFsPath += "/bpf_bypass/"

	if err := os.MkdirAll(sc.Info.MapPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	if err := os.MkdirAll(sc.Info.BpfFsPath,
		syscall.S_IRUSR|syscall.S_IWUSR|syscall.S_IXUSR|
			syscall.S_IRGRP|syscall.S_IXGRP); err != nil && !os.IsExist(err) {
		return err
	}

	return nil
}

func (sc *BpfBypass) loadKmeshByPassObjects() (*ebpf.CollectionSpec, error) {
	var (
		err  error
		spec *ebpf.CollectionSpec
		opts ebpf.CollectionOptions
	)
	opts.Maps.PinPath = sc.Info.MapPath
	opts.Programs.LogSize = sc.Info.BpfVerifyLogSize

	spec, err = bpf2go.LoadKmeshByPass()

	if err != nil || spec == nil {
		return nil, err
	}

	setMapPinType(spec, ebpf.PinByName)
	if err = spec.LoadAndAssign(&sc.KmeshByPassObjects, &opts); err != nil {
		return nil, err
	}

	value := reflect.ValueOf(sc.KmeshByPassObjects.KmeshByPassPrograms)
	if err = pinPrograms(&value, sc.Info.BpfFsPath); err != nil {
		return nil, err
	}

	return spec, nil
}

func (sc *BpfBypass) LoadBypass() error {
	/* load kmesh sockops main bpf prog */
	spec, err := sc.loadKmeshByPassObjects()
	if err != nil {
		return err
	}

	prog := spec.Programs["bypass_prog"]
	sc.Info.Type = prog.Type
	sc.Info.AttachType = prog.AttachType

	return nil
}

func (sc *BpfBypass) close() error {
	if err := sc.KmeshByPassObjects.Close(); err != nil {
		return err
	}
	return nil
}

func (sc *BpfBypass) Attach() error {
	cgopt := link.CgroupOptions{
		Path:    sc.Info.Cgroup2Path,
		Attach:  sc.Info.AttachType,
		Program: sc.KmeshByPassObjects.Bypass,
	}

	lk, err := link.AttachCgroup(cgopt)
	if err != nil {
		return err
	}
	sc.Link = lk

	return nil
}

func (sc *BpfBypass) Detach() error {
	var value reflect.Value

	if err := sc.close(); err != nil {
		return err
	}

	value = reflect.ValueOf(sc.KmeshByPassObjects.KmeshByPassPrograms)
	if err := unpinPrograms(&value); err != nil {
		return err
	}
	value = reflect.ValueOf(sc.KmeshByPassObjects.KmeshByPassMaps)
	if err := unpinMaps(&value); err != nil {
		return err
	}

	if err := os.RemoveAll(sc.Info.BpfFsPath); err != nil && !os.IsNotExist(err) {
		return err
	}

	if sc.Link != nil {
		return sc.Link.Close()
	}
	return nil
}
