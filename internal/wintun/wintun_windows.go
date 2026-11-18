/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"log"
	"runtime"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type (
	Adapter struct {
		handle uintptr
	}
)

var (
	modwintun                         = newLazyDLL(dllFileName)
	procWintunCreateAdapter           = modwintun.NewProc("WintunCreateAdapter")
	procWintunOpenAdapter             = modwintun.NewProc("WintunOpenAdapter")
	procWintunCloseAdapter            = modwintun.NewProc("WintunCloseAdapter")
	procWintunDeleteDriver            = modwintun.NewProc("WintunDeleteDriver")
	procWintunGetAdapterLUID          = modwintun.NewProc("WintunGetAdapterLUID")
	procWintunGetRunningDriverVersion = modwintun.NewProc("WintunGetRunningDriverVersion")
)

func init() {
	modwintun.onLoad = setupLogger
}

// logMessage writes one of Wintun's own messages to the standard log with the
// time the driver gave it. The messages name steps (driver, adapter, session),
// not addresses.
func logMessage(timestamp uint64, msg *uint16) uintptr {
	at := time.Unix(0, (int64(timestamp)-116444736000000000)*100)
	log.Printf("[tun] wintun %s: %s", at.Format("15:04:05.000"), windows.UTF16PtrToString(msg))
	return 0
}

// setupLogger routes Wintun's log to logMessage. The callback's arguments
// follow the C ABI: a 32-bit process receives the 64-bit timestamp as two words.
func setupLogger(module *windows.DLL) {
	proc, err := module.FindProc("WintunSetLogger")
	if err != nil {
		return
	}
	var callback uintptr
	switch runtime.GOARCH {
	case "386":
		callback = windows.NewCallback(func(_, timestampLow, timestampHigh uint32, msg *uint16) uintptr {
			return logMessage(uint64(timestampHigh)<<32|uint64(timestampLow), msg)
		})
	case "arm":
		callback = windows.NewCallback(func(_, _, timestampLow, timestampHigh uint32, msg *uint16) uintptr {
			return logMessage(uint64(timestampHigh)<<32|uint64(timestampLow), msg)
		})
	default:
		callback = windows.NewCallback(func(_ uint32, timestamp uint64, msg *uint16) uintptr {
			return logMessage(timestamp, msg)
		})
	}
	syscall.SyscallN(proc.Addr(), callback)
}

func closeAdapter(wintun *Adapter) {
	syscall.SyscallN(procWintunCloseAdapter.Addr(), 1, wintun.handle, 0, 0)
}

// CreateAdapter creates a Wintun adapter. name is the cosmetic name of the adapter.
// tunnelType represents the type of adapter and should be "Wintun". requestedGUID is
// the GUID of the created network adapter, which then influences NLA generation
// deterministically. If it is set to nil, the GUID is chosen by the system at random,
// and hence a new NLA entry is created for each new adapter.
func CreateAdapter(name string, tunnelType string, requestedGUID *windows.GUID) (wintun *Adapter, err error) {
	err = procWintunCloseAdapter.Find()
	if err != nil {
		return
	}
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	var tunnelType16 *uint16
	tunnelType16, err = windows.UTF16PtrFromString(tunnelType)
	if err != nil {
		return
	}
	r0, _, e1 := syscall.Syscall(procWintunCreateAdapter.Addr(), 3, uintptr(unsafe.Pointer(name16)), uintptr(unsafe.Pointer(tunnelType16)), uintptr(unsafe.Pointer(requestedGUID)))
	if r0 == 0 {
		err = e1
		return
	}
	wintun = &Adapter{handle: r0}
	runtime.SetFinalizer(wintun, closeAdapter)
	return
}

// OpenAdapter opens an existing Wintun adapter by name.
func OpenAdapter(name string) (wintun *Adapter, err error) {
	var name16 *uint16
	name16, err = windows.UTF16PtrFromString(name)
	if err != nil {
		return
	}
	r0, _, e1 := syscall.Syscall(procWintunOpenAdapter.Addr(), 1, uintptr(unsafe.Pointer(name16)), 0, 0)
	if r0 == 0 {
		err = e1
		return
	}
	wintun = &Adapter{handle: r0}
	runtime.SetFinalizer(wintun, closeAdapter)
	return
}

// Close closes a Wintun adapter.
func (wintun *Adapter) Close() (err error) {
	runtime.SetFinalizer(wintun, nil)
	r1, _, e1 := syscall.Syscall(procWintunCloseAdapter.Addr(), 1, wintun.handle, 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

// Uninstall removes the driver from the system if no drivers are currently in use.
func Uninstall() (err error) {
	r1, _, e1 := syscall.Syscall(procWintunDeleteDriver.Addr(), 0, 0, 0, 0)
	if r1 == 0 {
		err = e1
	}
	return
}

// RunningVersion returns the version of the running Wintun driver.
func RunningVersion() (version uint32, err error) {
	r0, _, e1 := syscall.Syscall(procWintunGetRunningDriverVersion.Addr(), 0, 0, 0, 0)
	version = uint32(r0)
	if version == 0 {
		err = e1
	}
	return
}

// LUID returns the LUID of the adapter.
func (wintun *Adapter) LUID() (luid uint64) {
	syscall.Syscall(procWintunGetAdapterLUID.Addr(), 2, uintptr(wintun.handle), uintptr(unsafe.Pointer(&luid)), 0)
	return
}
