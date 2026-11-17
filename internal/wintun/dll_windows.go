/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package wintun

import (
	"fmt"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// dllFileName is looked up in the directory of the module that holds this
// code, by full path and nowhere else: a wintun.dll on the search path or in
// the working directory is never loaded.
const dllFileName = "wintun.dll"

func (d *lazyDLL) NewProc(name string) *lazyProc {
	return &lazyProc{dll: d, Name: name}
}

type lazyProc struct {
	Name string
	mu   sync.Mutex
	dll  *lazyDLL
	addr uintptr
}

func (p *lazyProc) Find() error {
	if atomic.LoadUintptr(&p.addr) != 0 {
		return nil
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.addr != 0 {
		return nil
	}

	err := p.dll.Load()
	if err != nil {
		return fmt.Errorf("error loading DLL: %s, MODULE: %s, error: %w", p.dll.Name, p.Name, err)
	}
	proc, err := p.dll.module.FindProc(p.Name)
	if err != nil {
		return fmt.Errorf("error getting %s address: %w", p.Name, err)
	}

	atomic.StoreUintptr(&p.addr, proc.Addr())
	return nil
}

func (p *lazyProc) Addr() uintptr {
	err := p.Find()
	if err != nil {
		panic(err)
	}
	return p.addr
}

func (p *lazyProc) Load() error {
	return p.dll.Load()
}

type lazyDLL struct {
	Name   string
	mu     sync.Mutex
	loaded atomic.Bool
	module *windows.DLL
}

func newLazyDLL(name string) *lazyDLL {
	return &lazyDLL{Name: name}
}

func (d *lazyDLL) Load() error {
	if d.loaded.Load() {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.loaded.Load() {
		return nil
	}

	path, err := dllPath(d.Name)
	if err != nil {
		return err
	}
	handle, err := windows.LoadLibraryEx(path, 0, windows.LOAD_LIBRARY_SEARCH_DLL_LOAD_DIR|windows.LOAD_LIBRARY_SEARCH_SYSTEM32)
	if err != nil {
		return fmt.Errorf("unable to load %s: %w", path, err)
	}
	d.module = &windows.DLL{Name: path, Handle: handle}
	d.loaded.Store(true)
	return nil
}

// dllPath is the absolute path of name inside the directory of the module
// that holds this code: the core's DLL inside an app, or the executable of a
// service or a test.
func dllPath(name string) (string, error) {
	dir, err := moduleDirectory()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, name), nil
}

func moduleDirectory() (string, error) {
	var module windows.Handle
	address := reflect.ValueOf(moduleDirectory).Pointer()
	err := windows.GetModuleHandleEx(
		windows.GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS|windows.GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		*(**uint16)(unsafe.Pointer(&address)), &module)
	if err != nil {
		return "", fmt.Errorf("unable to find the module of the code: %w", err)
	}
	file, err := moduleFileName(module)
	if err != nil {
		return "", err
	}
	return filepath.Dir(file), nil
}

func moduleFileName(module windows.Handle) (string, error) {
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetModuleFileName(module, &buffer[0], uint32(len(buffer)))
	if err != nil {
		return "", fmt.Errorf("unable to read the module's file name: %w", err)
	}
	if int(length) >= len(buffer) {
		return "", fmt.Errorf("the module's file name is longer than %d characters", len(buffer))
	}
	return windows.UTF16ToString(buffer[:length]), nil
}
