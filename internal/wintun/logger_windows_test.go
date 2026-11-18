package wintun

import (
	"bytes"
	"log"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// A library without WintunSetLogger loads, and the hook leaves it alone.
func TestLoadWithLoggerHookTakesALibraryWithoutTheExport(t *testing.T) {
	// Another name than Wintun's: a loaded library cannot be deleted, so the
	// file of an earlier test's load is still there.
	const name = "wintun-logger-test.dll"
	path, err := dllPath(name)
	if err != nil {
		t.Fatal(err)
	}
	copySystemLibrary(t, path)
	t.Cleanup(func() { os.Remove(path) })

	dll := &lazyDLL{Name: name, onLoad: setupLogger}
	if err := dll.Load(); err != nil {
		t.Fatal(err)
	}
	if !dll.loaded.Load() {
		t.Fatal("the library is not marked loaded")
	}
}

// The native entry point, called as Wintun calls it with its C arguments,
// writes the message with the driver's time and keeps the level.
func TestLoggerCallbackWritesTheDriversMessage(t *testing.T) {
	var written bytes.Buffer
	previousWriter, previousFlags := log.Writer(), log.Flags()
	log.SetOutput(&written)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(previousWriter); log.SetFlags(previousFlags) })

	at := time.Date(2026, 11, 18, 12, 34, 56, 789_000_000, time.UTC)
	fileTime := uint64(at.UnixNano()/100 + loggerFileTimeEpochOffset)
	text, err := windows.UTF16PtrFromString("Removed orphaned adapter")
	if err != nil {
		t.Fatal(err)
	}
	callback := loggerCallback()
	cases := []struct {
		level  uintptr
		prefix string
	}{{logLevelInfo, ""}, {logLevelWarn, "warn: "}, {logLevelError, "error: "}}
	for _, c := range cases {
		written.Reset()
		var arguments []uintptr
		low, high := uintptr(uint32(fileTime)), uintptr(fileTime>>32)
		switch runtime.GOARCH {
		case "386":
			arguments = []uintptr{c.level, low, high, uintptr(unsafe.Pointer(text))}
		case "arm":
			arguments = []uintptr{c.level, 0, low, high, uintptr(unsafe.Pointer(text))}
		default:
			arguments = []uintptr{c.level, uintptr(fileTime), uintptr(unsafe.Pointer(text))}
		}
		syscall.SyscallN(callback, arguments...)
		want := c.prefix + "[tun] wintun 12:34:56.789: Removed orphaned adapter"
		if got := strings.TrimSpace(written.String()); got != want {
			t.Errorf("level %d: wrote %q, want %q", c.level, got, want)
		}
	}
}
