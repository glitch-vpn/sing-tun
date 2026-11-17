package wintun

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestDLLPathIsBesideTheModule(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path, err := dllPath(dllFileName)
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("path %q is not absolute", path)
	}
	if !sameFile(t, filepath.Dir(path), filepath.Dir(executable)) || filepath.Base(path) != dllFileName {
		t.Fatalf("path %q, want the directory of %q", path, executable)
	}
}

// A loadable library named wintun.dll in the working directory and on PATH
// must not be found: only a file beside the module is.
func TestLoadIgnoresDLLInWorkingDirectory(t *testing.T) {
	path, err := dllPath(dllFileName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("%s exists before the test", path)
	}
	decoyDirectory := t.TempDir()
	copySystemLibrary(t, filepath.Join(decoyDirectory, dllFileName))
	t.Chdir(decoyDirectory)
	t.Setenv("PATH", decoyDirectory)
	if err := newLazyDLL(dllFileName).Load(); err == nil {
		t.Fatal("loaded a wintun.dll that is not beside the module")
	}
}

func TestLoadTakesTheDLLBesideTheModule(t *testing.T) {
	path, err := dllPath(dllFileName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatalf("%s exists before the test", path)
	}
	copySystemLibrary(t, path)
	t.Cleanup(func() { os.Remove(path) })

	dll := newLazyDLL(dllFileName)
	if err := dll.Load(); err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetModuleFileName(dll.module.Handle, &buffer[0], uint32(len(buffer)))
	if err != nil {
		t.Fatal(err)
	}
	loaded := windows.UTF16ToString(buffer[:length])
	if !strings.EqualFold(loaded, path) {
		t.Fatalf("loaded %q, want %q", loaded, path)
	}
}

// copySystemLibrary writes a loadable library, which stands in for Wintun's.
func copySystemLibrary(t *testing.T, destination string) {
	t.Helper()
	systemDirectory, err := windows.GetSystemDirectory()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(filepath.Join(systemDirectory, "version.dll"))
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	target, err := os.Create(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if _, err := io.Copy(target, source); err != nil {
		t.Fatal(err)
	}
}

func sameFile(t *testing.T, a, b string) bool {
	t.Helper()
	infoA, errA := os.Stat(a)
	infoB, errB := os.Stat(b)
	if errA != nil || errB != nil {
		t.Fatalf("stat: %v, %v", errA, errB)
	}
	return os.SameFile(infoA, infoB)
}
