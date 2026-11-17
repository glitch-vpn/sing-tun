package wintun

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDLLPathIsBesideTheModule(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	path, err := dllPath("wintun.dll")
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(path) {
		t.Fatalf("path %q is not absolute", path)
	}
	want := filepath.Join(filepath.Dir(executable), "wintun.dll")
	if !sameFile(t, filepath.Dir(path), filepath.Dir(want)) || filepath.Base(path) != "wintun.dll" {
		t.Fatalf("path %q, want the directory of %q", path, executable)
	}
}

func TestLoadIgnoresDLLInWorkingDirectory(t *testing.T) {
	decoy := t.TempDir()
	if err := os.WriteFile(filepath.Join(decoy, "wintun.dll"), []byte("not a library"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Chdir(decoy)
	t.Setenv("PATH", decoy)
	path, err := dllPath("wintun.dll")
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Dir(path) == decoy {
		t.Fatalf("path %q is in the working directory", path)
	}
	if _, err := os.Stat(path); err == nil {
		t.Skip("a wintun.dll sits beside the test binary")
	}
	if err := newLazyDLL("wintun.dll").Load(); err == nil {
		t.Fatal("loaded a wintun.dll that is not beside the module")
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

func TestLoadFindsDLLBesideTheModule(t *testing.T) {
	path, err := dllPath("wintun.dll")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Skip("no wintun.dll beside the test binary")
	}
	if err := procWintunCreateAdapter.Find(); err != nil {
		t.Fatal(err)
	}
}
