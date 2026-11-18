package tun

import "testing"

func TestKeptAdapterNameIsMatchedAsWindowsMatchesIt(t *testing.T) {
	if isKeptAdapter("GlitchVPN") {
		t.Fatal("kept before anything was")
	}
	keptAdapters.Store(keptAdapterKey("GlitchVPN"), struct{}{})
	t.Cleanup(func() { keptAdapters.Delete(keptAdapterKey("GlitchVPN")) })
	for _, name := range []string{"GlitchVPN", "glitchvpn", "GLITCHVPN"} {
		if !isKeptAdapter(name) {
			t.Errorf("%q not taken for the kept adapter", name)
		}
	}
	if isKeptAdapter("Other") {
		t.Error("another name taken for the kept adapter")
	}
}
