package agent

import (
	"fmt"
	"strings"
	"sync"
)

// asmStore holds pre-loaded .NET assemblies by name for reuse across commands
// (e.g. powerpick, custom tools). Same pattern as the BOF store.
var asmStore struct {
	sync.Mutex
	m map[string][]byte
}

func asmStoreLoad(name string, data []byte) {
	asmStore.Lock()
	defer asmStore.Unlock()
	if asmStore.m == nil {
		asmStore.m = make(map[string][]byte)
	}
	asmStore.m[name] = data
}

func asmStoreGet(name string) ([]byte, bool) {
	asmStore.Lock()
	defer asmStore.Unlock()
	d, ok := asmStore.m[name]
	return d, ok
}

func asmStoreList() string {
	asmStore.Lock()
	defer asmStore.Unlock()
	if len(asmStore.m) == 0 {
		return "(asm store empty)"
	}
	var sb strings.Builder
	for k, v := range asmStore.m {
		fmt.Fprintf(&sb, "  %-30s  %d bytes\n", k, len(v))
	}
	return strings.TrimRight(sb.String(), "\n")
}

func asmStoreUnload(name string) string {
	asmStore.Lock()
	defer asmStore.Unlock()
	if _, ok := asmStore.m[name]; !ok {
		return fmt.Sprintf("[-] '%s' not in asm store", name)
	}
	delete(asmStore.m, name)
	return fmt.Sprintf("[+] '%s' removed from asm store", name)
}
