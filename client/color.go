package client

import "fmt"

// ANSI color/style codes.
const (
	cReset   = "\033[0m"
	cBold    = "\033[1m"
	cDim     = "\033[2m"
	cRed     = "\033[31m"
	cGreen   = "\033[32m"
	cYellow  = "\033[33m"
	cBlue    = "\033[34m"
	cMagenta = "\033[35m"
	cCyan    = "\033[36m"
	cWhite   = "\033[37m"

	cBRed    = "\033[1;31m"
	cBGreen  = "\033[1;32m"
	cBYellow = "\033[1;33m"
	cBBlue   = "\033[1;34m"
	cBCyan   = "\033[1;36m"
	cBWhite  = "\033[1;37m"

	// Prefix tokens
	pfxInfo = cBBlue + "[*]" + cReset + " "
	pfxOK   = cBGreen + "[+]" + cReset + " "
	pfxWarn = cBYellow + "[!]" + cReset + " "
	pfxErr  = cBRed + "[-]" + cReset + " "
)

// Convenience wrappers — print with newline.
func info(format string, a ...any) {
	fmt.Print(pfxInfo + fmt.Sprintf(format, a...) + "\n")
}
func ok(format string, a ...any) {
	fmt.Print(pfxOK + fmt.Sprintf(format, a...) + "\n")
}
func warn(format string, a ...any) {
	fmt.Print(pfxWarn + fmt.Sprintf(format, a...) + "\n")
}
func errLine(format string, a ...any) {
	fmt.Print(pfxErr + fmt.Sprintf(format, a...) + "\n")
}

// bold returns s wrapped in bold escape codes.
func bold(s string) string { return cBold + s + cReset }
