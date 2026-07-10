package agent

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type searchResult struct {
	Path    string
	Size    int64
	ModTime time.Time
}

// fileSearch walks root recursively looking for files whose name matches pattern.
// pattern supports shell wildcards (*, ?, [abc]).
// Stops after maxResults hits or maxDuration elapsed.
func fileSearch(root, pattern string, maxResults int, maxDuration time.Duration) ([]searchResult, error) {
	deadline := time.Now().Add(maxDuration)
	var results []searchResult

	// Skip directories that will hang or have no useful files.
	skipDirs := map[string]bool{
		"proc": true, "sys": true, "dev": true, "run": true,
		"$Recycle.Bin": true, "System Volume Information": true,
		"Windows\\WinSxS": true,
	}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return filepath.SkipDir
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("timeout")
		}
		if d.IsDir() {
			base := d.Name()
			if skipDirs[base] || strings.HasPrefix(base, "$") {
				return filepath.SkipDir
			}
			return nil
		}
		matched, _ := filepath.Match(strings.ToLower(pattern), strings.ToLower(d.Name()))
		if matched {
			info, err := d.Info()
			if err != nil {
				return nil
			}
			results = append(results, searchResult{Path: path, Size: info.Size(), ModTime: info.ModTime()})
			if len(results) >= maxResults {
				return fmt.Errorf("max results")
			}
		}
		return nil
	})

	if err != nil && err.Error() != "timeout" && err.Error() != "max results" {
		// Non-fatal walk errors are common (permission denied) — ignore
	}
	return results, nil
}

// defaultSearchRoot returns the most useful search starting point for the OS.
func defaultSearchRoot() string {
	if runtime.GOOS == "windows" {
		// Try common paths first; C:\ is fine but slow, so default to Users
		if _, err := os.Stat(`C:\Users`); err == nil {
			return `C:\`
		}
		return `C:\`
	}
	return "/home"
}

// formatSearchResults formats results as a plain text table.
func formatSearchResults(results []searchResult, truncated bool) string {
	if len(results) == 0 {
		return "[no results]"
	}
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%-80s  %10s  %s\n", "Path", "Size", "Modified"))
	sb.WriteString(strings.Repeat("-", 110) + "\n")
	for _, r := range results {
		sb.WriteString(fmt.Sprintf("%-80s  %10s  %s\n",
			r.Path,
			humanSize(r.Size),
			r.ModTime.Format("2006-01-02 15:04"),
		))
	}
	if truncated {
		sb.WriteString(fmt.Sprintf("\n[!] results truncated at %d — narrow your search\n", len(results)))
	}
	return sb.String()
}

func humanSize(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
