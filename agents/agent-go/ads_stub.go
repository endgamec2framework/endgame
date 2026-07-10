//go:build !windows

package agent

import "fmt"

func adsWrite(path, stream string, data []byte) error {
	return fmt.Errorf("ADS not supported on this platform")
}

func adsRead(path, stream string) ([]byte, error) {
	return nil, fmt.Errorf("ADS not supported on this platform")
}

func adsList(path string) (string, error) {
	return "", fmt.Errorf("ADS not supported on this platform")
}

func adsDelete(path, stream string) error {
	return fmt.Errorf("ADS not supported on this platform")
}
