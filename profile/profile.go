package profile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

type Profile struct {
	Name          string `json:"name"`
	Server        string `json:"server"`          // host:port — used for direct SSH-tunnel connections
	CACertPEM     string `json:"ca_cert_pem"`
	ClientCertPEM string `json:"client_cert_pem"`
	ClientKeyPEM  string `json:"client_key_pem"`
	ViaWS         string `json:"via_ws,omitempty"` // optional: ws[s]://host/ws — connect through WebSocket tunnel
}

func DefaultDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".endgame", "profiles")
}

func Save(p *Profile, dir string) (string, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	path := filepath.Join(dir, p.Name+".json")
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return "", err
	}
	return path, os.WriteFile(path, data, 0600)
}

func Load(path string) (*Profile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	if p.Server == "" || p.CACertPEM == "" || p.ClientCertPEM == "" || p.ClientKeyPEM == "" {
		return nil, fmt.Errorf("perfil incompleto: faltan campos obligatorios")
	}
	return &p, nil
}

// Export escribe el perfil en una ruta arbitraria (para distribución al cliente).
func Export(p *Profile, path string) error {
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func List(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name()[:len(e.Name())-5])
		}
	}
	return names, nil
}
