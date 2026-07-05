package server

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type CertBundle struct {
	CACert  *x509.Certificate
	CAKey   *rsa.PrivateKey
	CACertPEM []byte
	CAKeyPEM  []byte
}

func GenerateCA(certsDir string) (*CertBundle, error) {
	key, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"IT Security"}, CommonName: "Internal CA"},
		NotBefore:             time.Now().Add(-time.Minute),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, _ := x509.ParseCertificate(certDER)

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	if err := os.WriteFile(filepath.Join(certsDir, "ca.crt"), certPEM, 0600); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(certsDir, "ca.key"), keyPEM, 0600); err != nil {
		return nil, err
	}
	return &CertBundle{CACert: cert, CAKey: key, CACertPEM: certPEM, CAKeyPEM: keyPEM}, nil
}

func LoadCA(certsDir string) (*CertBundle, error) {
	certPEM, err := os.ReadFile(filepath.Join(certsDir, "ca.crt"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(certsDir, "ca.key"))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(keyPEM)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return &CertBundle{CACert: cert, CAKey: key, CACertPEM: certPEM, CAKeyPEM: keyPEM}, nil
}

// SignServerCert generates a server cert signed by the CA, writes to certsDir, returns TLS config.
func (ca *CertBundle) SignServerCert(certsDir string, ips []net.IP) (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{Organization: []string{"IT Security"}, CommonName: "Internal Services"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  append(ips, net.ParseIP("127.0.0.1")),
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.CACert, &key.PublicKey, ca.CAKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})

	os.WriteFile(filepath.Join(certsDir, "server.crt"), certPEM, 0600)
	os.WriteFile(filepath.Join(certsDir, "server.key"), keyPEM, 0600)

	return tls.X509KeyPair(certPEM, keyPEM)
}

// SignAgentCert generates a unique client cert for an agent. Returns PEM bytes.
func (ca *CertBundle) SignAgentCert(agentID string) (certPEM, keyPEM []byte, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"IT Security"}, CommonName: agentID},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(5 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, ca.CACert, &key.PublicKey, ca.CAKey)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return certPEM, keyPEM, nil
}

func EnsureCA(certsDir string) (*CertBundle, error) {
	if _, err := os.Stat(filepath.Join(certsDir, "ca.crt")); err == nil {
		return LoadCA(certsDir)
	}
	return GenerateCA(certsDir)
}
