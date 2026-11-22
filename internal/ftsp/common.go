// Package ftsp implements FTSP/1, FortiTatake's LAN sync protocol
// (docs/SYNC-PROTOCOL.md): a Windows hub and Android spokes exchanging
// append-only events over pinned TLS.
package ftsp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base32"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Version is the protocol version.
const Version = 1

// DefaultPort is the hub's default TCP port.
const DefaultPort = 47431

// ServiceType is the DNS-SD service name.
const ServiceType = "_fortitatake._tcp"

// Catalog entry for content packs. v0.2 ships the whole content bundle as one pack.
type Pack struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
	Size    int    `json:"size"`
}

// ContentSource lets the sync layer read and install the content bundle.
type ContentSource interface {
	Current() (data []byte, p Pack)
	Install(data []byte, p Pack) error
}

var b32 = base32.NewEncoding("0123456789ABCDEFGHJKMNPQRSTVWXYZ").WithPadding(base32.NoPadding)

func randToken(nbytes int) string {
	b := make([]byte, nbytes)
	_, _ = rand.Read(b)
	return b32.EncodeToString(b)
}

func sha256Hex(b []byte) string {
	h := sha256.Sum256(b)
	return strings.ToUpper(hex.EncodeToString(h[:]))
}

// Words returns the four-word form of a certificate fingerprint.
func Words(fp string) string {
	b, err := hex.DecodeString(strings.ToLower(strings.TrimPrefix(fp, "sha256:")))
	if err != nil || len(b) < 4 {
		return ""
	}
	return strings.Join([]string{fpWords[b[0]], fpWords[b[1]], fpWords[b[2]], fpWords[b[3]]}, " ")
}

// NormCode normalizes a typed pairing code: uppercase, no dashes or spaces,
// and the Crockford look-alikes O→0, I/L→1.
func NormCode(c string) string {
	c = strings.ToUpper(strings.TrimSpace(c))
	r := strings.NewReplacer("-", "", " ", "", "O", "0", "I", "1", "L", "1")
	return r.Replace(c)
}

// apiError is the protocol's error body.
type apiError struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, code, msg string) {
	var e apiError
	e.Error.Code, e.Error.Message = code, msg
	writeJSON(w, status, e)
}

// IsLAN reports whether ip is loopback, private (RFC 1918 / ULA) or link-local.
func IsLAN(ip net.IP) bool {
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast())
}

// LANAddrs lists this machine's private IPv4 addresses, best first.
func LANAddrs() []string {
	var out []string
	ifs, err := net.Interfaces()
	if err != nil {
		return nil
	}
	for _, ifc := range ifs {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		name := strings.ToLower(ifc.Name)
		virtual := strings.Contains(name, "vmware") || strings.Contains(name, "virtualbox") || strings.Contains(name, "vethernet") || strings.Contains(name, "docker") || strings.Contains(name, "wsl")
		addrs, _ := ifc.Addrs()
		for _, a := range addrs {
			ipn, ok := a.(*net.IPNet)
			if !ok || ipn.IP.To4() == nil || !ipn.IP.IsPrivate() {
				continue
			}
			if virtual {
				out = append(out, ipn.IP.String()) // keep, but after real adapters
			} else {
				out = append([]string{ipn.IP.String()}, out...)
			}
		}
	}
	return out
}

// loadOrCreateCert returns the hub's long-lived self-signed ECDSA P-256 certificate.
func loadOrCreateCert(dir string) (tls.Certificate, string, error) {
	certPath, keyPath := filepath.Join(dir, "hub-cert.pem"), filepath.Join(dir, "hub-key.pem")
	if c, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		return c, sha256Hex(c.Certificate[0]), nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	host, _ := os.Hostname()
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "FortiTatake hub " + host},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{"fortitatake.local"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	kb, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	return c, sha256Hex(der), nil
}

// ErrPinMismatch is returned when the hub presents a certificate other than the pinned one.
var ErrPinMismatch = errors.New("the PC presented a different certificate than the one paired; pair again if you reinstalled FortiTatake on the PC")

// pinnedClient returns an HTTPS client that accepts only the certificate with the given
// SHA-256 fingerprint. With pin == "" it accepts any certificate and records its
// fingerprint in *seen (trust on first use, confirmed by the user with the four words).
func pinnedClient(pin string, seen *string, timeout time.Duration) *http.Client {
	cfg := &tls.Config{
		InsecureSkipVerify: true, // replaced by the pin check below
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if len(raw) == 0 {
				return ErrPinMismatch
			}
			fp := sha256Hex(raw[0])
			if seen != nil {
				*seen = fp
			}
			if pin != "" && !strings.EqualFold(fp, strings.TrimPrefix(pin, "sha256:")) {
				return ErrPinMismatch
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     cfg,
			Proxy:               nil, // LAN only, never through a proxy
			DialContext:         (&net.Dialer{Timeout: 4 * time.Second}).DialContext,
			TLSHandshakeTimeout: 5 * time.Second,
			MaxIdleConns:        2,
			IdleConnTimeout:     30 * time.Second,
		},
	}
}

// writeFileAtomic writes via a temp file and rename.
func writeFileAtomic(path string, b []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
