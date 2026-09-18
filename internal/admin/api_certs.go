package admin

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"os"
	"time"

	"github.com/inkdust2021/vibeguard/internal/cert"
)

// CertResponse represents the certificate API response
type CertResponse struct {
	CA struct {
		Subject           string `json:"subject"`
		NotBefore         string `json:"not_before"`
		NotAfter          string `json:"not_after"`
		FingerprintSHA256 string `json:"fingerprint_sha256"`
		IsTrusted         bool   `json:"is_trusted"`
		// TrustStatus indicates trust detection result for the current runtime environment:
		// - trusted: detected as trusted
		// - untrusted: detected as not trusted
		// - unknown: cannot reliably detect (e.g. running inside a container; cannot tell if the host/browser trusts the exported ca.crt)
		TrustStatus string `json:"trust_status"`
		CertPath    string `json:"cert_path"`
	} `json:"ca"`
}

// handleCertificates handles GET /_admin/api/certificates
func (a *Admin) handleCertificates(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	resp := CertResponse{}
	resp.CA.CertPath = a.certPath

	// Get cert info from CA
	if a.ca != nil {
		caCertPEM := a.ca.GetCertificate()
		if len(caCertPEM) > 0 {
			if block, _ := pem.Decode(caCertPEM); block != nil && block.Type == "CERTIFICATE" {
				if caCert, err := x509.ParseCertificate(block.Bytes); err == nil {
					resp.CA.Subject = caCert.Subject.String()
					resp.CA.NotBefore = caCert.NotBefore.Format(time.RFC3339)
					resp.CA.NotAfter = caCert.NotAfter.Format(time.RFC3339)
					resp.CA.FingerprintSHA256 = cert.FingerprintSHA256FromCertificate(caCert)
				}
			}
		}
	}
	if resp.CA.Subject == "" {
		resp.CA.Subject = "VibeGuard CA"
	}

	// Check if trusted by system
	resp.CA.IsTrusted = cert.IsCATrusted(a.certPath)
	if resp.CA.IsTrusted {
		resp.CA.TrustStatus = "trusted"
	} else if isLikelyContainerRuntime() {
		// In containers, the "system trust store" differs from the host/browser; the backend cannot reliably determine client trust for the exported ca.crt.
		resp.CA.TrustStatus = "unknown"
	} else {
		resp.CA.TrustStatus = "untrusted"
	}

	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	json.NewEncoder(w).Encode(resp)
}

// handleCertTrust handles POST /_admin/api/certificates/trust
func (a *Admin) handleCertTrust(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// The admin UI runs in the server process and should not trigger interactive sudo; only install into the user trust store here.
	if err := cert.InstallCAToTrustStore(a.certPath, cert.TrustInstallModeUser); err != nil {
		http.Error(w, "安装到用户信任库失败。若需要安装到系统信任库（sudo），请在终端运行：vibeguard trust --mode system\n\n"+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "trusted_user",
	})
}

// handleCertRegenerate handles POST /_admin/api/certificates/regenerate
func (a *Admin) handleCertRegenerate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	certBackup := a.certPath + ".bak"
	keyBackup := a.keyPath + ".bak"
	haveExisting := fileExists(a.certPath) && fileExists(a.keyPath)
	if haveExisting {
		// Back up the old CA first (overwriting any stale previous backup) so a
		// failed rotation can be rolled back and the old CA remains recoverable.
		// LoadOrGenerateCA would otherwise silently reuse the existing files,
		// making this endpoint a no-op.
		_ = os.Remove(certBackup)
		_ = os.Remove(keyBackup)
		if err := os.Rename(a.certPath, certBackup); err != nil {
			http.Error(w, "Failed to back up old CA: "+err.Error(), http.StatusInternalServerError)
			return
		}
		if err := os.Rename(a.keyPath, keyBackup); err != nil {
			_ = os.Rename(certBackup, a.certPath) // best-effort restore
			http.Error(w, "Failed to back up old CA key: "+err.Error(), http.StatusInternalServerError)
			return
		}
	}

	// Generate a brand-new CA (files were moved away above, so this always creates fresh material).
	newCA, err := cert.LoadOrGenerateCA(a.certPath, a.keyPath)
	if err != nil {
		// Rotation failed: restore the previous CA so the proxy keeps working
		// with the old (still trusted) certificate.
		if haveExisting {
			_ = os.Rename(certBackup, a.certPath)
			_ = os.Rename(keyBackup, a.keyPath)
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Update reference
	a.ca = newCA
	a.metaRecord(r, "cert.regenerate")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{
		"status": "regenerated",
		"message": "CA certificate regenerated. The old CA was backed up as ca.crt.bak / ca.key.bak.\n" +
			"WARNING: the session WAL and encrypted keywords stored in the config are encrypted with a key derived from the OLD CA key and can no longer be decrypted after rotation (new sessions and new keywords are unaffected). Consider clearing old sessions and re-configuring encrypted keywords if needed.\n" +
			"Clients must re-trust the new ca.crt.\n" +
			"CA 证书已重新生成，旧 CA 已备份为 ca.crt.bak / ca.key.bak。\n" +
			"警告：会话 WAL 与配置中加密存储的关键词均使用旧 CA 密钥派生加密，轮换后将无法解密（新会话与新关键词不受影响）。建议清除旧会话，必要时重新配置加密关键词。\n" +
			"客户端需重新信任新的 ca.crt。",
	})
}
