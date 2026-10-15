package v2ray

import (
	"fmt"
	"github.com/daeuniverse/dae/pkg/outbound/dialer"
	"runtime"

	"golang.org/x/sys/cpu"
)

var (
	hasGCMAsmAMD64 = cpu.X86.HasAES && cpu.X86.HasPCLMULQDQ
	hasGCMAsmARM64 = cpu.ARM64.HasAES && cpu.ARM64.HasPMULL
	// Keep in sync with crypto/aes/cipher_s390x.go.
	hasGCMAsmS390X = cpu.S390X.HasAES && cpu.S390X.HasAESCBC && cpu.S390X.HasAESCTR &&
		(cpu.S390X.HasGHASH || cpu.S390X.HasAESGCM)

	hasAESGCMHardwareSupport = runtime.GOARCH == "amd64" && hasGCMAsmAMD64 ||
		runtime.GOARCH == "arm64" && hasGCMAsmARM64 ||
		runtime.GOARCH == "s390x" && hasGCMAsmS390X
)

func getAutoCipher() string {
	if hasAESGCMHardwareSupport {
		return "aes-128-gcm"
	}
	return "chacha20-poly1305"
}

// AEAD request headers (alterID=0) and body encryption are separate choices.
// This client implements the two AEAD body ciphers, not none/zero bodies.
func (s *V2Ray) dataCipher() (string, error) {
	if s.Protocol == "vless" {
		if s.Encryption != "" && s.Encryption != "none" {
			return "", fmt.Errorf("%w: unsupported VLESS encryption %q", dialer.UnexpectedFieldErr, s.Encryption)
		}
		return "", nil
	}
	if s.Aid != "" && s.Aid != "0" {
		return "", fmt.Errorf("%w: VMess alterID must be 0 for AEAD request headers", dialer.UnexpectedFieldErr)
	}
	switch s.Cipher {
	case "", "auto":
		return getAutoCipher(), nil
	case "aes-128-gcm", "chacha20-poly1305":
		return s.Cipher, nil
	default:
		return "", fmt.Errorf("%w: unsupported VMess cipher %q", dialer.UnexpectedFieldErr, s.Cipher)
	}
}
