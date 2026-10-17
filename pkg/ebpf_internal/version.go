// Modified from https://github.com/cilium/ebpf/blob/v0.10.0/internal/version.go

package internal

import (
	"fmt"
	"sync"

	"github.com/daeuniverse/dae/pkg/ebpf_internal/internal/unix"
)

var (
	kernelVersion = struct {
		once    sync.Once
		version Version
		err     error
	}{}
)

// A Version in the form Major.Minor.Patch.
type Version [3]uint16

// NewVersion creates a version from a string like "Major.Minor.Patch".
//
// Patch is optional.
func NewVersion(ver string) (Version, error) {
	var major, minor, patch uint16
	n, _ := fmt.Sscanf(ver, "%d.%d.%d", &major, &minor, &patch)
	if n < 2 {
		return Version{}, fmt.Errorf("invalid version: %s", ver)
	}
	return Version{major, minor, patch}, nil
}

// NewVersionFromCode creates a version from a LINUX_VERSION_CODE.
func NewVersionFromCode(code uint32) Version {
	return Version{
		uint16(uint8(code >> 16)),
		uint16(uint8(code >> 8)),
		uint16(uint8(code)),
	}
}

func (v Version) String() string {
	if v[2] == 0 {
		return fmt.Sprintf("v%d.%d", v[0], v[1])
	}
	return fmt.Sprintf("v%d.%d.%d", v[0], v[1], v[2])
}

// Less returns true if the version is less than another version.
func (v Version) Less(other Version) bool {
	for i, a := range v {
		if a == other[i] {
			continue
		}
		return a < other[i]
	}
	return false
}

// utsnameToString converts the utsname to a string and returns it.
func utsnameToString(unameArray [65]byte) string {
	var byteString [65]byte
	var indexLength int
	for ; unameArray[indexLength] != 0; indexLength++ {
		byteString[indexLength] = unameArray[indexLength]
	}
	return string(byteString[:indexLength])
}

// KernelVersion returns the version of the currently running kernel.
func KernelVersion() (Version, error) {
	kernelVersion.once.Do(func() {
		kernelVersion.version, kernelVersion.err = detectKernelVersion()
		if kernelVersion.err != nil {
			// Try syscall.
			var utsname unix.Utsname
			if err := unix.Uname(&utsname); err != nil {
				kernelVersion.err = fmt.Errorf("%w; %v", kernelVersion.err, err)
				return
			}
			version, err := NewVersion(utsnameToString(utsname.Release))
			if err != nil {
				kernelVersion.err = fmt.Errorf("%w; %v", kernelVersion.err, err)
				return
			}
			kernelVersion.version = version
			kernelVersion.err = nil
		}
	})

	if kernelVersion.err != nil {
		return Version{}, kernelVersion.err
	}
	return kernelVersion.version, nil
}

// detectKernelVersion returns the version of the running kernel.
func detectKernelVersion() (Version, error) {
	vc, err := vdsoVersion()
	if err != nil {
		return Version{}, err
	}
	return NewVersionFromCode(vc), nil
}
