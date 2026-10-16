// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	localca "github.com/daeuniverse/dae/component/ca"
)

func runCACommand(args ...string) (string, error) {
	command := newCACommand()
	var output bytes.Buffer
	command.SetOut(&output)
	command.SetErr(&output)
	command.SetArgs(args)
	err := command.Execute()
	return output.String(), err
}

func TestCAGenerateInspectAndExport(t *testing.T) {
	if _, err := runCACommand("generate", "--valid-days", "0"); err == nil {
		t.Fatal("accepted nonpositive certificate validity")
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")
	output, err := runCACommand("generate", "--cert", certPath, "--key", keyPath, "--name", "CLI test CA", "--valid-days", "1")
	if err != nil || !strings.Contains(output, "SHA-256:") {
		t.Fatalf("generate: %v\n%s", err, output)
	}
	if _, err := runCACommand("generate", "--cert", certPath, "--key", keyPath); err == nil {
		t.Fatal("CLI silently replaced existing CA")
	}
	cert, err := localca.ReadCertificate(certPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	output, err = runCACommand("info", "--cert", certPath)
	if err != nil || !strings.Contains(output, "CLI test CA") || !strings.Contains(output, localca.Fingerprint(cert)) {
		t.Fatalf("info required private key or lacked metadata: %v\n%s", err, output)
	}
	output, err = runCACommand("export", "--cert", certPath, "--format", "der")
	if err != nil || !bytes.Equal([]byte(output), cert.Raw) {
		t.Fatalf("DER export: %v", err)
	}
	exportPath := filepath.Join(dir, "ca.mobileconfig")
	_, err = runCACommand("export", "--cert", certPath, "--format", "mobileconfig", "--output", exportPath)
	if err != nil {
		t.Fatal(err)
	}
	profile, err := os.ReadFile(exportPath)
	if err != nil || !bytes.Equal(profile, localca.MobileConfig(cert)) {
		t.Fatalf("profile export: %v", err)
	}
	if _, err := runCACommand("export", "--cert", certPath, "--output", exportPath); err == nil {
		t.Fatal("export overwrote existing file")
	}
	if _, err := runCACommand("export", "--cert", certPath, "--format", "pkcs12"); err == nil {
		t.Fatal("export accepted private-key format")
	}
}

func TestCAEnvironmentDirectoryDefaults(t *testing.T) {
	caDir := filepath.Join(t.TempDir(), "surge")
	t.Setenv("DAE_LOCATION_CACHE", caDir)
	output, err := runCACommand("generate", "--name", "Environment CA", "--valid-days", "1")
	if err != nil {
		t.Fatalf("generate with environment defaults: %v\n%s", err, output)
	}
	certPath, keyPath := localca.ManagedPaths(filepath.Join(caDir, localca.ManagedDirectory))
	if _, err := localca.Load(certPath, keyPath); err != nil {
		t.Fatalf("CA pair was not generated in environment directory: %v", err)
	}
	cert, err := localca.ReadCertificate(certPath)
	if err != nil {
		t.Fatal(err)
	}
	output, err = runCACommand("info")
	if err != nil || !strings.Contains(output, localca.Fingerprint(cert)) {
		t.Fatalf("info did not use environment certificate: %v\n%s", err, output)
	}
	output, err = runCACommand("export")
	if err != nil || !bytes.Equal([]byte(output), localca.CertificatePEM(cert)) {
		t.Fatalf("export did not use environment certificate: %v", err)
	}
}

func TestCAHelpDefaultsDoNotCreateDirectories(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		unset bool
	}{
		{name: "unset", unset: true},
		{name: "empty"},
		{name: "absolute", value: "absolute"},
		{name: "relative", value: "relative-cache"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cwd := t.TempDir()
			t.Chdir(cwd)
			value := test.value
			if value == "absolute" {
				value = filepath.Join(cwd, "absolute-cache")
			}
			t.Setenv("DAE_LOCATION_CACHE", value)
			if test.unset {
				if err := os.Unsetenv("DAE_LOCATION_CACHE"); err != nil {
					t.Fatal(err)
				}
			}
			wantDirectory := value
			if wantDirectory == "" {
				wantDirectory = "/var/lib/dae"
			}
			_, directoryBefore := os.Stat(wantDirectory)
			_, etcBefore := os.Stat("/etc/dae")
			for _, command := range []string{"generate", "info", "export"} {
				output, err := runCACommand(command, "--help")
				if err != nil {
					t.Fatalf("%s help: %v\n%s", command, err, output)
				}
				for _, expected := range []string{
					filepath.Join(wantDirectory, "pki", "ca.pem"),
					filepath.Join(wantDirectory, "pki", "ca.key"),
					"DAE_LOCATION_CACHE or /var/lib/dae",
				} {
					if !strings.Contains(output, expected) {
						t.Errorf("%s help did not show %q:\n%s", command, expected, output)
					}
				}
			}
			for _, entry := range []struct {
				path   string
				before error
			}{{wantDirectory, directoryBefore}, {"/etc/dae", etcBefore}} {
				if _, after := os.Stat(entry.path); os.IsNotExist(entry.before) && !os.IsNotExist(after) {
					t.Errorf("help created %s: %v", entry.path, after)
				}
			}
			if value != "" {
				if _, err := runCACommand("info"); err == nil {
					t.Fatal("info succeeded without a certificate")
				}
				if _, err := os.Stat(wantDirectory); !os.IsNotExist(err) {
					t.Fatalf("info created a missing CA directory: %v", err)
				}
			}
		})
	}
}

func TestCAExplicitPathsOverrideEnvironmentDefaults(t *testing.T) {
	for _, test := range []struct {
		name     string
		certFlag bool
		keyFlag  bool
		absolute bool
	}{
		{name: "relative certificate and key", certFlag: true, keyFlag: true},
		{name: "absolute certificate and key", certFlag: true, keyFlag: true, absolute: true},
		{name: "certificate flag only", certFlag: true},
		{name: "key flag only", keyFlag: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			caDir, cwd := t.TempDir(), t.TempDir()
			t.Setenv("DAE_LOCATION_CACHE", caDir)
			t.Chdir(cwd)
			certPath, keyPath := localca.ManagedPaths(filepath.Join(caDir, localca.ManagedDirectory))
			args := []string{"generate", "--name", "Explicit paths CA", "--valid-days", "1"}
			if test.certFlag {
				flag := "explicit-cert.pem"
				certPath = filepath.Join(cwd, flag)
				if test.absolute {
					flag = certPath
				}
				args = append(args, "--cert", flag)
			}
			if test.keyFlag {
				flag := "explicit-key.pem"
				keyPath = filepath.Join(cwd, flag)
				if test.absolute {
					flag = keyPath
				}
				args = append(args, "--key", flag)
			}
			output, err := runCACommand(args...)
			if test.certFlag != test.keyFlag {
				if err == nil {
					t.Fatal("accepted incomplete explicit paths")
				}
				return
			}
			if err != nil {
				t.Fatalf("explicit path generation: %v\n%s", err, output)
			}
			if _, err := localca.Load(certPath, keyPath); err != nil {
				t.Fatalf("explicit flags were rebased to environment directory: %v", err)
			}
			for _, entry := range []struct {
				explicit    bool
				defaultName string
			}{
				{test.certFlag, "pki/ca.pem"},
				{test.keyFlag, "pki/ca.key"},
			} {
				if entry.explicit {
					if _, err := os.Stat(filepath.Join(caDir, entry.defaultName)); !os.IsNotExist(err) {
						t.Fatalf("explicit flag also generated default %s: %v", entry.defaultName, err)
					}
				}
			}
		})
	}
}
