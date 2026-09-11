// SPDX-License-Identifier: AGPL-3.0-only

package cmd

import (
	"crypto/x509"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/daeuniverse/dae/component/mitm/ca"
	"github.com/daeuniverse/dae/component/plugin"
	"github.com/spf13/cobra"
)

func newMITMCommand(definitions map[string]plugin.Definition, services plugin.CommandServices) *cobra.Command {
	var certPath, keyPath string
	mitm := &cobra.Command{Use: "mitm", Short: "Manage MITM certificates, plugins and status."}
	ca := &cobra.Command{Use: "ca", Short: "Generate, inspect and export the local MITM CA."}
	caDir := cacheDirectory()
	ca.PersistentFlags().StringVar(&certPath, "cert", filepath.Join(caDir, "mitm-ca.pem"), "CA certificate path (PEM or DER); default directory: DAE_LOCATION_CACHE or /var/lib/dae")
	ca.PersistentFlags().StringVar(&keyPath, "key", filepath.Join(caDir, "mitm-ca.key"), "CA private key path (PEM); default directory: DAE_LOCATION_CACHE or /var/lib/dae")
	mitm.AddCommand(ca)

	var commonName string
	var validDays int
	generate := &cobra.Command{
		Use: "generate", Short: "Create a CA without overwriting existing files.", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if validDays < 1 || validDays > 36500 {
				return fmt.Errorf("--valid-days must be between 1 and 36500")
			}
			if err := mitmca.Generate(certPath, keyPath, commonName, time.Duration(validDays)*24*time.Hour); err != nil {
				return err
			}
			cert, err := mitmca.ReadCertificate(certPath)
			if err != nil {
				return err
			}
			cmd.Printf("Created CA certificate: %s\nPrivate key: %s (keep on the dae host)\n", certPath, keyPath)
			return printMITMCAInfo(cmd.OutOrStdout(), cert)
		},
	}
	generate.Flags().StringVar(&commonName, "name", "dae MITM CA", "CA display name")
	generate.Flags().IntVar(&validDays, "valid-days", 3650, "CA validity in days")
	ca.AddCommand(generate)
	ca.AddCommand(&cobra.Command{
		Use: "info", Short: "Inspect the public CA and its SHA-256 fingerprint.", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cert, err := mitmca.ReadCertificate(certPath)
			if err != nil {
				return err
			}
			return printMITMCAInfo(cmd.OutOrStdout(), cert)
		},
	})
	var format, output string
	export := &cobra.Command{
		Use: "export", Short: "Export the public CA as PEM, DER or an iOS profile.", Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cert, err := mitmca.ReadCertificate(certPath)
			if err != nil {
				return err
			}
			var data []byte
			switch format {
			case "pem":
				data = mitmca.CertificatePEM(cert)
			case "der":
				data = cert.Raw
			case "mobileconfig":
				data = mitmca.MobileConfig(cert)
			default:
				return fmt.Errorf("unknown format %q (use pem, der or mobileconfig)", format)
			}
			if output == "-" {
				_, err = cmd.OutOrStdout().Write(data)
				return err
			}
			f, err := os.OpenFile(output, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
			if err != nil {
				return err
			}
			_, err = f.Write(data)
			if closeErr := f.Close(); err == nil {
				err = closeErr
			}
			if err != nil {
				_ = os.Remove(output)
			}
			return err
		},
	}
	export.Flags().StringVar(&format, "format", "pem", "export format: pem, der, mobileconfig")
	export.Flags().StringVarP(&output, "output", "o", "-", "new output file, or - for stdout")
	ca.AddCommand(export)
	addMITMCommands(mitm, definitions, services)
	return mitm
}

func printMITMCAInfo(w io.Writer, cert *x509.Certificate) error {
	status := "valid"
	now := time.Now()
	if now.Before(cert.NotBefore) {
		status = "not yet valid"
	} else if !now.Before(cert.NotAfter) {
		status = "expired"
	}
	_, err := fmt.Fprintf(w, "Name: %s\nSerial: %s\nNot before: %s\nNot after: %s\nStatus: %s\nSHA-256: %s\n",
		cert.Subject.CommonName, cert.SerialNumber.Text(16), cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339), status, mitmca.Fingerprint(cert))
	return err
}
