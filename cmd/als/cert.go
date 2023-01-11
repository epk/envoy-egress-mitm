package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

const (
	certsDir       = "/app/certs"
	cfsslConfigDir = "/app/cfssl"
	binDir         = "/app/bin"
)

type certConfig struct {
	CN   string         `json:"CN"`
	Key  *certConfigkey `json:"key"`
	Host []string       `json:"hosts"`
}

type certConfigkey struct {
	Algo string `json:"algo"`
	Size int    `json:"size"`
}

func createCert(sni string) error {
	crtFile := filepath.Join(certsDir, sni, "cert.crt")
	keyFile := filepath.Join(certsDir, sni, "cert.key")

	// check if a cert already exists
	if _, err := os.Stat(crtFile); err == nil {
		if _, err := os.Stat(keyFile); err == nil {
			log.Println("Cert already exists for", sni)
			return nil
		}
	}

	// create the cert
	log.Println("Creating cert for", sni, "at", crtFile, "and", keyFile)

	err := os.MkdirAll(filepath.Join(certsDir, sni), 0755)
	if err != nil {
		return fmt.Errorf("error creating cert dir: %w", err)
	}

	tmpDir, err := os.MkdirTemp("", sni)
	if err != nil {
		return fmt.Errorf("error creating temp dir: %w", err)
	}

	certConfigbytes, err := json.Marshal(certConfigFor(sni))
	if err != nil {
		return fmt.Errorf("error marshalling cert config: %w", err)
	}

	certConfigFile := filepath.Join(tmpDir, "cert.json")
	if err := os.WriteFile(certConfigFile, certConfigbytes, 0644); err != nil {
		return fmt.Errorf("error writing cert config: %w", err)
	}

	cfsslOut := bytes.NewBuffer(nil)

	cfsslCmd := &exec.Cmd{
		Dir:  tmpDir,
		Path: filepath.Join(binDir, "cfssl"),
		Args: []string{
			"cfssl",
			"gencert",
			"-ca", filepath.Join(cfsslConfigDir, "intermediate-ca.crt"),
			"-ca-key", filepath.Join(cfsslConfigDir, "intermediate-ca.key"),
			"-config", filepath.Join(cfsslConfigDir, "cfssl.json"),
			"-profile", "certificate",
			certConfigFile,
		},
		Stdout: cfsslOut,
		Stderr: io.Discard,
	}

	cfssljsonCmd := &exec.Cmd{
		Dir:  tmpDir,
		Path: filepath.Join(binDir, "cfssljson"),
		Args: []string{
			"cfssljson",
			"-bare",
			"cert",
		},
		Stdin:  cfsslOut,
		Stderr: io.Discard,
	}

	if err := cfsslCmd.Run(); err != nil {
		return fmt.Errorf("cfssl failed: %w", err)
	}

	if err := cfssljsonCmd.Run(); err != nil {
		return fmt.Errorf("cfssljson failed: %w", err)
	}

	// Copy the cert and key to the correct location
	cert := filepath.Join(tmpDir, "cert.pem")
	if err := copyFile(cert, crtFile); err != nil {
		return fmt.Errorf("error copying cert: %w", err)
	}

	// Copy the cert and key to the correct location
	certKey := filepath.Join(tmpDir, "cert-key.pem")
	if err := copyFile(certKey, keyFile); err != nil {
		return fmt.Errorf("error copying key: %w", err)
	}

	defer os.RemoveAll(tmpDir)
	return nil
}

func copyFile(src, dst string) error {
	if in, err := os.Open(src); err == nil {
		defer in.Close()

		out, err := os.Create(dst)
		if err != nil {
			return fmt.Errorf("error creating key file: %w", err)
		}

		if _, err := io.Copy(out, in); err != nil {
			return fmt.Errorf("error copying key: %w", err)
		}

		if err := out.Close(); err != nil {
			return fmt.Errorf("error closing key file: %w", err)
		}
	}

	return nil
}

func certConfigFor(sni string) *certConfig {
	return &certConfig{
		CN: sni,
		Key: &certConfigkey{
			Algo: "rsa",
			Size: 2048,
		},
		Host: []string{sni},
	}
}
