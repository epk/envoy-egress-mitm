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

	"github.com/epk/envoy-egress-mitm/cfssl"
	"github.com/epk/envoy-egress-mitm/types"
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
	outFile := filepath.Join(certsDir, sni+".json")

	// check if a cert already exists
	if _, err := os.Stat(outFile); err == nil {
		return nil
	}

	// create the cert
	log.Println("Creating cert for", sni, "at", outFile)

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

	cert := filepath.Join(tmpDir, "cert.pem")
	certKey := filepath.Join(tmpDir, "cert-key.pem")

	certBytes, err := os.ReadFile(cert)
	if err != nil {
		return fmt.Errorf("error reading certificate file: %w", err)
	}

	keyBytes, err := os.ReadFile(certKey)
	if err != nil {
		return fmt.Errorf("error reading certificate key file: %w", err)
	}

	out := &types.Certificate{
		Cert: certBytes,
		Key:  keyBytes,
		SNI:  sni,

		CAName: fmt.Sprintf("intermediate-ca-%s", sni),
		CA:     cfssl.CA,
	}

	raw, err := json.Marshal(out)
	if err != nil {
		return fmt.Errorf("error marshalling json  : %w", err)
	}

	if err := os.WriteFile(outFile, raw, 0644); err != nil {
		return fmt.Errorf("error writing json to file: %w", err)
	}

	defer os.RemoveAll(tmpDir)
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
