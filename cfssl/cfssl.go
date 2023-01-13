package cfssl

import (
	"crypto/x509"
	_ "embed"
)

//go:embed combined.crt
var ca []byte

func CertPool() *x509.CertPool {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(ca)
	return certPool
}
