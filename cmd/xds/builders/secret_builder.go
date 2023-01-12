package builders

import (
	envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"

	"github.com/epk/envoy-egress-mitm/types"
)

func BuildSecret(cert *types.Certificate) (*envoy_extensions_transport_sockets_tls_v3.Secret, error) {
	c := &envoy_extensions_transport_sockets_tls_v3.Secret{
		Name: cert.SNI,
		Type: &envoy_extensions_transport_sockets_tls_v3.Secret_TlsCertificate{
			TlsCertificate: &envoy_extensions_transport_sockets_tls_v3.TlsCertificate{
				CertificateChain: &envoy_core_v3.DataSource{
					Specifier: &envoy_core_v3.DataSource_InlineBytes{
						InlineBytes: cert.Cert,
					},
				},
				PrivateKey: &envoy_core_v3.DataSource{
					Specifier: &envoy_core_v3.DataSource_InlineBytes{
						InlineBytes: cert.Key,
					},
				},
			},
		},
	}

	if err := c.Validate(); err != nil {
		return nil, err
	}

	return c, nil
}
