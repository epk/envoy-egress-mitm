package builders

import (
	"fmt"

	envoy_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/config/endpoint/v3"
	envoy_dynamic_forward_proxy_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/clusters/dynamic_forward_proxy/v3"
	envoy_extensions_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	envoy_extensions_upstream_http_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/upstreams/http/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"github.com/epk/envoy-egress-mitm/types"
	"github.com/golang/protobuf/ptypes/any"
	"google.golang.org/protobuf/types/known/anypb"
)

func BuildALSCluster() (*envoy_cluster_v3.Cluster, error) {
	httpsOpts := &envoy_extensions_upstream_http_v3.HttpProtocolOptions{
		UpstreamProtocolOptions: &envoy_extensions_upstream_http_v3.HttpProtocolOptions_ExplicitHttpConfig_{
			ExplicitHttpConfig: &envoy_extensions_upstream_http_v3.HttpProtocolOptions_ExplicitHttpConfig{
				ProtocolConfig: &envoy_extensions_upstream_http_v3.HttpProtocolOptions_ExplicitHttpConfig_Http2ProtocolOptions{},
			},
		},
	}

	if err := httpsOpts.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid http protocol options config: %w", err)
	}

	httpsOptsAny, err := anypb.New(httpsOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to convert http protocol options to any: %w", err)
	}

	c := &envoy_cluster_v3.Cluster{
		Name:                 "envoy_access_log_service",
		LbPolicy:             envoy_cluster_v3.Cluster_ROUND_ROBIN,
		ClusterDiscoveryType: &envoy_cluster_v3.Cluster_Type{Type: envoy_cluster_v3.Cluster_LOGICAL_DNS},
		DnsLookupFamily:      envoy_cluster_v3.Cluster_V4_ONLY,
		LoadAssignment: &envoy_endpoint_v3.ClusterLoadAssignment{
			ClusterName: "envoy_access_log_service",
			Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						{
							HostIdentifier: &envoy_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &envoy_endpoint_v3.Endpoint{
									Address: &envoy_core_v3.Address{
										Address: &envoy_core_v3.Address_SocketAddress{
											SocketAddress: &envoy_core_v3.SocketAddress{
												Address: "als_service",
												PortSpecifier: &envoy_core_v3.SocketAddress_PortValue{
													PortValue: 50051,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		TypedExtensionProtocolOptions: map[string]*any.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": httpsOptsAny,
		},
	}

	if err := c.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid cluster config: %w", err)
	}

	return c, nil
}

func BuildDynamicForwardProxyCluster() (*envoy_cluster_v3.Cluster, error) {
	dfpc := envoy_dynamic_forward_proxy_cluster_v3.ClusterConfig{
		DnsCacheConfig:            defaultDNSCacheConfig(),
		AllowCoalescedConnections: true,
	}

	if err := dfpc.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid dynamic forward proxy cluster config: %w", err)
	}

	dfpcAny, err := anypb.New(&dfpc)
	if err != nil {
		return nil, fmt.Errorf("failed to convert dynamic forward proxy cluster to any: %w", err)
	}

	c := &envoy_cluster_v3.Cluster{
		Name:            "dynamic_forward_proxy_cluster",
		LbPolicy:        envoy_cluster_v3.Cluster_CLUSTER_PROVIDED,
		DnsLookupFamily: envoy_cluster_v3.Cluster_V4_ONLY,
		ClusterDiscoveryType: &envoy_cluster_v3.Cluster_ClusterType{
			ClusterType: &envoy_cluster_v3.Cluster_CustomClusterType{
				Name:        "envoy.clusters.dynamic_forward_proxy",
				TypedConfig: dfpcAny,
			},
		},
	}

	if err := c.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid cluster config: %w", err)
	}

	return c, nil
}

func BuildManualUpstream(cert *types.Certificate) (*envoy_cluster_v3.Cluster, error) {
	httpsOpts := &envoy_extensions_upstream_http_v3.HttpProtocolOptions{
		UpstreamProtocolOptions: &envoy_extensions_upstream_http_v3.HttpProtocolOptions_AutoConfig{
			AutoConfig: &envoy_extensions_upstream_http_v3.HttpProtocolOptions_AutoHttpConfig{
				HttpProtocolOptions:  &envoy_core_v3.Http1ProtocolOptions{},
				Http2ProtocolOptions: &envoy_core_v3.Http2ProtocolOptions{},
			},
		},
	}

	if err := httpsOpts.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid http protocol options config: %w", err)
	}

	httpsOptsAny, err := anypb.New(httpsOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to convert http protocol options to any: %w", err)
	}

	tlsConfig := &envoy_extensions_transport_sockets_tls_v3.UpstreamTlsContext{
		CommonTlsContext: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext{
			ValidationContextType: &envoy_extensions_transport_sockets_tls_v3.CommonTlsContext_ValidationContext{
				ValidationContext: &envoy_extensions_transport_sockets_tls_v3.CertificateValidationContext{
					TrustedCa: &envoy_core_v3.DataSource{
						Specifier: &envoy_core_v3.DataSource_Filename{
							Filename: "/etc/ssl/certs/ca-certificates.crt",
						},
					},
				},
			},
		},
	}

	if err := tlsConfig.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid tls config: %w", err)
	}

	tlsConfigAny, err := anypb.New(tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tls config to any: %w", err)
	}

	c := &envoy_cluster_v3.Cluster{
		Name:                 cert.SNI,
		LbPolicy:             envoy_cluster_v3.Cluster_ROUND_ROBIN,
		ClusterDiscoveryType: &envoy_cluster_v3.Cluster_Type{Type: envoy_cluster_v3.Cluster_LOGICAL_DNS},
		DnsLookupFamily:      envoy_cluster_v3.Cluster_V4_ONLY,
		LoadAssignment: &envoy_endpoint_v3.ClusterLoadAssignment{
			ClusterName: cert.SNI,
			Endpoints: []*envoy_endpoint_v3.LocalityLbEndpoints{
				{
					LbEndpoints: []*envoy_endpoint_v3.LbEndpoint{
						{
							HostIdentifier: &envoy_endpoint_v3.LbEndpoint_Endpoint{
								Endpoint: &envoy_endpoint_v3.Endpoint{
									Address: &envoy_core_v3.Address{
										Address: &envoy_core_v3.Address_SocketAddress{
											SocketAddress: &envoy_core_v3.SocketAddress{
												Address: cert.SNI,
												PortSpecifier: &envoy_core_v3.SocketAddress_PortValue{
													PortValue: 443,
												},
											},
										},
									},
								},
							},
						},
					},
				},
			},
		},
		TypedExtensionProtocolOptions: map[string]*any.Any{
			"envoy.extensions.upstreams.http.v3.HttpProtocolOptions": httpsOptsAny,
		},
		TransportSocket: &envoy_core_v3.TransportSocket{
			Name: wellknown.TransportSocketTLS,
			ConfigType: &envoy_core_v3.TransportSocket_TypedConfig{
				TypedConfig: tlsConfigAny,
			},
		},
	}

	if err := c.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid cluster config: %w", err)
	}

	return c, nil
}
