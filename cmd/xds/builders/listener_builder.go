package builders

import (
	"fmt"
	"log"

	envoy_accesslog_v3 "github.com/envoyproxy/go-control-plane/envoy/config/accesslog/v3"
	envoy_core_v3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	envoy_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/config/listener/v3"
	envoy_route_v3 "github.com/envoyproxy/go-control-plane/envoy/config/route/v3"
	envoy_file_access_log_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/file/v3"
	envoy_grpc_access_log_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/access_loggers/grpc/v3"
	envoy_http_router_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/http/router/v3"
	envoy_extensions_filters_listener_tls_inspector_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/listener/tls_inspector/v3"
	envoy_http_connection_manager_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/http_connection_manager/v3"
	envoy_sni_dynamic_forward_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/sni_dynamic_forward_proxy/v3"
	envoy_tcp_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/filters/network/tcp_proxy/v3"
	envoy_transport_sockets_tls_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/transport_sockets/tls/v3"
	"github.com/envoyproxy/go-control-plane/pkg/wellknown"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/epk/envoy-egress-mitm/types"
)

func BuildListener(certs []*types.Certificate) (*envoy_listener_v3.Listener, error) {
	accessLog, err := buildCombinedAccessLog()
	if err != nil {
		return nil, err
	}

	tcpProxy, err := buildTCPProxy(accessLog...)
	if err != nil {
		return nil, err
	}

	sniProxy, err := buildSNIProxy()
	if err != nil {
		return nil, err
	}

	tlsInspector, err := buildTLSInspector()
	if err != nil {
		return nil, err
	}

	lis := &envoy_listener_v3.Listener{
		Name: "listener_0",
		Address: &envoy_core_v3.Address{
			Address: &envoy_core_v3.Address_SocketAddress{
				SocketAddress: &envoy_core_v3.SocketAddress{
					Address: "0.0.0.0",
					PortSpecifier: &envoy_core_v3.SocketAddress_PortValue{
						PortValue: 8443,
					},
					Protocol: envoy_core_v3.SocketAddress_TCP,
				},
			},
		},
		ListenerFilters: []*envoy_listener_v3.ListenerFilter{
			{
				Name: "envoy.filters.listener.tls_inspector",
				ConfigType: &envoy_listener_v3.ListenerFilter_TypedConfig{
					TypedConfig: tlsInspector,
				},
			},
		},
		FilterChains: []*envoy_listener_v3.FilterChain{},
	}

	// Always add sni_dynamic_forward_proxy + tcp_proxy filter chain
	lis.FilterChains = append(lis.FilterChains, &envoy_listener_v3.FilterChain{
		FilterChainMatch: &envoy_listener_v3.FilterChainMatch{
			TransportProtocol: "tls",
		},
		Filters: []*envoy_listener_v3.Filter{
			{
				Name: "envoy.filters.network.sni_dynamic_forward_proxy",
				ConfigType: &envoy_listener_v3.Filter_TypedConfig{
					TypedConfig: sniProxy,
				},
			},
			{
				Name: wellknown.TCPProxy,
				ConfigType: &envoy_listener_v3.Filter_TypedConfig{
					TypedConfig: tcpProxy,
				},
			},
		},
	})

	// Add L7 Filters if we have certs
	// Be really defensive here, if we have certs, but can't build the filter chains, we should not fail
	// the whole listener as we can still proxy the traffic on L4
	if len(certs) > 0 {
		for _, cert := range certs {
			downstreamTLSContext, err := buildDownstreamTLSContext(cert)
			if err != nil {
				log.Println("failed to build downstream TLS context", err)
				continue
			}

			hcm, err := buildHCM(cert.SNI)
			if err != nil {
				log.Println("failed to build HCM", err)
				continue
			}

			lis.FilterChains = append(lis.FilterChains, &envoy_listener_v3.FilterChain{
				FilterChainMatch: &envoy_listener_v3.FilterChainMatch{
					ServerNames: []string{cert.SNI},
				},
				TransportSocket: &envoy_core_v3.TransportSocket{
					Name: wellknown.TransportSocketTLS,
					ConfigType: &envoy_core_v3.TransportSocket_TypedConfig{
						TypedConfig: downstreamTLSContext,
					},
				},
				Filters: []*envoy_listener_v3.Filter{
					{
						Name: wellknown.HTTPConnectionManager,
						ConfigType: &envoy_listener_v3.Filter_TypedConfig{
							TypedConfig: hcm,
						},
					},
				},
			})
		}
	}

	if err := lis.ValidateAll(); err != nil {
		return nil, err
	}
	return lis, nil
}

func buildSNIProxy() (*anypb.Any, error) {
	sniProxy := envoy_sni_dynamic_forward_proxy_v3.FilterConfig{
		DnsCacheConfig: defaultDNSCacheConfig(),
		PortSpecifier: &envoy_sni_dynamic_forward_proxy_v3.FilterConfig_PortValue{
			PortValue: 443,
		},
	}

	if err := sniProxy.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid sni proxy config: %w", err)
	}

	sniProxyAny, err := anypb.New(&sniProxy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert sni proxy to any: %w", err)
	}

	return sniProxyAny, nil
}

func buildTCPProxy(logSinks ...*envoy_accesslog_v3.AccessLog) (*anypb.Any, error) {
	tcpProxy := envoy_tcp_proxy_v3.TcpProxy{
		StatPrefix: "tcp_ingress",
		ClusterSpecifier: &envoy_tcp_proxy_v3.TcpProxy_Cluster{
			Cluster: "dynamic_forward_proxy_cluster",
		},
		AccessLog: logSinks,
	}

	if err := tcpProxy.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid tcp proxy config: %w", err)
	}

	tcpProxyAny, err := anypb.New(&tcpProxy)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tcp proxy to any: %w", err)
	}

	return tcpProxyAny, nil
}

func buildCombinedAccessLog() ([]*envoy_accesslog_v3.AccessLog, error) {
	fileAccessLog, err := buildFileAccessLog()
	if err != nil {
		return nil, fmt.Errorf("failed to build file access log: %w", err)
	}

	grpcAccessLog, err := buildGRPCAccessLog()
	if err != nil {
		return nil, fmt.Errorf("failed to build grpc access log: %w", err)
	}

	return []*envoy_accesslog_v3.AccessLog{
		{
			Name: wellknown.FileAccessLog,
			ConfigType: &envoy_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: fileAccessLog,
			},
		},
		{
			Name: "envoy.access_loggers.tcp_grpc",
			ConfigType: &envoy_accesslog_v3.AccessLog_TypedConfig{
				TypedConfig: grpcAccessLog,
			},
		},
	}, nil
}

func buildGRPCAccessLog() (*anypb.Any, error) {
	grpcAccessLog := envoy_grpc_access_log_v3.TcpGrpcAccessLogConfig{
		CommonConfig: &envoy_grpc_access_log_v3.CommonGrpcAccessLogConfig{
			LogName:             "tcp_ingress",
			TransportApiVersion: envoy_core_v3.ApiVersion_V3,
			GrpcService: &envoy_core_v3.GrpcService{
				TargetSpecifier: &envoy_core_v3.GrpcService_EnvoyGrpc_{
					EnvoyGrpc: &envoy_core_v3.GrpcService_EnvoyGrpc{
						ClusterName: "envoy_access_log_service",
					},
				},
			},
		},
	}

	if err := grpcAccessLog.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid grpc access log config: %w", err)
	}

	grpcAccessLogAny, err := anypb.New(&grpcAccessLog)
	if err != nil {
		return nil, fmt.Errorf("failed to convert grpc access log to any: %w", err)
	}

	return grpcAccessLogAny, nil
}

func buildFileAccessLog() (*anypb.Any, error) {
	fileAccessLog := envoy_file_access_log_v3.FileAccessLog{
		Path: "/dev/stdout",
	}

	if err := fileAccessLog.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid file access log config: %w", err)
	}

	fileAccessLogAny, err := anypb.New(&fileAccessLog)
	if err != nil {
		return nil, fmt.Errorf("failed to convert file access log to any: %w", err)
	}

	return fileAccessLogAny, nil
}

func buildDownstreamTLSContext(cert *types.Certificate) (*anypb.Any, error) {
	cfg := &envoy_transport_sockets_tls_v3.DownstreamTlsContext{
		CommonTlsContext: &envoy_transport_sockets_tls_v3.CommonTlsContext{
			AlpnProtocols: []string{"h2,http/1.1"},
			TlsCertificateSdsSecretConfigs: []*envoy_transport_sockets_tls_v3.SdsSecretConfig{
				{
					Name: cert.SNI,
					SdsConfig: &envoy_core_v3.ConfigSource{
						ResourceApiVersion: envoy_core_v3.ApiVersion_V3,
						ConfigSourceSpecifier: &envoy_core_v3.ConfigSource_Ads{
							Ads: &envoy_core_v3.AggregatedConfigSource{},
						},
					},
				},
			},
		},
	}

	if err := cfg.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid tls context config: %w", err)
	}

	cfgAny, err := anypb.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tls context to any: %w", err)
	}

	return cfgAny, nil
}

func buildHCM(domain string) (*anypb.Any, error) {
	httpRouter, err := buildHTTPRouter()
	if err != nil {
		return nil, fmt.Errorf("failed to build http router: %w", err)
	}

	accesslog, err := buildFileAccessLog()
	if err != nil {
		return nil, fmt.Errorf("failed to build access log: %w", err)
	}

	hcm := envoy_http_connection_manager_v3.HttpConnectionManager{
		StatPrefix: domain,
		CodecType:  envoy_http_connection_manager_v3.HttpConnectionManager_AUTO,
		UpgradeConfigs: []*envoy_http_connection_manager_v3.HttpConnectionManager_UpgradeConfig{
			{
				Enabled:     wrapperspb.Bool(true),
				UpgradeType: "websocket",
			},
		},
		AccessLog: []*envoy_accesslog_v3.AccessLog{
			{
				Name: wellknown.FileAccessLog,
				ConfigType: &envoy_accesslog_v3.AccessLog_TypedConfig{
					TypedConfig: accesslog,
				},
			},
		},
		HttpFilters: []*envoy_http_connection_manager_v3.HttpFilter{
			{
				Name: wellknown.Router,
				ConfigType: &envoy_http_connection_manager_v3.HttpFilter_TypedConfig{
					TypedConfig: httpRouter,
				},
			},
		},
		RouteSpecifier: &envoy_http_connection_manager_v3.HttpConnectionManager_RouteConfig{
			RouteConfig: &envoy_route_v3.RouteConfiguration{
				Name: domain,
				VirtualHosts: []*envoy_route_v3.VirtualHost{
					{
						Name:    domain,
						Domains: []string{domain},
						Routes: []*envoy_route_v3.Route{
							{
								Match: &envoy_route_v3.RouteMatch{
									PathSpecifier: &envoy_route_v3.RouteMatch_Prefix{
										Prefix: "/",
									},
								},
								Action: &envoy_route_v3.Route_Route{
									Route: &envoy_route_v3.RouteAction{
										RetryPolicy: &envoy_route_v3.RetryPolicy{
											RetryOn: "reset",
										},
										ClusterSpecifier: &envoy_route_v3.RouteAction_Cluster{
											Cluster: domain,
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	if err := hcm.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid http connection manager config: %w", err)
	}

	hcmAny, err := anypb.New(&hcm)
	if err != nil {
		return nil, fmt.Errorf("failed to convert http connection manager to any: %w", err)
	}

	return hcmAny, nil
}

func buildHTTPRouter() (*anypb.Any, error) {
	router := envoy_http_router_v3.Router{
		StartChildSpan: true,
	}

	if err := router.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid http router config: %w", err)
	}

	routerAny, err := anypb.New(&router)
	if err != nil {
		return nil, fmt.Errorf("failed to convert http router to any: %w", err)
	}

	return routerAny, nil
}

func buildTLSInspector() (*anypb.Any, error) {
	cfg := &envoy_extensions_filters_listener_tls_inspector_v3.TlsInspector{}

	if err := cfg.ValidateAll(); err != nil {
		return nil, fmt.Errorf("invalid tls inspector config: %w", err)
	}

	cfgAny, err := anypb.New(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to convert tls inspector to any: %w", err)
	}

	return cfgAny, nil
}
