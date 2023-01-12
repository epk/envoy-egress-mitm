package builders

import (
	envoy_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/config/cluster/v3"
	envoy_dynamic_forward_proxy_v3 "github.com/envoyproxy/go-control-plane/envoy/extensions/common/dynamic_forward_proxy/v3"
)

func defaultDNSCacheConfig() *envoy_dynamic_forward_proxy_v3.DnsCacheConfig {
	return &envoy_dynamic_forward_proxy_v3.DnsCacheConfig{
		Name:            "dynamic_forward_proxy_cache_config",
		DnsLookupFamily: envoy_cluster_v3.Cluster_V4_ONLY,
	}
}
