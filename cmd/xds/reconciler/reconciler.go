package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"time"

	envoy_types "github.com/envoyproxy/go-control-plane/pkg/cache/types"
	envoy_cache_v3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_resource_v3 "github.com/envoyproxy/go-control-plane/pkg/resource/v3"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gopkg.in/yaml.v2"

	"github.com/epk/envoy-egress-mitm/cmd/xds/builders"
	"github.com/epk/envoy-egress-mitm/types"
)

func Reconcile(ctx context.Context, cache envoy_cache_v3.SnapshotCache, certs []*types.Certificate) error {
	alsCluster, err := builders.BuildALSCluster()
	if err != nil {
		return fmt.Errorf("failed to build ALS cluster: %w", err)
	}

	dynamicForwardProxyCluster, err := builders.BuildDynamicForwardProxyCluster()
	if err != nil {
		return fmt.Errorf("failed to build dynamic forward proxy cluster: %w", err)
	}

	listener, err := builders.BuildListener(certs)
	if err != nil {
		return fmt.Errorf("failed to build listener: %w", err)
	}

	var clusters []envoy_types.Resource
	clusters = append(clusters, alsCluster, dynamicForwardProxyCluster)

	var secrets []envoy_types.Resource
	for _, cert := range certs {
		secret, err := builders.BuildSecret(cert)
		if err != nil {
			return fmt.Errorf("failed to build secret: %w", err)
		}
		secrets = append(secrets, secret)

		validationSecret, err := builders.BuildValidationContextSecret(cert)
		if err != nil {
			return fmt.Errorf("failed to build validation secret: %w", err)
		}
		secrets = append(secrets, validationSecret)

		cluster, err := builders.BuildManualUpstream(cert)
		if err != nil {
			return fmt.Errorf("failed to build manual upstream cluster: %w", err)
		}

		clusters = append(clusters, cluster)
	}

	snap, err := envoy_cache_v3.NewSnapshot(time.Now().String(), map[envoy_resource_v3.Type][]envoy_types.Resource{
		envoy_resource_v3.ClusterType:  clusters,
		envoy_resource_v3.ListenerType: {listener},
		envoy_resource_v3.SecretType:   secrets,
	})
	if err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}

	if err := snap.Consistent(); err != nil {
		return fmt.Errorf("inconsistent snapshot: %w", err)
	}

	if err := cache.SetSnapshot(ctx, "default", snap); err != nil {
		return fmt.Errorf("failed to set snapshot: %w", err)
	}

	log.Println("snapshot updated")
	return nil
}

func protoYaml(m proto.Message) ([]byte, error) {
	bytes, err := protojson.MarshalOptions{
		AllowPartial:  true,
		UseProtoNames: true,
	}.Marshal(m)
	if err != nil {
		return nil, err
	}

	var v interface{}
	err = json.Unmarshal(bytes, &v)
	if err != nil {
		return nil, err
	}

	bytes, err = yaml.Marshal(v)
	if err != nil {
		return nil, err
	}

	return bytes, nil
}
