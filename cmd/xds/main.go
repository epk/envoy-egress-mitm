package main

import (
	"context"
	"log"
	"net"

	"google.golang.org/grpc"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"

	envoy_service_cluster_v3 "github.com/envoyproxy/go-control-plane/envoy/service/cluster/v3"
	envoy_service_discovery_v3 "github.com/envoyproxy/go-control-plane/envoy/service/discovery/v3"
	envoy_service_endpoint_v3 "github.com/envoyproxy/go-control-plane/envoy/service/endpoint/v3"
	envoy_service_listener_v3 "github.com/envoyproxy/go-control-plane/envoy/service/listener/v3"
	envoy_service_route_v3 "github.com/envoyproxy/go-control-plane/envoy/service/route/v3"
	envoy_service_runtime_v3 "github.com/envoyproxy/go-control-plane/envoy/service/runtime/v3"
	envoy_service_secret_v3 "github.com/envoyproxy/go-control-plane/envoy/service/secret/v3"
	envoy_cache_v3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"
	envoy_server_v3 "github.com/envoyproxy/go-control-plane/pkg/server/v3"

	"github.com/epk/envoy-egress-mitm/cmd/xds/certstore"
	"github.com/epk/envoy-egress-mitm/cmd/xds/reconciler"
)

const (
	certsDir = "/app/certs"
)

func main() {
	ctx := context.Background()

	// Create cache
	cache := envoy_cache_v3.NewSnapshotCache(true, envoy_cache_v3.IDHash{}, nil)

	store := certstore.NewConfigStore(certsDir)

	go func() {
		updateCh, err := store.StartWatcher()

		if err != nil {
			log.Fatal(err)
		}

		for {
			select {
			case <-ctx.Done(): // superficial
				return
			case <-updateCh:
				err := reconciler.Reconcile(ctx, cache, store.List())
				if err != nil {
					log.Println("Error reconciling: ", err)
				}
			}
		}
	}()

	// Perform initial snapshot update
	err := reconciler.Reconcile(ctx, cache, nil)
	if err != nil {
		log.Fatal(err)
	}

	// Create gRPC server
	srv := grpc.NewServer()
	// Register gRPC healthcheck
	grpc_health_v1.RegisterHealthServer(srv, health.NewServer())

	// Create xDS server
	srv3 := envoy_server_v3.NewServer(ctx, cache, envoy_server_v3.CallbackFuncs{})
	// Register services
	envoy_service_discovery_v3.RegisterAggregatedDiscoveryServiceServer(srv, srv3)
	envoy_service_secret_v3.RegisterSecretDiscoveryServiceServer(srv, srv3)
	envoy_service_cluster_v3.RegisterClusterDiscoveryServiceServer(srv, srv3)
	envoy_service_endpoint_v3.RegisterEndpointDiscoveryServiceServer(srv, srv3)
	envoy_service_listener_v3.RegisterListenerDiscoveryServiceServer(srv, srv3)
	envoy_service_route_v3.RegisterRouteDiscoveryServiceServer(srv, srv3)
	envoy_service_runtime_v3.RegisterRuntimeDiscoveryServiceServer(srv, srv3)

	lis, err := net.Listen("tcp", ":50051")
	if err != nil {
		log.Fatal(err)
	}

	log.Println("Starting server")
	if err := srv.Serve(lis); err != nil {
		log.Fatal(err)
	}
}
