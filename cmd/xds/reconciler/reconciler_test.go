package reconciler

import (
	"context"
	"testing"

	envoy_cache_v3 "github.com/envoyproxy/go-control-plane/pkg/cache/v3"

	"github.com/epk/envoy-egress-mitm/types"
)

func TestReconcile(t *testing.T) {
	cache := envoy_cache_v3.NewSnapshotCache(false, envoy_cache_v3.IDHash{}, nil)
	certs := []*types.Certificate{
		{
			SNI:  "example.com",
			Cert: []byte("cert"),
			Key:  []byte("key"),
		},
	}

	err := Reconcile(context.Background(), cache, certs)
	if err != nil {
		t.Fatal(err)
	}
}
