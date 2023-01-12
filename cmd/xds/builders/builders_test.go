package builders_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"gopkg.in/yaml.v2"

	"github.com/epk/envoy-egress-mitm/cmd/xds/builders"
	"github.com/epk/envoy-egress-mitm/types"
)

func TestFixtures(t *testing.T) {

	t.Run("listener-tcp-l4-only", func(t *testing.T) {
		got, err := builders.BuildListener([]*types.Certificate{})
		if err != nil {
			t.Fatal(err)
		}

		assertFixture(t, got)
	})

	t.Run("listener-single-l7-and-tcp-l4", func(t *testing.T) {
		got, err := builders.BuildListener(
			[]*types.Certificate{
				{
					SNI:    "example.com",
					Cert:   []byte("cert"),
					Key:    []byte("key"),
					CAName: "my custom CA",
					CA:     []byte("ca"),
				},
			})
		if err != nil {
			t.Fatal(err)
		}

		assertFixture(t, got)
	})

	t.Run("listener-multiple-l7-and-tcp-l4", func(t *testing.T) {
		got, err := builders.BuildListener(
			[]*types.Certificate{
				{
					SNI:    "example.com",
					Cert:   []byte("cert"),
					Key:    []byte("key"),
					CAName: "my custom CA",
					CA:     []byte("ca"),
				},
				{
					SNI:    "example2.com",
					Cert:   []byte("cert2"),
					Key:    []byte("key2"),
					CAName: "my custom CA2",
					CA:     []byte("ca 2"),
				},
			})
		if err != nil {
			t.Fatal(err)
		}

		assertFixture(t, got)
	})

	t.Run("als-cluster", func(t *testing.T) {
		got, err := builders.BuildALSCluster()
		if err != nil {
			t.Fatal(err)
		}

		assertFixture(t, got)
	})

	t.Run("dynamic-forward-proxy-cluster", func(t *testing.T) {
		got, err := builders.BuildDynamicForwardProxyCluster()
		if err != nil {
			t.Fatal(err)
		}

		assertFixture(t, got)
	})

	t.Run("secret", func(t *testing.T) {
		got, err := builders.BuildSecret(&types.Certificate{
			SNI:    "example.com",
			Cert:   []byte("cert"),
			Key:    []byte("key"),
			CAName: "my custom CA",
			CA:     []byte("ca"),
		})

		if err != nil {
			t.Fatal(err)
		}

		assertFixture(t, got)
	})

	t.Run("validation-secret", func(t *testing.T) {
		got, err := builders.BuildValidationContextSecret(&types.Certificate{
			SNI:    "example.com",
			Cert:   []byte("cert"),
			Key:    []byte("key"),
			CAName: "my custom CA",
			CA:     []byte("ca"),
		})

		if err != nil {
			t.Fatal(err)
		}

		assertFixture(t, got)
	})

	t.Run("manual-upstream-cluster", func(t *testing.T) {
		got, err := builders.BuildManualUpstream(&types.Certificate{
			SNI:    "example.com",
			Cert:   []byte("cert"),
			Key:    []byte("key"),
			CAName: "my custom CA",
			CA:     []byte("ca"),
		})

		if err != nil {
			t.Fatal(err)
		}

		assertFixture(t, got)
	})
}

func assertFixture(t *testing.T, in proto.Message) {
	t.Helper()

	_, updateFixtures := os.LookupEnv("UPDATE_FIXTURES")
	got := protoYaml(t, in)
	fixturePath := filepath.Join("testdata", t.Name()+".yaml")

	want, err := os.ReadFile(fixturePath)
	if err != nil {
		if os.IsNotExist(err) {
			want = []byte{}
		} else {
			t.Fatal(err)
		}
	}

	if !cmp.Equal(want, got) {
		if updateFixtures {
			err := os.WriteFile(fixturePath, got, 0644)
			if err != nil {
				t.Fatal(err)
			}

		} else {
			t.Fatalf(cmp.Diff(string(want), string(got)))
		}
	}
}

// protoYaml converts a protobuf message to YAML.
// protobuf messages are not guaranteed to be marshalled to YAML in a deterministic way.
// proto -> json blob -> interface{} -> yaml blob
func protoYaml(t *testing.T, m proto.Message) []byte {
	t.Helper()

	bytes, err := protojson.MarshalOptions{
		AllowPartial:  true,
		UseProtoNames: true,
	}.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}

	var v interface{}
	err = json.Unmarshal(bytes, &v)
	if err != nil {
		t.Fatal(err)
	}

	bytes, err = yaml.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return bytes
}
