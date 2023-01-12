package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sort"
	"time"

	"github.com/epk/envoy-egress-mitm/cfssl"
	"github.com/sourcegraph/conc/pool"
	"k8s.io/apimachinery/pkg/util/sets"
)

const topDomainsURL = "https://raw.githubusercontent.com/Kikobeats/top-sites/master/top-sites.json"

type Domain struct {
	RootDomain string `json:"rootDomain,omitempty"`
}

func main() {
	certPool := x509.NewCertPool()
	certPool.AppendCertsFromPEM(cfssl.CA)

	var domains []Domain
	resp, err := http.Get(topDomainsURL)
	if err != nil {
		log.Fatal(fmt.Errorf("error getting top domains: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		log.Fatal(fmt.Errorf("error getting top domains: %v", resp.Status))
	}

	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		log.Fatal(fmt.Errorf("error decoding top domains: %v", err))
	}

	sort.SliceStable(domains, func(i, j int) bool {
		return domains[i].RootDomain < domains[j].RootDomain
	})

	// log.Println("Starting test run....")
	// log.Println("Total domains:", len(domains))

	// Test without Proxy
	successfulDomains := runHTTPTests(newProxyClient(false, nil), domains)

	// Test with Proxy but without injecting root CA
	// tcpProxysuccessfulDomains := runHTTPTests(newProxyClient(true, nil), domains)
	// log.Println("Successful 200 OK(s) with TCP/L4 proxy", len(tcpProxysuccessfulDomains))

	// log.Println("Sleeping for 2 minutes to allow for Envoy to pick up new config changes...")
	// time.Sleep(2 * time.Minute)

	// Test with Proxy and injecting root CA
	httpsProxysuccessfulDomains := runHTTPTests(newProxyClient(true, certPool), domains)

	fmt.Printf("%d,%d\n", len(successfulDomains), len(httpsProxysuccessfulDomains))

	// Print difference between no proxy and TCP proxy
	// log.Println("Domains that failed with TCP proxy but succeeded without proxy:")
	// log.Println(getDiff(successfulDomains, tcpProxysuccessfulDomains))

	// // Print difference between no proxy and HTTPS proxy
	// log.Println("Domains that failed with HTTPS proxy but succeeded without proxy:")
	// log.Println(getDiff(successfulDomains, httpsProxysuccessfulDomains))
}

func getDiff(a, b []string) []string {
	aSet := sets.New(a...)
	bSet := sets.New(b...)

	diff := aSet.Difference(bSet).UnsortedList()

	sort.SliceStable(diff, func(i, j int) bool {
		return diff[i] < diff[j]
	})

	return diff
}

func runHTTPTests(client *http.Client, domains []Domain) []string {
	p := pool.NewWithResults[string]().WithMaxGoroutines(50)

	for _, domain := range domains {
		domain := domain

		p.Go(func() string {
			resp, err := client.Get(fmt.Sprintf("https://%s", domain.RootDomain))
			if err != nil {
				return ""
			}
			defer resp.Body.Close()

			// discard response body to avoid leaking connections
			_, _ = io.Copy(io.Discard, resp.Body)
			// log.Printf("[L4/TCP] Response from %s: %v\n", domain.RootDomain, resp.Status)

			if resp.StatusCode == http.StatusOK {
				return domain.RootDomain
			}

			return ""
		})
	}

	result := p.Wait()
	successfulDomains := []string{}
	for _, domain := range result {
		if domain != "" {
			successfulDomains = append(successfulDomains, domain)
		}
	}
	sort.SliceStable(successfulDomains, func(i, j int) bool {
		return successfulDomains[i] < successfulDomains[j]
	})

	return successfulDomains
}

// When proxy is true and pool is nil
// Equivalent to: curl https://www.reddit.com --connect-to www.reddit.com:443:0.0.0.0:8443
// When proxy is true and pool is not nil
// Equivalent to: curl https://www.reddit.com --cacert cfssl/ca.pem --connect-to www.reddit.com:443:
// Otherwise just a regular http client with sane timeouts
func newProxyClient(proxy bool, pool *x509.CertPool) *http.Client {
	contextDialer := func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := &net.Dialer{
			Timeout:   1 * time.Second,
			KeepAlive: 30 * time.Second,
		}

		return dialer.DialContext(ctx, network, "0.0.0.0:8443")
	}

	transport := &http.Transport{
		ResponseHeaderTimeout: time.Second * 1,
		ExpectContinueTimeout: time.Second * 1,
	}

	if proxy {
		transport.DialContext = contextDialer
	}

	if pool != nil {
		transport.TLSClientConfig = &tls.Config{
			RootCAs: pool,
		}
	}

	return &http.Client{
		Transport: transport,
		Timeout:   time.Second * 1,
	}
}
