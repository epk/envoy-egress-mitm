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
	"os"
	"sort"
	"text/tabwriter"
	"time"

	"github.com/epk/envoy-egress-mitm/cfssl"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/pflag"
	"k8s.io/apimachinery/pkg/util/sets"
)

var (
	iterations = pflag.IntP("iterations", "i", 20, "Number of iterations to run")
	printDiff  = pflag.BoolP("print-diff", "p", false, "Print the diff between request success/failure (No Proxy vs HTTPS Proxy)")
	outFile    = pflag.StringP("out-file", "o", "results.csv", "Output file to write results to")

	seedCertificates = pflag.BoolP("seed-certificates", "s", false, "Seed certificates and quit")
)

func main() {
	pflag.Parse()

	domains, err := domainsList()
	if err != nil {
		log.Fatalf("error getting domains: %v\n", err)
	}

	// Hit the TCP proxy first, this will cause the Envoy to mint certificates for all domains
	if *seedCertificates {
		_ = runHTTPTests(newProxyClient(true, nil), domains)
	}

	header := "time,no_proxy,tcp_proxy,https_proxy\n"
	var results []string

	for i := 0; i < *iterations; i++ {
		// Test without Proxy
		noProxy := runHTTPTests(newProxyClient(false, nil), domains)

		// Test with Proxy but without injecting root CA (L4/TCP)
		tcpProxy := runHTTPTests(newProxyClient(true, nil), domains)

		// Test with Proxy and injecting root CA (L7/HTTPS)
		httpsProxy := runHTTPTests(newProxyClient(true, cfssl.CertPool()), domains)

		results = append(results, fmt.Sprintf("%s,%d,%d,%d\n", time.Now().Format("02-Jan-2006 15:04:05"), len(noProxy), len(tcpProxy), len(httpsProxy)))

		if *printDiff {
			fmt.Printf("Iteration %d\n", i+1)
			fmt.Printf("No Proxy: %d\n", len(noProxy))
			fmt.Printf("HTTPS Proxy: %d\n", len(httpsProxy))
			fmt.Printf("diff: \n")

			w := tabwriter.NewWriter(os.Stdout, 1, 1, 1, ' ', tabwriter.AlignRight)
			fmt.Fprintf(w, "Domain\t|No Proxy\t|HTTPS Proxy|\n")

			for _, domain := range getDiff(noProxy, httpsProxy) {
				fmt.Fprintf(w, "%s\t|✅\t|❌|\n", domain)
			}
			w.Flush()

			fmt.Println("")
		}
	}

	_ = os.Remove(*outFile)
	f, err := os.OpenFile(*outFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalf("error opening file: %v\n", err)
	}
	defer f.Close()

	if _, err := f.WriteString(header); err != nil {
		log.Fatalf("error writing to file: %v\n", err)
	}

	for _, result := range results {
		if _, err := f.WriteString(result); err != nil {
			log.Fatalf("error writing to file: %v\n", err)
		}
	}

	fmt.Printf("Results written to %s\n", *outFile)
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

func runHTTPTests(client *http.Client, domains []string) []string {
	p := pool.NewWithResults[string]().WithMaxGoroutines(20)

	for _, domain := range domains {
		domain := domain

		p.Go(func() string {
			resp, err := client.Get(fmt.Sprintf("https://%s", domain))
			if err != nil {
				return ""
			}
			defer resp.Body.Close()
			_, _ = io.Copy(io.Discard, resp.Body)

			if resp.StatusCode == http.StatusOK {
				return domain
			}

			return ""
		})
	}

	result := p.Wait()

	success := []string{}
	for _, domain := range result {
		if domain != "" {
			success = append(success, domain)
		}
	}
	sort.SliceStable(success, func(i, j int) bool {
		return success[i] < success[j]
	})

	return success
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

type Domain struct {
	RootDomain string `json:"rootDomain,omitempty"`
}

func domainsList() ([]string, error) {
	var domains []Domain

	resp, err := http.Get("https://raw.githubusercontent.com/Kikobeats/top-sites/master/top-sites.json")
	if err != nil {
		return []string{}, fmt.Errorf("error getting top domains: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return []string{}, fmt.Errorf("error getting top domains: %v", resp.Status)
	}

	if err := json.NewDecoder(resp.Body).Decode(&domains); err != nil {
		return []string{}, fmt.Errorf("error decoding top domains: %v", err)
	}

	sort.SliceStable(domains, func(i, j int) bool {
		return domains[i].RootDomain < domains[j].RootDomain
	})

	var result []string
	for _, domain := range domains {
		result = append(result, domain.RootDomain)
	}

	return result, nil
}
