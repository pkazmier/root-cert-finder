package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/alecthomas/kong"
	"github.com/fatih/color"
)

var cli struct {
	Timeout    time.Duration `short:"t" help:"connection timeout" default:"2s"`
	NumWorkers int           `short:"n" help:"number of concurrent workers" default:"100"`
}

type Result struct {
	root   *x509.Certificate
	domain string
	err    error
}

var (
	red           = color.New(color.FgRed).SprintFunc()
	errEarlyAbort = fmt.Errorf("closing connection early")
)

func main() {
	log.SetOutput(os.Stderr)
	kong.Parse(&cli,
		kong.Name("rootcert"),
		kong.Description("Find the root certificate for one or more domains."),
		kong.UsageOnError(),
	)

	var wg sync.WaitGroup
	domainChannel := make(chan string)
	resultChannel := make(chan Result)

	// Start workers
	for i := 0; i < cli.NumWorkers; i++ {
		wg.Add(1)
		go worker(domainChannel, resultChannel, &wg)
	}

	// Read from domains from stdin
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			domain := scanner.Text()
			if domain != "" {
				domainChannel <- scanner.Text()
			}
		}
		close(domainChannel)
	}()

	// Clean up
	go func() {
		wg.Wait()
		close(resultChannel)
	}()

	// Collect results
	counts := make(map[string]int)
	for result := range resultChannel {
		if result.err != nil {
			errMsg := red("Error: " + result.err.Error())
			log.Printf("%30s --> %s\n", result.domain, errMsg)
			counts[errMsg]++
		} else {
			issuer := result.root.Issuer.String()
			log.Printf("%30s --> %s\n", result.domain, issuer)
			counts[issuer]++
		}
	}
	displayCounts(os.Stdout, counts)
}

func displayCounts(w io.Writer, counts map[string]int) {
	sum := 0
	keys := make([]string, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return counts[keys[i]] > counts[keys[j]]
	})
	for _, k := range keys {
		sum += counts[k]
		fmt.Fprintf(w, "%10d %+v\n", counts[k], k)
	}
	fmt.Fprintf(w, "%10d %s\n", sum, "Total")
}

func worker(domainChannel chan string, resultChannel chan Result, wg *sync.WaitGroup) {
	defer wg.Done()
	for domain := range domainChannel {
		root, resolvedDomain, err := getRootCertificate(domain, cli.Timeout)
		resultChannel <- Result{root, resolvedDomain, err}
	}
}

func getRootCertificate(domain string, timeout time.Duration) (*x509.Certificate, string, error) {
	var root *x509.Certificate
	if !strings.Contains(domain, ":") {
		domain = domain + ":443"
	}
	dialer := &tls.Dialer{
		Config: &tls.Config{
			VerifyConnection: func(state tls.ConnectionState) error {
				peerChain := state.VerifiedChains[0]
				root = peerChain[len(peerChain)-1]
				return errEarlyAbort
			},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	conn, err := dialer.DialContext(ctx, "tcp", domain)
	if err == errEarlyAbort {
		return root, domain, nil
	}

	var (
		dnsErr          *net.DNSError
		opErr           *net.OpError
		verificationErr *tls.CertificateVerificationError
	)

	errors.As(err, &dnsErr)
	errors.As(err, &opErr)
	errors.As(err, &verificationErr)

	if dnsErr != nil && dnsErr.IsNotFound || opErr != nil && opErr.Timeout() {
		if !strings.HasPrefix(domain, "www.") {
			return getRootCertificate("www."+domain, timeout)
		}
	}

	if dnsErr != nil && dnsErr.IsNotFound {
		return nil, domain, fmt.Errorf("DNS error")
	} else if opErr != nil && opErr.Timeout() {
		return nil, domain, fmt.Errorf("connection timout")
	} else if opErr != nil && errors.Is(opErr.Err, syscall.ECONNREFUSED) {
		return nil, domain, fmt.Errorf("connection refused")
	} else if opErr != nil && errors.Is(opErr.Err, syscall.ECONNRESET) {
		return nil, domain, fmt.Errorf("connection reset")
	} else if opErr != nil && errors.Is(opErr.Err, syscall.ENETUNREACH) {
		return nil, domain, fmt.Errorf("no route to host")
	} else if verificationErr != nil {
		return nil, domain, fmt.Errorf("TLS verification error")
	} else if err != nil {
		return nil, domain, fmt.Errorf("%s", err)
	}

	// Should never make it here
	conn.Close()
	return nil, domain, fmt.Errorf("should not have made it here: %v", domain)
}
