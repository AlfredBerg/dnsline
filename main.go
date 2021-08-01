package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/AlfredBerg/dnsline/resolver"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"log"
	"os"
	"strings"
	"sync"
	"time"
)

var (
	//TODO: flag for number of dns retries?
	quadLookup             = flag.Bool("q", false, "Query for AAAA records instead of A records")
	disableNameserverCache = flag.Bool("x", false, "Disable the nameserver cache. With this disabled all queries will begin from the DNS ROOT.")
	concurrency            = flag.Int("c", 10, "Number of goroutines that try to resolve domains.")
	inFile                 = flag.String("i", "", "File to read input from if STDIN is not used.")
	//externalResolver       = flag.String("r", "1.1.1.1", "Resolver to use.")
	mode = flag.String("m", "resolve", "Mode to use. Available: resolve, soa, statusdiff, responsediff\n\t"+
		"resolve: Resolve the input domains and output the whole CNAME chain and all ip-addresses.\n\t"+
		"soa: Print the FQDN of the closes SOA (Start Of Authority).\n\t"+
		"statusdiff: Check if there is a difference between the statuses from the authoritative nameservers.\n\t"+
		"responsediff: Check if there is a difference between the resolved address(es) from the authoritative nameservers.\n")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: \n")
		flag.PrintDefaults()
	}
	flag.Parse()

	recordType := dns.TypeA
	if *quadLookup {
		recordType = dns.TypeAAAA
	}

	c := cache.New(5*time.Minute, 10*time.Minute)
	if *disableNameserverCache {
		c = nil
	}

	var resolveMethod resolver.Resolver
	if *mode == "soa" {
		resolveMethod = resolver.NewSoa(recordType, c)
	} else if *mode == "statusdiff" {
		fmt.Fprint(os.Stderr, "domain [status@ns.example.com] isDifference\n")
		resolveMethod = resolver.NewDiffStatus(recordType, c)
	} else if *mode == "responsediff" {
		fmt.Fprint(os.Stderr, "domain [response]@ns1 ([response]@ns2) isDifference\n")
		resolveMethod = resolver.NewDiffResponse(recordType, c)
	} else if *mode == "resolve" {
		fmt.Fprint(os.Stderr, "domain>cname(s)>[127.0.0.1 127.0.0.2]\n")
		resolveMethod = resolver.NewCacheIpAddr(recordType, c)
		//}else if *mode == "externalResolve" {
		//	resolveMethod = resolver.NewIpAddr(recordType, *externalResolver)
	} else {
		log.Fatal("A unknown -m mode was specified")
	}

	domains := make(chan string)
	output := make(chan string)
	var workerWG sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		workerWG.Add(1)
		go func() {
			client := new(dns.Client)
			for domain := range domains {
				resultString, err := resolveMethod.Resolve(domain, client)
				if err != nil {
					log.Printf("Error for %s: %s\n", domain, err.Error())
					continue
				}
				output <- resultString
			}
			workerWG.Done()
		}()
	}

	// Close the output channel when the workers are done
	go func() {
		workerWG.Wait()
		close(output)
	}()

	go func() {
		var sc *bufio.Scanner
		if *inFile == "" {
			sc = bufio.NewScanner(os.Stdin)
		} else {
			f, err := os.Open(*inFile)
			if err != nil {
				panic(err)
			}
			sc = bufio.NewScanner(f)
		}
		for sc.Scan() {
			domain := strings.ToLower(sc.Text())
			domains <- domain
		}
		if sc.Err() != nil {
			panic(sc.Err())
		}
		close(domains)
	}()

	for line := range output {
		fmt.Println(line)
	}
}
