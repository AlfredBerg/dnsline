package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/AlfredBerg/dnsline/resolver"
	"github.com/miekg/dns"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	//TODO: flag for number of dns retries
	quadLookup       = flag.Bool("q", false, "Query for AAAA records instead of A records")
	concurrency      = flag.Int("c", 10, "Number of goroutines that try to resolve domains.")
	inFile           = flag.String("i", "", "File to read input from if STDIN is not used.")
	externalResolver = flag.String("r", "1.1.1.1", "Resolver to use.")
	mode             = flag.String("m", "resolve", "Mode to use. Available: resolve, soa, statusdiff, responsediff\n\t"+
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

	var resolvMethod resolver.Resolver
	if *mode == "soa" {
		resolvMethod = resolver.NewSoa(recordType)
	} else if *mode == "statusdiff" {
		resolvMethod = resolver.NewDiffStatus(recordType)
	} else if *mode == "responsediff" {
		resolvMethod = resolver.NewDiffResponse(recordType)
	} else if *mode == "resolve" {
		resolvMethod = resolver.NewIpAddr(recordType, *externalResolver)
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
				resultString, err := resolvMethod.Resolve(domain, client)
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
