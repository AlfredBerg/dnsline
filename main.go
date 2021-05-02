package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"os"
	"strings"
	"sync"
)

var (
	quadLookup  = flag.Bool("AAAA", false, "Use AAAA record instead of the default A record")
	concurrency = flag.Int("c", 10, "Number of goroutines that try to resolve domains.")
	inFile      = flag.String("i", "", "Optional file to read input from. STDIN used by default.")
	resolver    = flag.String("r", "1.1.1.1", "Resolver to use.")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: \n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	domains := make(chan string)
	output := make(chan string)
	var workerWG sync.WaitGroup
	for i := 0; i < *concurrency; i++ {
		workerWG.Add(1)
		go func() {
			client := new(dns.Client)
			for domain := range domains {
				var err error
				var result *dns.Msg
				if *quadLookup {
					result, err = resolve(domain, dns.TypeAAAA, client)
				} else {
					result, err = resolve(domain, dns.TypeA, client)
				}
				if err != nil {
					log.Printf("ERROR: %s failed with %s\n", domain, err)
					continue
				}
				output <- prettyPrintResult(result)
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
		close(domains)
	}()

	for line := range output {
		fmt.Println(line)
	}
}

func prettyPrintResult(result *dns.Msg) string {
	var b strings.Builder
	if len(result.Question) != 0 {
		b.WriteString(result.Question[0].Name + " > ")
	}
	firstASeen := false
	for place, answer := range result.Answer {
		switch r := answer.(type) {
		case *dns.CNAME:
			b.WriteString(r.Target)
		case *dns.A:
			if !firstASeen {
				b.WriteString("[")
				firstASeen = true
			}
			b.WriteString(r.A.String())
			if place == len(result.Answer)-1 {
				b.WriteString("]")
			}
		case *dns.AAAA:
			if !firstASeen {
				b.WriteString("[")
				firstASeen = true
			}
			b.WriteString(r.AAAA.String())
			if place == len(result.Answer)-1 {
				b.WriteString("]")
			}
		default:
			b.WriteString("UNKNOWN-TYPE")
		}
		b.WriteString(" ")
		if !firstASeen {
			b.WriteString("> ")
		}
	}
	return b.String()
}

func resolve(label string, recordType uint16, client *dns.Client) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(label), recordType)
	in, _, err := client.Exchange(m, *resolver+":53")
	if err != nil {
		return nil, err
	}
	return in, err
}
