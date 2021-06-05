package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"github.com/miekg/dns"
	"log"
	"os"
	"sort"
	"strings"
	"sync"
)

var (
	quadLookup          = flag.Bool("q", false, "Use AAAA record mode instead of the default A record")
	concurrency         = flag.Int("c", 10, "Number of goroutines that try to resolve domains.")
	inFile              = flag.String("i", "", "File to read input from if STDIN is not used.")
	resolver            = flag.String("r", "1.1.1.1", "Resolver to use.")
	authorativeZoneMode = flag.Bool("a", false, "Print the FQDN of the closes SOA (Start Of Authority)")

	I_ROOT_SERVER = "192.36.148.17"
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
				resultString := ""
				var err error
				if *authorativeZoneMode {
					resultString, err = zoneMode(domain, client)
				} else {
					resultString, err = ipAddrMode(domain, client)
				}

				if err != nil {
					log.Println("Error: " + string(err.Error()))
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

func zoneMode(domain string, client *dns.Client) (string, error) {
	lastAuthority := ""
	maxDepth := 10

	//TODO: Add some cache so we don't have to start at the ROOT all the time
	answer, err := resolve(domain, dns.TypeA, client, I_ROOT_SERVER)
	if err != nil {
		return "", errors.New(fmt.Sprintf("%s failed with %s\n", domain, err))
	}

	//Lets (kinda) act like a recursive resolver from ROOT. The SOA will be the last place that had nameservers
	for i := 0; i < maxDepth; i++ {
		//Pick the first NS record
		var ns *dns.NS
		for _, answer := range answer.Ns {
			switch r := answer.(type) {
			case *dns.NS:
				ns = r
				break
			}
		}

		if answer.Authoritative {
			return lastAuthority, nil
		}

		if ns == nil {
			return "", errors.New(fmt.Sprintf("%s got no NS record, potentiall packet loss\n", domain))
		}

		lastAuthority = ns.Hdr.Name

		//Lazy, lets not look at the glue records or traverse the dns-tree ourself again for the address of the NS record. Make the default OS resolver handle that
		answer, err = resolve(domain, dns.TypeA, client, ns.Ns)
		if err != nil {
			return "", errors.New(fmt.Sprintf("%s failed with %s\n", domain, err))
		}
	}

	return "", errors.New(fmt.Sprintf("%s depth limit reached before answer\n", domain))
}

func ipAddrMode(domain string, client *dns.Client) (string, error) {
	var err error
	var result *dns.Msg
	if *quadLookup {
		result, err = resolve(domain, dns.TypeAAAA, client, *resolver)
	} else {
		result, err = resolve(domain, dns.TypeA, client, *resolver)
	}
	if err != nil {
		return "", errors.New(fmt.Sprintf("%s failed with %s\n", domain, err))
	}
	resultString := prettyPrintResult(result)
	return resultString, nil
}

func prettyPrintResult(result *dns.Msg) string {
	var b strings.Builder
	if len(result.Question) != 0 {
		b.WriteString(result.Question[0].Name + ">")
	}
	aRecords := []string{}
	for _, answer := range result.Answer {
		switch r := answer.(type) {
		case *dns.CNAME:
			b.WriteString(r.Target)
		case *dns.A:
			aRecords = append(aRecords, r.A.String())
		case *dns.AAAA:
			aRecords = append(aRecords, r.AAAA.String())
		default:
			b.WriteString("UNKNOWN-RECORD-TYPE")
		}
		if len(aRecords) == 0 {
			b.WriteString(">")
		}

	}
	sort.Strings(aRecords)
	b.WriteString("[")
	b.WriteString(strings.Join(aRecords, " "))
	b.WriteString("]")
	return b.String()
}

func resolve(label string, recordType uint16, client *dns.Client, nameserver string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(label), recordType)
	in, _, err := client.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	return in, err
}
