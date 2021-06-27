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
	//TODO: flag for number of dns retries
	quadLookup  = flag.Bool("q", false, "Query for AAAA records instead of A records")
	concurrency = flag.Int("c", 10, "Number of goroutines that try to resolve domains.")
	inFile      = flag.String("i", "", "File to read input from if STDIN is not used.")
	resolver    = flag.String("r", "1.1.1.1", "Resolver to use.")
	mode        = flag.String("m", "resolve", "Mode to use. Available: resolve, soa, statusdiff, responsediff\n\t"+
		"resolve: Resolve the input domains and output the whole CNAME chain and all ip-addresses.\n\t"+
		"soa: Print the FQDN of the closes SOA (Start Of Authority).\n\t"+
		"statusdiff: Check if there is a difference between the statuses from the authoritative nameservers.\n\t"+
		"responsediff: Check if there is a difference between the resolved address(es) from the authoritative nameservers.\n")

	I_ROOT_SERVER = "192.36.148.17"
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
				//TODO: Do these checks elsewhere and just pass a resolve function
				if *mode == "soa" {
					resultString, err = zoneMode(domain, client, recordType)
				} else if *mode == "statusdiff" {
					resultString, err = statusMode(domain, client, recordType)
				} else if *mode == "responsediff" {
					resultString, err = responseDiffMode(domain, client, recordType)
				} else if *mode == "resolve" {
					resultString, err = ipAddrMode(domain, client, recordType)
				}else{
					panic("Unknown resolve mode")
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

func statusMode(domain string, client *dns.Client, recordType uint16) (string, error) {
	nameservers, err := getAuthorativeNameservers(domain, client, recordType)
	if err != nil {
		return "", err
	}

	statuses := []string{}
	thereIsDifference := false
	firstStatus := ""
	for _, answer := range nameservers {
		switch r := answer.(type) {
		case *dns.NS:
			statusAnswer, err := resolve(domain, recordType, client, r.Ns)
			if err != nil {
				return "", err
			}
			status := dns.RcodeToString[statusAnswer.Rcode]
			if firstStatus == "" {
				firstStatus = status
			} else {
				if firstStatus != status {
					thereIsDifference = true
				}
			}
			statuses = append(statuses, fmt.Sprintf("%s@%s", status, r.Ns))
		}
	}
	return fmt.Sprintf("%s [%s] %v", domain, strings.Join(statuses, " "), thereIsDifference), err
}

func responseDiffMode(domain string, client *dns.Client, recordType uint16) (string, error) {
	nameservers, err := getAuthorativeNameservers(domain, client, recordType)
	if err != nil {
		return "", err
	}

	thereIsDifference := false
	firstNs := ""
	diffNs := ""
	firstResponse := []string{}
	diffResponse := []string{}
	for i, answer := range nameservers {
		switch r := answer.(type) {
		case *dns.NS:
			statusAnswer, err := resolve(domain, recordType, client, r.Ns)
			if err != nil {
				return "", err
			}
			records := []string{}
			for _, record := range statusAnswer.Answer {
				rString := ""
				switch r := record.(type) {
				case *dns.A:
					rString = r.A.String()
				case *dns.AAAA:
					rString = r.AAAA.String()
				case *dns.CNAME:
					rString = r.Target
				default:
					return "", errors.New(fmt.Sprintf("Unknown record type: %s", record.String()))
				}
				records = append(records, rString)
			}
			sort.Strings(records)

			if i == 0 {
				firstResponse = records
				firstNs = r.Ns
			} else {
				if len(firstResponse) != len(records) {
					thereIsDifference = true
					break
				}
				if len(records) == 0 {
					break
				}
				for r := range firstResponse {
					if firstResponse[r] != records[r] {
						thereIsDifference = true
						break
					}
				}
				if thereIsDifference {
					diffResponse = records
					diffNs = r.Ns
					break
				}
			}
		}
	}
	b := strings.Builder{}
	b.WriteString(fmt.Sprintf("%s %v [%s]@%s ", domain, thereIsDifference, strings.Join(firstResponse, " "), firstNs))
	if thereIsDifference {
		b.WriteString(fmt.Sprintf("[%s]@%s", strings.Join(diffResponse, " "), diffNs))
	}
	return b.String(), nil
}

func zoneMode(domain string, client *dns.Client, recordType uint16) (string, error) {
	nameservers, err := getAuthorativeNameservers(domain, client, recordType)
	if err != nil {
		return "", err
	}

	authority := ""
	//Lets just get the first ns record and what it is authoritative over
	for _, answer := range nameservers {
		switch r := answer.(type) {
		case *dns.NS:
			authority = r.Hdr.Name
			break
		}
	}
	if authority == "" {
		return "", errors.New(fmt.Sprintf("%s Did not get any ns records\n", domain))
	}
	return fmt.Sprintf("%s for %s", authority, domain), err
}

//Returns a list of RRs that should contain NS records for the closes authorative zone to the input domain. It is the responsibility of the caller to check that the RRs are actually NS records
func getAuthorativeNameservers(domain string, client *dns.Client, recordType uint16) ([]dns.RR, error) {
	var lastNSresourceRecords []dns.RR
	maxDepth := 10
	//TODO: Add some cache so we don't have to start at the ROOT all the time
	answer, err := resolve(domain, recordType, client, I_ROOT_SERVER)
	if err != nil {
		return nil, errors.New(fmt.Sprintf("%s failed with %s\n", domain, err))
	}

	//Lets (kinda) act like a recursive resolver from ROOT. The closest SOA will be the last place that had nameservers
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
			if lastNSresourceRecords != nil {
				return lastNSresourceRecords, nil
			}
			return nil, errors.New(fmt.Sprintf("%s Unexpected state, got a authorative response but never got any NS servers\n", domain))
		}

		if ns == nil {
			return lastNSresourceRecords, errors.New(fmt.Sprintf("%s Unexpected response, got a response not containing ns records and it is not authorative\n", domain))
		}

		lastNSresourceRecords = answer.Ns
		//Lazy, lets not look at the glue records or traverse the dns-tree ourself again for the address of the NS record. Make the default OS resolver handle that
		answer, err = resolve(domain, dns.TypeA, client, ns.Ns)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("%s failed with %s\n", domain, err))
		}
	}
	return nil, errors.New(fmt.Sprintf("%s depth limit reached before answer\n", domain))
}

func ipAddrMode(domain string, client *dns.Client, recordType uint16) (string, error) {
	var err error
	var result *dns.Msg
	result, err = resolve(domain, recordType, client, *resolver)

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
