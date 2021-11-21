package helpers

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"sort"
	"strings"
)

var (
	I_ROOT_SERVER = "192.36.148.17"
	MAX_RETRIES   = 3
)

func Resolve(label string, recordType uint16, client *dns.Client, nameserver string, c *cache.Cache) (*dns.Msg, error) {
	var finalError error
	for i := 0; i < MAX_RETRIES; i++ {
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(label), recordType)
		answer, _, err := client.Exchange(m, nameserver+":53")
		if err != nil {
			finalError = err
			continue
		}

		if zoneCut := getAnswerZoneCut(answer); c != nil && zoneCut != "" {
			c.Add(zoneCut, answer, 0)
		}
		return answer, nil
	}
	return nil, finalError
}

//Gets where the delegation starts/stops. At returns "" for nameservers in SOA records (common for nxdomain responses)
func getAnswerZoneCut(answer *dns.Msg) string {
	for _, ns := range answer.Ns {
		if ns, ok := ns.(*dns.NS); ok {
			return ns.Hdr.Name
		}
	}
	return ""
}

//Returns a list of RRs that should contain NS records for the closes authoritative zone to the input domain. It is the responsibility of the caller to check that the RRs are actually NS records
func GetAuthoritativeNameservers(domain string, client *dns.Client, recordType uint16, cache *cache.Cache) ([]dns.RR, error) {
	var previousNSresourceRecords []dns.RR
	previousNsServer := "fromCache"
	maxDepth := 10

	gotCacheResult, answer := getClosestCachedNameserver(domain, cache)

	var err error
	if !gotCacheResult {
		answer, err = Resolve(domain, recordType, client, I_ROOT_SERVER, cache)
		previousNsServer = I_ROOT_SERVER
		if err != nil {
			return nil, err
		}
	} else {
		var ns *dns.NS
		for _, answer := range answer.Ns {
			switch r := answer.(type) {
			case *dns.NS:
				ns = r
				break
			}
		}
		if ns != nil {
			previousNSresourceRecords = answer.Ns
		}
	}
	//Lets (kinda) act like a recursive resolver from ROOT. The closest SOA will be the last place that had nameservers
	previousNSresourceRecords = answer.Ns
	for i := 0; i < maxDepth; i++ {
		if answer.Authoritative {
			if previousNSresourceRecords != nil {
				return previousNSresourceRecords, nil
			}
			return nil, errors.New(fmt.Sprintf("unexpected state, got a authorative response but never got any NS servers. Rcode: %s from %s", dns.RcodeToString[answer.Rcode], previousNsServer))
		}

		//Pick the first NS record
		var ns *dns.NS
		for _, answer := range answer.Ns {
			switch r := answer.(type) {
			case *dns.NS:
				ns = r
			}
		}

		if ns == nil {
			return previousNSresourceRecords, errors.New(fmt.Sprintf("unexpected response, got a response not containing ns records and it is not authorative. Rcode: %s from %s", dns.RcodeToString[answer.Rcode], previousNsServer))
		}

		previousNSresourceRecords = answer.Ns
		//Lazy, lets not look at the glue records or traverse the dns-tree ourself again for the address of the NS record. Make the default OS resolver handle that
		answer, err = Resolve(domain, dns.TypeA, client, ns.Ns, cache)
		previousNsServer = ns.Ns
		if err != nil {
			return nil, errors.New(fmt.Sprintf("%s failed with %s", domain, err))
		}
	}
	return nil, errors.New(fmt.Sprintf("%s depth limit reached before answer", domain))
}

func getClosestCachedNameserver(domain string, c *cache.Cache) (gotCacheResult bool, answer *dns.Msg) {
	if c == nil {
		return false, nil
	}

	labels := dns.SplitDomainName(domain)
	//Find the longest string of labels in cache
	for i := range labels {
		d := strings.Join(labels[i:], ".")
		if interfaceResult, found := c.Get(dns.Fqdn(d)); found {
			if in, success := interfaceResult.(*dns.Msg); success {
				return true, in
			}
		}
	}
	return false, nil
}

func PrettyPrintResult(result *dns.Msg) string {
	var b strings.Builder
	if len(result.Question) != 0 {
		b.WriteString(result.Question[0].Name + ">")
	}
	var aRecords []string
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
