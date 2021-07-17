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
)

func Resolve(label string, recordType uint16, client *dns.Client, nameserver string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(label), recordType)
	in, _, err := client.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	return in, err
}

func ResolveCache(domainName string, recordType uint16, client *dns.Client, nameserver string, cache *cache.Cache) (*dns.Msg, error) {
	labels := dns.SplitDomainName(domainName)
	//Find the longest string of labels in cache
	for i := range labels {
		d := strings.Join(labels[i:], ".")
		if interfaceResult, found := cache.Get(dns.Fqdn(d)); found {
			if in, success := interfaceResult.(*dns.Msg); success {
				if in.Authoritative {
					return in, nil
				} else {
					ns := getNs(in)
					if ns == nil {
						return nil, errors.New(fmt.Sprintf("Unexpected non authorative response in cache that does not contain ns records for %s", d))
					}
					nameserver = ns.Ns
				}
				break
			}
		}
	}

	fqdn := dns.Fqdn(domainName)

	m := new(dns.Msg)
	m.SetQuestion(fqdn, recordType)
	in, _, err := client.Exchange(m, nameserver+":53")
	if err != nil {
		return nil, err
	}
	zoneCut := getAnswerZoneCut(in)
	if zoneCut != "" {
		cache.Add(zoneCut, in, 0)
	}

	return in, err
}

func getAnswerZoneCut(answer *dns.Msg) string {
	for _, ns := range answer.Ns {
		if ns, ok := ns.(*dns.NS); ok {
			return ns.Hdr.Name
		}
	}
	return ""

}

//Returns a list of RRs that should contain NS records for the closes authorative zone to the input domain. It is the responsibility of the caller to check that the RRs are actually NS records
func GetAuthorativeNameserversCache(domain string, client *dns.Client, recordType uint16, cache *cache.Cache) ([]dns.RR, error) {
	var lastNSresourceRecords []dns.RR
	maxDepth := 10

	answer, err := ResolveCache(domain, recordType, client, I_ROOT_SERVER, cache)
	if err != nil{
		return nil, err
	}
	lastNSresourceRecords = getNsRecords(answer)

	//Lets (kinda) act like a recursive resolver from ROOT. The closest SOA will be the last place that had nameservers
	for i := 0; i < maxDepth; i++ {
		if answer.Authoritative {
			if lastNSresourceRecords != nil {
				return lastNSresourceRecords, nil
			}
			return nil, errors.New(fmt.Sprintf("%s Unexpected state, got a authorative response but never got any NS servers\n", domain))
		}

		ns := getNs(answer)
		if ns == nil {
			//return lastNSresourceRecords, errors.New(fmt.Sprintf("%s Unexpected response, got a response not containing ns records and it is not authorative\n", domain))
			if lastNSresourceRecords == nil {
				return lastNSresourceRecords, errors.New(fmt.Sprintf("%s Unexpected response does not have any lastNSrecordsresponse\n", domain))
			}
			return lastNSresourceRecords, nil

		}

		lastNSresourceRecords = getNsRecords(answer)
		//Lazy, lets not look at the glue records or traverse the dns-tree ourself again for the address of the NS record. Make the default OS resolver handle that
		answer, err = ResolveCache(domain, dns.TypeA, client, ns.Ns, cache)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("%s failed with %s\n", domain, err))
		}
	}
	return nil, errors.New(fmt.Sprintf("%s depth limit reached before answer\n", domain))
}

func getNs(answer *dns.Msg) (ns *dns.NS) {
	if answer == nil {
		return nil
	}
	for _, answer := range answer.Ns {
		switch r := answer.(type) {
		case *dns.NS:
			ns = r
			break
		}
	}
	return ns
}

func getNsRecords(answer *dns.Msg) (nsRecords []dns.RR) {
	if answer == nil {
		return nil
	}
	for _, answer := range answer.Ns {
		switch r := answer.(type) {
		case *dns.NS:
			nsRecords = append(nsRecords, r)
		}
	}
	return nsRecords
}

//Returns a list of RRs that should contain NS records for the closes authorative zone to the input domain. It is the responsibility of the caller to check that the RRs are actually NS records
func GetAuthorativeNameservers(domain string, client *dns.Client, recordType uint16) ([]dns.RR, error) {

	var lastNSresourceRecords []dns.RR
	maxDepth := 10

	//TODO: Add some cache so we don't have to start at the ROOT all the time
	answer, err := Resolve(domain, recordType, client, I_ROOT_SERVER)
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
		answer, err = Resolve(domain, dns.TypeA, client, ns.Ns)
		if err != nil {
			return nil, errors.New(fmt.Sprintf("%s failed with %s\n", domain, err))
		}
	}
	return nil, errors.New(fmt.Sprintf("%s depth limit reached before answer\n", domain))
}

func PrettyPrintResult(result *dns.Msg) string {
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
