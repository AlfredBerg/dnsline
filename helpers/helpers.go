package helpers

import (
	"errors"
	"fmt"
	"github.com/miekg/dns"
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
