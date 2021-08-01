package resolver

import (
	"errors"
	"github.com/AlfredBerg/dnsline/helpers"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

type cacheIpAddr struct {
	recordType uint16
	cache      *cache.Cache
}

func NewCacheIpAddr(recordType uint16, cache *cache.Cache) cacheIpAddr {
	return cacheIpAddr{recordType: recordType, cache: cache}
}

func (r cacheIpAddr) Resolve(domain string, client *dns.Client) (string, error) {
	nextDomain := domain
	var cnameResponses []dns.RR
	var aResponses []dns.RR
	for i := 0; i < 10; i++ {
		nameservers, err := helpers.GetAuthoritativeNameservers(nextDomain, client, r.recordType, r.cache)
		if err != nil {
			return "", err
		}
		nameserver := ""
		//TODO: randomize ns?
		for _, ns := range nameservers {
			if ns, ok := ns.(*dns.NS); ok {
				nameserver = ns.Ns
			}
		}

		if nameserver == "" {
			return "", errors.New("no ns to query found")
		}

		var result *dns.Msg
		result, err = helpers.Resolve(nextDomain, r.recordType, client, nameserver, r.cache)
		if err != nil {
			return "", err
		}

		done := false
		if len(result.Answer) != 0 {
			if dns.RcodeToString[result.Rcode] == "NOERROR" {
				for _, record := range result.Answer {
					switch r := record.(type) {
					case *dns.CNAME:
						cnameResponses = append(cnameResponses, r)
						nextDomain = r.Target
					case *dns.A:
						aResponses = append(aResponses, r)
						done = true
					case *dns.AAAA:
						aResponses = append(aResponses, r)
						done = true
					}
				}
			}
		} else {
			done = true
		}

		if done {
			if len(cnameResponses) != 0 {
				//Reconstruct a response if we had to ask multiple servers
				result.Question[0].Name = dns.Fqdn(domain)
				result.Answer = cnameResponses
				result.Answer = append(result.Answer, aResponses...)
			}

			resultString := helpers.PrettyPrintResult(result)
			return resultString, nil
		}
	}
	return "", errors.New("to long cname chain")

}
