package resolver

import (
	"errors"
	"fmt"
	"github.com/AlfredBerg/dnsline/helpers"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
)

type soa struct {
	recordType uint16
	cache      *cache.Cache
}

func NewSoa(recordType uint16, cache *cache.Cache) soa {
	return soa{recordType: recordType, cache: cache}
}

func (r soa) Resolve(domain string, client *dns.Client) (string, error) {
	nameservers, err := helpers.GetAuthoritativeNameservers(domain, client, r.recordType, r.cache)
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
		if authority != "" {
			break
		}
	}
	if authority == "" {
		return "", errors.New(fmt.Sprintf("%s Did not get any ns records", domain))
	}
	return fmt.Sprintf("%s for %s", authority, domain), err
}
