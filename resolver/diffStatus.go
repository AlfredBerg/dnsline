package resolver

import (
	"fmt"
	"github.com/AlfredBerg/dnsline/helpers"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"strings"
)

type diffStatus struct {
	recordType uint16
	cache      *cache.Cache
}

func NewDiffStatus(recordType uint16, cache *cache.Cache) diffStatus {
	return diffStatus{recordType: recordType, cache: cache}
}

func (r diffStatus) Resolve(domain string, client *dns.Client) (string, error) {
	nameservers, err := helpers.GetAuthoritativeNameservers(domain, client, r.recordType, r.cache)
	if err != nil {
		return "", err
	}

	var statuses []string
	thereIsDifference := false
	firstStatus := ""
	for _, answer := range nameservers {
		switch rec := answer.(type) {
		case *dns.NS:
			statusAnswer, err := helpers.Resolve(domain, r.recordType, client, rec.Ns, r.cache)
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
			statuses = append(statuses, fmt.Sprintf("%s@%s", status, rec.Ns))
		}
	}
	return fmt.Sprintf("%s [%s] %v", domain, strings.Join(statuses, " "), thereIsDifference), err
}
