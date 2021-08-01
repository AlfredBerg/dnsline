package resolver

import (
	"errors"
	"fmt"
	"github.com/AlfredBerg/dnsline/helpers"
	"github.com/miekg/dns"
	"github.com/patrickmn/go-cache"
	"sort"
	"strings"
)

type diffResponse struct {
	recordType uint16
	cache      *cache.Cache
}

func NewDiffResponse(recordType uint16, cache *cache.Cache) diffResponse {
	return diffResponse{recordType: recordType, cache: cache}
}

func (r diffResponse) Resolve(domain string, client *dns.Client) (string, error) {
	nameservers, err := helpers.GetAuthoritativeNameservers(domain, client, r.recordType, r.cache)
	if err != nil {
		return "", err
	}

	thereIsDifference := false
	firstNs := ""
	diffNs := ""
	var firstResponse, differentResponse []string
	for i, answer := range nameservers {
		switch rec := answer.(type) {
		case *dns.NS:
			statusAnswer, err := helpers.Resolve(domain, r.recordType, client, rec.Ns, r.cache)
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
				firstNs = rec.Ns
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
					differentResponse = records
					diffNs = rec.Ns
					break
				}
			}
		}
		if thereIsDifference {
			break
		}
	}
	b := strings.Builder{}
	b.WriteString(fmt.Sprintf("%s [%s]@%s %v", domain, strings.Join(firstResponse, " "), firstNs, thereIsDifference))
	if thereIsDifference {
		b.WriteString(fmt.Sprintf("[%s]@%s", strings.Join(differentResponse, " "), diffNs))
	}
	return b.String(), nil
}
