package resolver

import (
	"errors"
	"fmt"
	"github.com/AlfredBerg/dnsline/helpers"
	"github.com/miekg/dns"
	"sort"
	"strings"
)

type diffResponse struct {
	recordType uint16
}

func NewDiffResponse(recordType uint16) diffResponse {
	return diffResponse{recordType: recordType}
}

func (r diffResponse) Resolve(domain string, client *dns.Client) (string, error) {
	nameservers, err := helpers.GetAuthorativeNameservers(domain, client, r.recordType)
	if err != nil {
		return "", err
	}

	thereIsDifference := false
	firstNs := ""
	diffNs := ""
	firstResponse := []string{}
	diffResponse := []string{}
	for i, answer := range nameservers {
		switch rec := answer.(type) {
		case *dns.NS:
			statusAnswer, err := helpers.Resolve(domain, r.recordType, client, rec.Ns)
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
					diffResponse = records
					diffNs = rec.Ns
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
