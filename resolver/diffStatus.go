package resolver

import (
	"fmt"
	"github.com/AlfredBerg/dnsline/helpers"
	"github.com/miekg/dns"
	"strings"
)

type diffStatus struct {
	recordType uint16
}

func NewDiffStatus(recordType uint16) diffStatus {
	return diffStatus{recordType: recordType}
}

func (r diffStatus) Resolve(domain string, client *dns.Client) (string, error) {
	nameservers, err := helpers.GetAuthorativeNameservers(domain, client, r.recordType)
	if err != nil {
		return "", err
	}

	statuses := []string{}
	thereIsDifference := false
	firstStatus := ""
	for _, answer := range nameservers {
		switch rec := answer.(type) {
		case *dns.NS:
			statusAnswer, err := helpers.Resolve(domain, r.recordType, client, rec.Ns)
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
