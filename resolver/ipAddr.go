package resolver

import (
	"errors"
	"fmt"
	"github.com/AlfredBerg/dnsline/helpers"
	"github.com/miekg/dns"
)

type ipAddr struct {
	recordType       uint16
	externalResolver string
}

func NewIpAddr(recordType uint16, externalResolver string) ipAddr {
	return ipAddr{recordType: recordType, externalResolver: externalResolver}
}

func (r ipAddr) Resolve(domain string, client *dns.Client) (string, error) {
	var err error
	var result *dns.Msg
	result, err = helpers.Resolve(domain, r.recordType, client, r.externalResolver, nil)

	if err != nil {
		return "", errors.New(fmt.Sprintf("%s failed with %s\n", domain, err))
	}
	resultString := helpers.PrettyPrintResult(result)
	return resultString, nil
}
