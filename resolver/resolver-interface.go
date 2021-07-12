package resolver

import "github.com/miekg/dns"

type Resolver interface {
	Resolve(domain string, client *dns.Client) (string, error)
}
