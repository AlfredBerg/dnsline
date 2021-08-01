# dnsline

Making it easy to grep & cut accurate dns results.

Dnsline uses a similar approach as a recursive dns resolver with a cache to get the results. This means
that there is no need to supply a list of resolvers, and the results will come directly from the
authoritative dns servers.

## Install

```
go install github.com/AlfredBerg/dnsline@latest
```
Old go versions <1.16:
```
go get -u github.com/AlfredBerg/dnsline
```

## Usage

Basic usage:  

```
$ cat domains.txt | dnsline
example.com.>[203.0.113.1]
cname.example.com.>cname-chain.example.com.>[203.0.113.1 203.0.113.2]
```

Get response difference
```
$ cat domains.txt | dnsline -m responsediff
example.com [203.0.113.1]@a.iana-servers.net. false
cdn.example.com [203.0.113.1]@a.iana-servers.net. [203.0.113.2]@b.iana-servers.net. true
```

Get status difference
```
$ cat domains.txt | dnsline -m statusdiff
example.com [NOERROR@a.iana-servers.net. NOERROR@b.iana-servers.net.] false
foo.example.com [NXDOMAIN@a.iana-servers.net. NXDOMAIN@b.iana-servers.net.] false
diff.example.com [NXDOMAIN@a.iana-servers.net. NOERROR@b.iana-servers.net.] true
```

Get SOA (Start Of Authority)
```
$ cat domains.txt | dnsline -m soa
example.com. for example.com
example.com. for foo.example.com
delegation.example.com. for a.delegation.example.com
```

## Options

```
$ dnsline -h
Usage: 
  -c int
    	Number of goroutines that try to resolve domains. (default 10)
  -i string
    	File to read input from if STDIN is not used.
  -m string
    	Mode to use. Available: resolve, soa, statusdiff, responsediff
    		resolve: Resolve the input domains and output the whole CNAME chain and all ip-addresses.
    		soa: Print the FQDN of the closes SOA (Start Of Authority).
    		statusdiff: Check if there is a difference between the statuses from the authoritative nameservers.
    		responsediff: Check if there is a difference between the resolved address(es) from the authoritative nameservers.
    	 (default "resolve")
  -q	Query for AAAA records instead of A records
  -x	Disable the nameserver cache. With this disabled all queries will begin from the DNS ROOT.
```
