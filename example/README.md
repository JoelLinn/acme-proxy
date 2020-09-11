# Web Firewall Example

## What's this?

Given an intranet that is connected to the internet by NAT, this example illustrates the use of the acme proxy as part of a web firewall.
Enabling:

- Every host that has a DNS name assigned on the intranet to obtain _Let's Encrypt_ certificates.
- To expose selected intranet HTTPS resources to the Internet, even if they are on different intranet hosts.

## Prerequisites

- Have a DNS server on your intranet with a valid domain you own on the WWW (`*.local` won't cut it), in this case `*.i.example.com.`
- Point the public DNS wildcard entry for your intranet domain name to your NAT IP.
- Forward the port `80` and `443` from your firewall to the docker host running the `docker-compose.yml` onto port `8080` and `8443`.
