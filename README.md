# ACME proxy

Forward ACME challenge requests to local clients. Clients on the intranet with valid local dns entries can request certs using standard acme tools.

## Configuration

Make sure your docker host uses the intranet dns server for name resolution.

By default, all domains are allowed.
You should limit this to the domain prefixes used on the intranet to not leak requests.
The environment variable `ACME_DOMAINS` holds a regex to filter incomming requests with.

`ACME_DOMAINS` | matches
---- | -----
`.*` | any string/domain (default)
`^intra\.example\.com$` | exacty intra.example.com
`(\.i\.example\.com)$\|(\.iana\.org)$` | any subdomain under i.example.com or any subdomain under iana.org

Keep in mind that a regex like `iana\.org$` also matches a domain like `whateverisinfrontiana.org`, so better use something like `(\.|^)iana.org$` in that case.

The timeout for the proxied acme token requests can be set in milliseconds using the `ACME_TIMEOUT` variable.

## Starting

Change 8888 to the port you want your firewall/gateway to forward requests to

```bash
docker run -p 8888:8080 -e ACME_DOMAINS="(\.i\.example\.com)$" -d joellinn/acme-proxy
```
