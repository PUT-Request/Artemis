# Artemis

A self-hosted DNS server and HTTP redirect infrastructure with a web management UI, built as a single Go binary.

## Features

- **DNS forwarding** -- Proxies queries to ordered upstreams with UDP-to-TCP fallback and TTL-based response caching.
- **URL redirects** -- DNS returns an answer IP; an HTTP front issues 302 redirects to the real target. Supports sitemap auto-import.
- **Base32 short codes** -- `<base32-encoded-url>.ba` resolves and redirects live to the original URL.
- **Auto-mirror redirector** -- `<name>.auto` redirects to the first healthy mirror in a group, with stale-while-revalidate health checks.
- **Custom DNS records** -- Wildcard or exact domain-to-IP mappings for private LAN DNS.
- **Phone-number IP resolution** -- `+1-192-168-199-1` resolves to `192.168.199.1` (toggleable).

All configuration changes are hot-reloadable via the Web UI or `SIGHUP` -- no restart required.

## Architecture

```
                        +-------------------------------------+
                        |              Artemis                 |
                        |                                     |
  Client ------- UDP/TCP -- DNS (53)                          |
  Client ------- HTTP ----- DoH (8053)                        |
  Browser ------ HTTP ----- HTTP front (80)                   |
  Admin -------- HTTP ----- Web UI (8082)                     |
                        |                                     |
                        |  SQLite (artemis.db)                |
                        +-------------------------------------+
```

Single Go binary, no CGO required (pure-Go SQLite via `modernc.org/sqlite`).

## Quick Start

```bash
go build -o artemis .
./artemis
```

The server starts listening on the ports defined in `config.yaml`. Open the Web UI at `http://127.0.0.1:8082`.

### Default credentials

```
username: admin
password: changeme
```

Change these in `config.yaml` before exposing the Web UI to any network.

## Configuration

All settings live in `config.yaml`:

```yaml
listen: "127.0.0.1:8082"       # Web UI address
dns_listen: "0.0.0.0:53"       # DNS listen address
doh_listen: "0.0.0.0:8053"     # DNS-over-HTTPS listen address
http_listen: "0.0.0.0:80"      # HTTP redirect front
username: "admin"
password: "changeme"
short_tld: "ba"                 # TLD for short-code redirects
```

Upstreams, redirects, custom domains, and auto-mirror groups are managed through the Web UI and stored in SQLite.

## Building

```bash
# Requires Go 1.25+
go build -o artemis .
```

## Testing

```bash
go test ./...
```

## Security Notes

- Web UI uses HTTP Basic auth with constant-time password comparison and IP-based brute-force throttling.
- CSRF tokens are rotated per request.
- All SQL queries are parameterized.
- SSRF validation blocks link-local and cloud-metadata IPs for redirect targets.
- Database file is created with `0600` permissions.
- The Web UI is served over plain HTTP by default. Use a reverse proxy with TLS for external access.

## License

See [LICENSE](LICENSE) if present.
