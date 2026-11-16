# Trusted proxy middleware

A PSR-15 middleware for applications running behind a reverse proxy (Traefik, nginx, a load
balancer...). It reads the `X-Forwarded-*` headers **only when the request comes from a proxy
you declared**, then fixes the request for the rest of the stack: client IP address in a request
attribute, scheme, host and port of the URI.

Requires PHP 8.3+, `psr/http-message` and `psr/http-server-middleware`. No other dependency.

## The problem

Behind a reverse proxy, PHP sees the connection of the proxy: `REMOTE_ADDR` is the IP of the
proxy and the scheme is often `http` even when the visitor uses `https`. The proxy tells the
real values in `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and
`X-Forwarded-Port`, but any client can send these headers too. They can only be believed when
the direct connection comes from a known proxy: that is what this middleware checks.

## Installation

```bash
composer require gadwinn/trusted-proxy-middleware
```

## Usage

```php
use G\TrustedProxyMiddleware\TrustedProxyMiddleware;

$middleware = new TrustedProxyMiddleware(
    trustedProxies: ['172.18.0.0/16', '::1'],   // IP addresses or CIDR ranges, IPv4 or IPv6
);
```

Put it **first** in the middleware stack, so that every other middleware (logging, rate
limiting, CSRF, redirections to `https`...) sees the corrected request. Then read the client IP
from the request attribute:

```php
$ip = $request->getAttribute('client_ip'); // TrustedProxyMiddleware::ATTRIBUTE
```

### Example: Traefik in Docker

Traefik forwards the requests from its container, inside the Docker network of the
application. Declare that network (`docker network inspect <network>` shows its subnet):

```php
new TrustedProxyMiddleware(['172.18.0.0/16']);
```

Traefik sets `X-Forwarded-For`, `X-Forwarded-Proto`, `X-Forwarded-Host` and
`X-Forwarded-Port` by default. With nginx, set them yourself:

```nginx
proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;
proxy_set_header X-Forwarded-Host  $host;
proxy_set_header X-Forwarded-Port  $server_port;
```

> **Never declare `0.0.0.0/0` or `::/0`.** Every client would then be trusted, and anyone could
> choose their own IP address, scheme and host by sending the headers. Declare only the
> addresses of your proxies.

## Behaviour

The direct IP is the `REMOTE_ADDR` server parameter of the PSR-7 request (never `$_SERVER`).

- **Direct IP not declared**: the `X-Forwarded-*` headers are ignored, the `client_ip`
  attribute holds the direct IP and the URI is left untouched.
- **Direct IP missing or invalid**: the request is passed on untouched, without attribute.
- **Direct IP declared**:
  - `X-Forwarded-For` is read **from right to left**, skipping the declared proxies: the first
    address which is not a declared proxy is the client. An invalid entry stops the walk (the
    last valid address is kept); when every address is a declared proxy, the leftmost one is
    the client. Several header lines are joined; a port appended to an address
    (`1.2.3.4:5678`, `[2001:db8::1]:443`) is ignored.
  - `X-Forwarded-Proto`: `http` or `https` only (case insensitive, first value) → scheme of the URI.
  - `X-Forwarded-Host`: a host name, an IPv4 address or a bracketed IPv6 address, with an optional
    port (`example.com:8443`) → host (and port) of the URI. An invalid value is ignored.
  - `X-Forwarded-Port`: an integer from 1 to 65535 → port of the URI; it wins over the port given
    in `X-Forwarded-Host`. An invalid value is ignored.
  - Without any forwarded port, a changed scheme or host resets the port of the URI to the
    default port of the scheme: the port seen by PHP is the one of the proxy.

IP addresses are returned in canonical form (`2001:db8::1`), and an IPv4-mapped IPv6 address
(`::ffff:192.0.2.1`) becomes the IPv4 address.

The middleware has no state: one instance can serve any number of requests (FrankenPHP worker
mode, RoadRunner...).

## Options

```php
new TrustedProxyMiddleware(
    trustedProxies: ['10.0.0.0/8'],
    headers: [TrustedProxyMiddleware::FORWARDED_FOR, TrustedProxyMiddleware::FORWARDED_PROTO],
    attribute: 'ip',
);
```

| Parameter | Default | Description |
|---|---|---|
| `trustedProxies` | (required) | IP addresses or CIDR ranges of the proxies. An invalid entry throws an `InvalidArgumentException`. |
| `headers` | all four | Headers taken into account: `FORWARDED_FOR`, `FORWARDED_PROTO`, `FORWARDED_HOST`, `FORWARDED_PORT`. Leave out the ones your proxy does not set. |
| `attribute` | `'client_ip'` | Name of the request attribute receiving the client IP. |

## Limits

The standard `Forwarded` header (RFC 7239) is not supported in this version: only the
`X-Forwarded-*` headers are read.

## Development

```bash
composer install
composer test-all   # security audit, code style, static analysis, unit tests, magic numbers
```

## License

MIT
