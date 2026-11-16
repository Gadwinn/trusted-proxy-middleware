<?php

declare(strict_types=1);

namespace G\TrustedProxyMiddleware;

use InvalidArgumentException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\UriInterface;
use Psr\Http\Server\MiddlewareInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Behind a reverse proxy, PHP sees the IP address and the scheme of the proxy. This middleware
 * reads the X-Forwarded-* headers only when the request comes from a declared proxy, then
 * fixes the request for the rest of the stack: client IP in an attribute, scheme, host and
 * port of the URI.
 *
 * Stateless: one instance can serve any number of requests (worker mode).
 */
final class TrustedProxyMiddleware implements MiddlewareInterface
{
    public const string ATTRIBUTE = 'client_ip';

    public const string FORWARDED_FOR = 'X-Forwarded-For';
    public const string FORWARDED_PROTO = 'X-Forwarded-Proto';
    public const string FORWARDED_HOST = 'X-Forwarded-Host';
    public const string FORWARDED_PORT = 'X-Forwarded-Port';

    private const array SUPPORTED_HEADERS = [
        self::FORWARDED_FOR,
        self::FORWARDED_PROTO,
        self::FORWARDED_HOST,
        self::FORWARDED_PORT,
    ];
    private const array SCHEMES = ['http', 'https'];
    private const int PORT_MIN = 1;
    private const int PORT_MAX = 65535;
    private const int BITS_PER_BYTE = 8;
    private const int BYTE_MASK = 0xFF;
    /** "::ffff:" prefix of an IPv4-mapped IPv6 address: length in bytes and bits, binary value */
    private const int MAPPED_PREFIX_BYTES = 12;
    private const int MAPPED_PREFIX_BITS = 96;
    private const string MAPPED_PREFIX = "\0\0\0\0\0\0\0\0\0\0\xFF\xFF";
    private const string HOSTNAME_PATTERN =
        '/^(?=.{1,253}\.?$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*\.?$/iD';

    /** @var list<array{string, int}> Trusted networks: binary address and prefix length in bits */
    private readonly array $networks;

    /** @var array<string, true> Enabled headers, by lowercase name */
    private readonly array $enabled;

    /**
     * @param list<string> $trustedProxies IP addresses or CIDR ranges (IPv4/IPv6) of the proxies,
     *                                     e.g. ['172.18.0.0/16', '::1']
     * @param list<string> $headers        Headers taken into account, all by default
     * @param string       $attribute      Name of the request attribute receiving the client IP
     *
     * @throws InvalidArgumentException On an invalid IP address, CIDR range or header name.
     */
    public function __construct(
        array $trustedProxies,
        array $headers = [self::FORWARDED_FOR, self::FORWARDED_PROTO, self::FORWARDED_HOST, self::FORWARDED_PORT],
        private readonly string $attribute = self::ATTRIBUTE,
    ) {
        $networks = [];
        foreach ($trustedProxies as $proxy) {
            $networks[] = $this->parseNetwork($proxy);
        }
        $this->networks = $networks;

        $supported = array_map('strtolower', self::SUPPORTED_HEADERS);
        $enabled = [];
        foreach ($headers as $header) {
            $name = strtolower($header);
            if (!in_array($name, $supported, true)) {
                throw new InvalidArgumentException(
                    "Unsupported header '$header', expected one of: " . implode(', ', self::SUPPORTED_HEADERS)
                );
            }
            $enabled[$name] = true;
        }
        $this->enabled = $enabled;

        if ($this->attribute === '') {
            throw new InvalidArgumentException('The attribute name cannot be empty');
        }
    }

    public function process(ServerRequestInterface $request, RequestHandlerInterface $handler): ResponseInterface
    {
        $remoteAddr = $request->getServerParams()['REMOTE_ADDR'] ?? null;
        $directIp = is_string($remoteAddr) ? $this->normalizeIp($remoteAddr) : null;

        if ($directIp === null) {
            return $handler->handle($request);
        }

        if (!$this->isTrusted($directIp)) {
            return $handler->handle($request->withAttribute($this->attribute, $directIp));
        }

        $clientIp = $this->isEnabled(self::FORWARDED_FOR)
            ? $this->resolveClientIp($request, $directIp)
            : $directIp;

        $uri = $this->resolveUri($request);
        if ($uri !== $request->getUri()) {
            $request = $request->withUri($uri);
        }

        return $handler->handle($request->withAttribute($this->attribute, $clientIp));
    }

    /**
     * Walks X-Forwarded-For from right to left, skipping the trusted proxies: the first
     * address which is not a trusted proxy is the client. An invalid entry stops the walk
     * (the last valid address is kept); when every address is trusted, the leftmost wins.
     */
    private function resolveClientIp(ServerRequestInterface $request, string $directIp): string
    {
        $entries = explode(',', implode(',', $request->getHeader(self::FORWARDED_FOR)));
        $clientIp = $directIp;

        foreach (array_reverse($entries) as $entry) {
            $ip = $this->normalizeIp($this->stripPort(trim($entry)));
            if ($ip === null) {
                break;
            }

            $clientIp = $ip;
            if (!$this->isTrusted($ip)) {
                break;
            }
        }

        return $clientIp;
    }

    /**
     * Applies X-Forwarded-Proto, X-Forwarded-Host and X-Forwarded-Port to the URI. Without a
     * forwarded port, a changed scheme or host falls back to the default port of the scheme,
     * the port seen by PHP being the one of the proxy.
     */
    private function resolveUri(ServerRequestInterface $request): UriInterface
    {
        $uri = $request->getUri();
        $changed = false;

        $scheme = $this->isEnabled(self::FORWARDED_PROTO)
            ? strtolower($this->firstValue($request, self::FORWARDED_PROTO))
            : '';
        if (in_array($scheme, self::SCHEMES, true) && $scheme !== $uri->getScheme()) {
            $uri = $uri->withScheme($scheme);
            $changed = true;
        }

        $hostPort = null;
        $host = $this->isEnabled(self::FORWARDED_HOST)
            ? $this->parseHost($this->firstValue($request, self::FORWARDED_HOST))
            : null;
        if ($host !== null) {
            [$hostName, $hostPort] = $host;
            if ($hostName !== $uri->getHost()) {
                $uri = $uri->withHost($hostName);
                $changed = true;
            }
        }

        $port = $this->isEnabled(self::FORWARDED_PORT)
            ? $this->parsePort($this->firstValue($request, self::FORWARDED_PORT))
            : null;
        $port ??= $hostPort;

        if ($port !== null) {
            return $port !== $uri->getPort() ? $uri->withPort($port) : $uri;
        }

        return $changed && $uri->getPort() !== null ? $uri->withPort(null) : $uri;
    }

    /**
     * First value of a header which may hold a comma separated list.
     */
    private function firstValue(ServerRequestInterface $request, string $header): string
    {
        $line = $request->getHeaderLine($header);

        return trim(explode(',', $line, 2)[0]);
    }

    /**
     * Validates a "host[:port]" value: host name, IPv4 address or bracketed IPv6 address.
     *
     * @return array{string, ?int}|null The lowercase host and the port, if any; null when invalid.
     */
    private function parseHost(string $value): ?array
    {
        if ($value === '') {
            return null;
        }

        $port = null;
        if (preg_match('/^(\[[^\]]+\]|[^:]+)(?::([^:]*))?$/D', $value, $matches) !== 1) {
            return null;
        }

        if (isset($matches[2])) {
            $port = $this->parsePort($matches[2]);
            if ($port === null) {
                return null;
            }
        }

        $host = strtolower($matches[1]);
        if (str_starts_with($host, '[')) {
            return filter_var(substr($host, 1, -1), FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false
                ? [$host, $port]
                : null;
        }

        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return [$host, $port];
        }

        return preg_match(self::HOSTNAME_PATTERN, $host) === 1 ? [$host, $port] : null;
    }

    private function parsePort(string $value): ?int
    {
        if (!ctype_digit($value)) {
            return null;
        }

        $port = (int) $value;

        return $port >= self::PORT_MIN && $port <= self::PORT_MAX ? $port : null;
    }

    private function isEnabled(string $header): bool
    {
        return isset($this->enabled[strtolower($header)]);
    }

    /**
     * Removes the port some proxies append to an address ("1.2.3.4:5678", "[::1]:80").
     */
    private function stripPort(string $address): string
    {
        if (preg_match('/^\[([^\]]+)\](?::\d+)?$/D', $address, $matches) === 1) {
            return $matches[1];
        }

        if (preg_match('/^([0-9.]+):\d+$/D', $address, $matches) === 1) {
            return $matches[1];
        }

        return $address;
    }

    private function isTrusted(string $ip): bool
    {
        $binary = inet_pton($ip);
        if ($binary === false) {
            return false;
        }

        foreach ($this->networks as [$network, $prefix]) {
            if ($this->matches($binary, $network, $prefix)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Tests whether a binary address belongs to a binary network of the given prefix length.
     */
    private function matches(string $binary, string $network, int $prefix): bool
    {
        if (strlen($binary) !== strlen($network)) {
            return false;
        }

        $fullBytes = intdiv($prefix, self::BITS_PER_BYTE);
        $remainingBits = $prefix % self::BITS_PER_BYTE;

        if ($fullBytes > 0 && substr($binary, 0, $fullBytes) !== substr($network, 0, $fullBytes)) {
            return false;
        }

        if ($remainingBits > 0) {
            $mask = self::BYTE_MASK & (self::BYTE_MASK << (self::BITS_PER_BYTE - $remainingBits));

            return (ord($binary[$fullBytes]) & $mask) === (ord($network[$fullBytes]) & $mask);
        }

        return true;
    }

    /**
     * @return array{string, int} Binary network address and prefix length in bits
     *
     * @throws InvalidArgumentException
     */
    private function parseNetwork(string $proxy): array
    {
        $parts = explode('/', trim($proxy), 2);
        $address = $parts[0];
        $isMapped = $this->isMapped($address);
        $ip = $this->normalizeIp($address);
        $binary = $ip !== null ? inet_pton($ip) : false;

        if ($binary === false) {
            throw new InvalidArgumentException("Invalid trusted proxy '$proxy'");
        }

        $maxBits = strlen($binary) * self::BITS_PER_BYTE;
        if (!isset($parts[1])) {
            return [$binary, $maxBits];
        }

        if (!ctype_digit($parts[1])) {
            throw new InvalidArgumentException("Invalid prefix length in trusted proxy '$proxy'");
        }

        $prefix = (int) $parts[1];
        if ($isMapped) {
            // An IPv4-mapped range ("::ffff:10.0.0.0/104") is stored as an IPv4 range
            $prefix -= self::MAPPED_PREFIX_BITS;
        }

        if ($prefix < 0 || $prefix > $maxBits) {
            throw new InvalidArgumentException("Invalid prefix length in trusted proxy '$proxy'");
        }

        return [$binary, $prefix];
    }

    private function isMapped(string $ip): bool
    {
        $binary = filter_var(trim($ip), FILTER_VALIDATE_IP) !== false ? inet_pton(trim($ip)) : false;

        return $binary !== false && str_starts_with($binary, self::MAPPED_PREFIX);
    }

    /**
     * Validates an IP address and returns its canonical form, an IPv4-mapped IPv6 address
     * ("::ffff:1.2.3.4") being turned into the IPv4 address.
     */
    private function normalizeIp(string $ip): ?string
    {
        $trimmed = trim($ip);

        if ($trimmed === '' || filter_var($trimmed, FILTER_VALIDATE_IP) === false) {
            return null;
        }

        $binary = inet_pton($trimmed);
        if ($binary === false) {
            return null;
        }

        if (str_starts_with($binary, self::MAPPED_PREFIX)) {
            $binary = substr($binary, self::MAPPED_PREFIX_BYTES);
        }

        $canonical = inet_ntop($binary);

        return $canonical !== false ? $canonical : null;
    }
}
