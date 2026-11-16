<?php

declare(strict_types=1);

namespace G\TrustedProxyMiddleware\Tests\Fixtures;

use Psr\Http\Message\UriInterface;

final class Uri implements UriInterface
{
    /** @var array<string, int|string> */
    private array $parts;

    public function __construct(string $uri = '')
    {
        $this->parts = parse_url($uri) ?: [];
    }

    public function getScheme(): string
    {
        return (string) ($this->parts['scheme'] ?? '');
    }

    public function getAuthority(): string
    {
        $authority = $this->getHost();
        if ($this->getUserInfo() !== '') {
            $authority = $this->getUserInfo() . '@' . $authority;
        }

        return $this->getPort() !== null ? $authority . ':' . $this->getPort() : $authority;
    }

    public function getUserInfo(): string
    {
        $user = (string) ($this->parts['user'] ?? '');

        return isset($this->parts['pass']) ? $user . ':' . $this->parts['pass'] : $user;
    }

    public function getHost(): string
    {
        return (string) ($this->parts['host'] ?? '');
    }

    public function getPort(): ?int
    {
        return isset($this->parts['port']) ? (int) $this->parts['port'] : null;
    }

    public function getPath(): string
    {
        return (string) ($this->parts['path'] ?? '');
    }

    public function getQuery(): string
    {
        return (string) ($this->parts['query'] ?? '');
    }

    public function getFragment(): string
    {
        return (string) ($this->parts['fragment'] ?? '');
    }

    public function withScheme(string $scheme): static
    {
        return $this->with('scheme', $scheme);
    }

    public function withUserInfo(string $user, ?string $password = null): static
    {
        $new = $this->with('user', $user);
        $new->parts['pass'] = (string) $password;

        return $new;
    }

    public function withHost(string $host): static
    {
        return $this->with('host', $host);
    }

    public function withPort(?int $port): static
    {
        if ($port === null) {
            $new = clone $this;
            unset($new->parts['port']);

            return $new;
        }

        return $this->with('port', $port);
    }

    public function withPath(string $path): static
    {
        return $this->with('path', $path);
    }

    public function withQuery(string $query): static
    {
        return $this->with('query', $query);
    }

    public function withFragment(string $fragment): static
    {
        return $this->with('fragment', $fragment);
    }

    public function __toString(): string
    {
        $uri = $this->getScheme() !== '' ? $this->getScheme() . ':' : '';
        $uri .= $this->getAuthority() !== '' ? '//' . $this->getAuthority() : '';
        $uri .= $this->getPath();
        $uri .= $this->getQuery() !== '' ? '?' . $this->getQuery() : '';

        return $uri . ($this->getFragment() !== '' ? '#' . $this->getFragment() : '');
    }

    private function with(string $part, int|string $value): static
    {
        $new = clone $this;
        $new->parts[$part] = $value;

        return $new;
    }
}
