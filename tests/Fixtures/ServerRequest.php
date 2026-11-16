<?php

declare(strict_types=1);

namespace G\TrustedProxyMiddleware\Tests\Fixtures;

use LogicException;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Message\StreamInterface;
use Psr\Http\Message\UriInterface;

/**
 * Minimal PSR-7 server request used by the tests (no concrete implementation is required).
 */
final class ServerRequest implements ServerRequestInterface
{
    /** @var array<string, list<string>> */
    private array $headers = [];

    /** @var array<string, mixed> */
    private array $attributes = [];

    /**
     * @param array<string, mixed> $serverParams
     * @param array<string, string|list<string>> $headers
     */
    public function __construct(private UriInterface $uri, private array $serverParams = [], array $headers = [])
    {
        foreach ($headers as $name => $value) {
            $this->headers[$name] = array_values((array) $value);
        }
    }

    public function getProtocolVersion(): string
    {
        return '1.1';
    }

    public function withProtocolVersion(string $version): static
    {
        return $this;
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function hasHeader(string $name): bool
    {
        return $this->findHeader($name) !== null;
    }

    public function getHeader(string $name): array
    {
        $found = $this->findHeader($name);

        return $found !== null ? $this->headers[$found] : [];
    }

    public function getHeaderLine(string $name): string
    {
        return implode(', ', $this->getHeader($name));
    }

    public function withHeader(string $name, $value): static
    {
        $new = $this->withoutHeader($name);
        $new->headers[$name] = array_values(array_map('strval', (array) $value));

        return $new;
    }

    public function withAddedHeader(string $name, $value): static
    {
        return $this->withHeader($name, [...$this->getHeader($name), ...array_map('strval', (array) $value)]);
    }

    public function withoutHeader(string $name): static
    {
        $new = clone $this;
        $found = $this->findHeader($name);
        if ($found !== null) {
            unset($new->headers[$found]);
        }

        return $new;
    }

    public function getBody(): StreamInterface
    {
        throw new LogicException('Not used by the tests');
    }

    public function withBody(StreamInterface $body): static
    {
        throw new LogicException('Not used by the tests');
    }

    public function getRequestTarget(): string
    {
        return '/';
    }

    public function withRequestTarget(string $requestTarget): static
    {
        return $this;
    }

    public function getMethod(): string
    {
        return 'GET';
    }

    public function withMethod(string $method): static
    {
        return $this;
    }

    public function getUri(): UriInterface
    {
        return $this->uri;
    }

    public function withUri(UriInterface $uri, bool $preserveHost = false): static
    {
        $new = clone $this;
        $new->uri = $uri;
        if (!$preserveHost && $uri->getHost() !== '') {
            $new = $new->withHeader('Host', $uri->getPort() !== null ? $uri->getHost() . ':' . $uri->getPort() : $uri->getHost());
        }

        return $new;
    }

    public function getServerParams(): array
    {
        return $this->serverParams;
    }

    public function getCookieParams(): array
    {
        return [];
    }

    public function withCookieParams(array $cookies): static
    {
        return $this;
    }

    public function getQueryParams(): array
    {
        return [];
    }

    public function withQueryParams(array $query): static
    {
        return $this;
    }

    public function getUploadedFiles(): array
    {
        return [];
    }

    public function withUploadedFiles(array $uploadedFiles): static
    {
        return $this;
    }

    public function getParsedBody()
    {
        return null;
    }

    public function withParsedBody($data): static
    {
        return $this;
    }

    public function getAttributes(): array
    {
        return $this->attributes;
    }

    public function getAttribute(string $name, $default = null)
    {
        return array_key_exists($name, $this->attributes) ? $this->attributes[$name] : $default;
    }

    public function withAttribute(string $name, $value): static
    {
        $new = clone $this;
        $new->attributes[$name] = $value;

        return $new;
    }

    public function withoutAttribute(string $name): static
    {
        $new = clone $this;
        unset($new->attributes[$name]);

        return $new;
    }

    private function findHeader(string $name): ?string
    {
        foreach (array_keys($this->headers) as $key) {
            if (strcasecmp($key, $name) === 0) {
                return $key;
            }
        }

        return null;
    }
}
