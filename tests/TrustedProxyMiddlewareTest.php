<?php

declare(strict_types=1);

namespace G\TrustedProxyMiddleware\Tests;

use G\TrustedProxyMiddleware\Tests\Fixtures\{RecordingHandler, ServerRequest, Uri};
use G\TrustedProxyMiddleware\TrustedProxyMiddleware;
use InvalidArgumentException;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;

final class TrustedProxyMiddlewareTest extends TestCase
{
    private const array PROXIES = ['10.0.0.0/8', '172.18.0.5', '2001:db8::/32'];

    /**
     * @param array<string, string|list<string>> $headers
     */
    private function request(?string $remoteAddr, array $headers = [], string $uri = 'http://internal:8080/path?q=1'): ServerRequest
    {
        return new ServerRequest(
            new Uri($uri),
            $remoteAddr !== null ? ['REMOTE_ADDR' => $remoteAddr] : [],
            $headers
        );
    }

    /**
     * @param list<string>|null $headers
     */
    private function process(ServerRequestInterface $request, ?array $headers = null, string $attribute = TrustedProxyMiddleware::ATTRIBUTE): ServerRequestInterface
    {
        $middleware = $headers === null
            ? new TrustedProxyMiddleware(self::PROXIES, attribute: $attribute)
            : new TrustedProxyMiddleware(self::PROXIES, $headers, $attribute);
        $response = $this->createStub(ResponseInterface::class);
        $handler = new RecordingHandler($response);

        $this->assertSame($response, $middleware->process($request, $handler));

        return $handler->received();
    }

    // --- Direct connection not trusted

    public function testUntrustedDirectIpIgnoresForgedHeaders(): void
    {
        $request = $this->request('203.0.113.7', [
            'X-Forwarded-For' => '1.2.3.4',
            'X-Forwarded-Proto' => 'https',
            'X-Forwarded-Host' => 'evil.example',
            'X-Forwarded-Port' => '443',
        ]);

        $received = $this->process($request);

        $this->assertSame('203.0.113.7', $received->getAttribute('client_ip'));
        $this->assertSame($request->getUri(), $received->getUri());
    }

    public function testMissingOrInvalidDirectIpLeavesTheRequestUntouched(): void
    {
        foreach ([null, 'not-an-ip', ''] as $remoteAddr) {
            $request = $this->request($remoteAddr, ['X-Forwarded-For' => '1.2.3.4']);

            $received = $this->process($request);

            $this->assertNull($received->getAttribute('client_ip'));
            $this->assertSame($request->getUri(), $received->getUri());
        }
    }

    public function testNonStringDirectIpIsIgnored(): void
    {
        $request = new ServerRequest(new Uri('http://internal/'), ['REMOTE_ADDR' => 42]);

        $this->assertNull($this->process($request)->getAttribute('client_ip'));
    }

    // --- X-Forwarded-For

    /**
     * @return array<string, array{string|list<string>, string}>
     */
    public static function forwardedFor(): array
    {
        return [
            'single client' => ['198.51.100.1', '198.51.100.1'],
            'chain of proxies' => ['198.51.100.1, 10.1.2.3, 172.18.0.5', '198.51.100.1'],
            'spoofed leftmost entry' => ['6.6.6.6, 198.51.100.1, 10.0.0.2', '198.51.100.1'],
            'several header lines' => [['198.51.100.1', '10.0.0.2'], '198.51.100.1'],
            'all trusted: leftmost' => ['10.0.0.3, 10.0.0.2', '10.0.0.3'],
            'invalid entry stops the walk' => ['198.51.100.1, garbage, 10.0.0.2', '10.0.0.2'],
            'invalid last entry: direct ip' => ['198.51.100.1, garbage', '10.0.0.1'],
            'empty header: direct ip' => ['', '10.0.0.1'],
            'ipv6 client' => ['2001:DB9:0:0::1', '2001:db9::1'],
            'ipv6 proxy in the chain' => ['198.51.100.1, 2001:db8::7', '198.51.100.1'],
            'ipv4-mapped client' => ['::ffff:198.51.100.1', '198.51.100.1'],
            'ipv4-mapped proxy' => ['198.51.100.1, ::ffff:10.0.0.9', '198.51.100.1'],
            'port appended' => ['198.51.100.1:5678, [2001:db8::7]:443', '198.51.100.1'],
        ];
    }

    /**
     * @param string|list<string> $header
     */
    #[DataProvider('forwardedFor')]
    public function testForwardedFor(string|array $header, string $expected): void
    {
        $received = $this->process($this->request('10.0.0.1', ['X-Forwarded-For' => $header]));

        $this->assertSame($expected, $received->getAttribute('client_ip'));
    }

    public function testWithoutForwardedForTheClientIsTheDirectIp(): void
    {
        $this->assertSame('10.0.0.1', $this->process($this->request('10.0.0.1'))->getAttribute('client_ip'));
    }

    public function testDirectIpIsCanonicalized(): void
    {
        $received = $this->process($this->request('2001:0DB8:0:0:0:0:0:1'));

        $this->assertSame('2001:db8::1', $received->getAttribute('client_ip'));
    }

    public function testDirectIpv4MappedProxyIsTrusted(): void
    {
        $received = $this->process($this->request('::ffff:10.0.0.1', ['X-Forwarded-For' => '198.51.100.1']));

        $this->assertSame('198.51.100.1', $received->getAttribute('client_ip'));
    }

    public function testCustomAttribute(): void
    {
        $received = $this->process($this->request('10.0.0.1', ['X-Forwarded-For' => '198.51.100.1']), attribute: 'ip');

        $this->assertSame('198.51.100.1', $received->getAttribute('ip'));
        $this->assertNull($received->getAttribute('client_ip'));
    }

    // --- X-Forwarded-Proto, X-Forwarded-Host, X-Forwarded-Port

    public function testProtoSwitchesSchemeAndFallsBackToTheDefaultPort(): void
    {
        $received = $this->process($this->request('10.0.0.1', ['X-Forwarded-Proto' => 'HTTPS']));

        $this->assertSame('https', $received->getUri()->getScheme());
        $this->assertNull($received->getUri()->getPort());
        $this->assertSame('/path', $received->getUri()->getPath());
        $this->assertSame('q=1', $received->getUri()->getQuery());
    }

    public function testProtoUsesTheFirstValue(): void
    {
        $received = $this->process($this->request('10.0.0.1', ['X-Forwarded-Proto' => 'https, http']));

        $this->assertSame('https', $received->getUri()->getScheme());
    }

    public function testInvalidProtoIsIgnored(): void
    {
        $request = $this->request('10.0.0.1', ['X-Forwarded-Proto' => 'ftp']);

        $this->assertSame($request->getUri(), $this->process($request)->getUri());
    }

    public function testSameSchemeKeepsThePort(): void
    {
        $request = $this->request('10.0.0.1', ['X-Forwarded-Proto' => 'http']);

        $this->assertSame(8080, $this->process($request)->getUri()->getPort());
    }

    public function testHostAndPort(): void
    {
        $received = $this->process($this->request('10.0.0.1', [
            'X-Forwarded-Proto' => 'https',
            'X-Forwarded-Host' => 'WWW.Example.com',
            'X-Forwarded-Port' => '8443',
        ]));

        $this->assertSame('https://www.example.com:8443/path?q=1', (string) $received->getUri());
        $this->assertSame('www.example.com:8443', $received->getHeaderLine('Host'));
    }

    public function testHostWithoutPortFallsBackToTheDefaultPort(): void
    {
        $received = $this->process($this->request('10.0.0.1', ['X-Forwarded-Host' => 'example.com']));

        $this->assertSame('http://example.com/path?q=1', (string) $received->getUri());
    }

    public function testPortCarriedByTheHost(): void
    {
        $received = $this->process($this->request('10.0.0.1', ['X-Forwarded-Host' => 'example.com:9000']));

        $this->assertSame('example.com', $received->getUri()->getHost());
        $this->assertSame(9000, $received->getUri()->getPort());
    }

    public function testForwardedPortWinsOverThePortOfTheHost(): void
    {
        $received = $this->process($this->request('10.0.0.1', [
            'X-Forwarded-Host' => 'example.com:9000',
            'X-Forwarded-Port' => '9001',
        ]));

        $this->assertSame(9001, $received->getUri()->getPort());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function validHosts(): array
    {
        return [
            'ipv4' => ['192.0.2.10'],
            'ipv6' => ['[2001:db8::1]'],
            'single label' => ['localhost'],
            'trailing dot' => ['example.com.'],
        ];
    }

    #[DataProvider('validHosts')]
    public function testValidHosts(string $host): void
    {
        $received = $this->process($this->request('10.0.0.1', ['X-Forwarded-Host' => $host]));

        $this->assertSame($host, $received->getUri()->getHost());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidHosts(): array
    {
        return [
            'empty' => [''],
            'path injection' => ['example.com/evil'],
            'user info' => ['user@example.com'],
            'space' => ['exa mple.com'],
            'underscore' => ['exa_mple.com'],
            'leading hyphen' => ['-example.com'],
            'bad port' => ['example.com:99999'],
            'empty port' => ['example.com:'],
            'bracketed non ipv6' => ['[example.com]'],
            'unbracketed ipv6' => ['2001:db8::1'],
        ];
    }

    #[DataProvider('invalidHosts')]
    public function testInvalidHostIsIgnored(string $host): void
    {
        $request = $this->request('10.0.0.1', ['X-Forwarded-Host' => $host]);

        $this->assertSame($request->getUri(), $this->process($request)->getUri());
    }

    /**
     * @return array<string, array{string}>
     */
    public static function invalidPorts(): array
    {
        return [
            'zero' => ['0'],
            'too big' => ['65536'],
            'negative' => ['-1'],
            'not a number' => ['https'],
            'empty' => [''],
        ];
    }

    #[DataProvider('invalidPorts')]
    public function testInvalidPortIsIgnored(string $port): void
    {
        $request = $this->request('10.0.0.1', ['X-Forwarded-Port' => $port]);

        $this->assertSame($request->getUri(), $this->process($request)->getUri());
    }

    // --- Headers can be disabled

    public function testEachHeaderCanBeDisabled(): void
    {
        $headers = [
            'X-Forwarded-For' => '198.51.100.1',
            'X-Forwarded-Proto' => 'https',
            'X-Forwarded-Host' => 'example.com',
            'X-Forwarded-Port' => '8443',
        ];

        $received = $this->process($this->request('10.0.0.1', $headers), []);
        $this->assertSame('10.0.0.1', $received->getAttribute('client_ip'));
        $this->assertSame('http://internal:8080/path?q=1', (string) $received->getUri());

        $received = $this->process($this->request('10.0.0.1', $headers), [TrustedProxyMiddleware::FORWARDED_FOR]);
        $this->assertSame('198.51.100.1', $received->getAttribute('client_ip'));
        $this->assertSame('http://internal:8080/path?q=1', (string) $received->getUri());

        $received = $this->process($this->request('10.0.0.1', $headers), ['x-forwarded-proto']);
        $this->assertSame('10.0.0.1', $received->getAttribute('client_ip'));
        $this->assertSame('https://internal/path?q=1', (string) $received->getUri());

        $received = $this->process($this->request('10.0.0.1', $headers), [TrustedProxyMiddleware::FORWARDED_HOST]);
        $this->assertSame('http://example.com/path?q=1', (string) $received->getUri());

        $received = $this->process($this->request('10.0.0.1', $headers), [TrustedProxyMiddleware::FORWARDED_PORT]);
        $this->assertSame('http://internal:8443/path?q=1', (string) $received->getUri());
    }

    // --- Configuration

    /**
     * @return array<string, array{string}>
     */
    public static function invalidProxies(): array
    {
        return [
            'not an ip' => ['proxy.local'],
            'empty' => [''],
            'ipv4 prefix too long' => ['10.0.0.0/33'],
            'ipv6 prefix too long' => ['::1/129'],
            'negative prefix' => ['10.0.0.0/-1'],
            'non numeric prefix' => ['10.0.0.0/abc'],
            'empty prefix' => ['10.0.0.0/'],
            'mapped prefix too short' => ['::ffff:10.0.0.0/95'],
        ];
    }

    #[DataProvider('invalidProxies')]
    public function testInvalidTrustedProxyIsRejected(string $proxy): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TrustedProxyMiddleware([$proxy]);
    }

    public function testUnsupportedHeaderIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->expectExceptionMessage('Forwarded');

        new TrustedProxyMiddleware(['10.0.0.1'], ['Forwarded']);
    }

    public function testEmptyAttributeIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);

        new TrustedProxyMiddleware(['10.0.0.1'], attribute: '');
    }

    public function testIpv4MappedRangeIsStoredAsIpv4(): void
    {
        $middleware = new TrustedProxyMiddleware(['::ffff:10.0.0.0/104']);
        $handler = new RecordingHandler($this->createStub(ResponseInterface::class));

        $middleware->process($this->request('10.20.30.40', ['X-Forwarded-For' => '198.51.100.1']), $handler);

        $this->assertSame('198.51.100.1', $handler->received()->getAttribute('client_ip'));
    }

    public function testInstanceIsReusable(): void
    {
        $middleware = new TrustedProxyMiddleware(self::PROXIES);
        $handler = new RecordingHandler($this->createStub(ResponseInterface::class));

        $middleware->process($this->request('10.0.0.1', ['X-Forwarded-For' => '198.51.100.1', 'X-Forwarded-Proto' => 'https']), $handler);
        $first = $handler->received();
        $middleware->process($this->request('203.0.113.7', ['X-Forwarded-For' => '198.51.100.1']), $handler);
        $second = $handler->received();

        $this->assertSame('198.51.100.1', $first->getAttribute('client_ip'));
        $this->assertSame('https', $first->getUri()->getScheme());
        $this->assertSame('203.0.113.7', $second->getAttribute('client_ip'));
        $this->assertSame('http', $second->getUri()->getScheme());
    }
}
