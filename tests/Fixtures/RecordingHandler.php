<?php

declare(strict_types=1);

namespace G\TrustedProxyMiddleware\Tests\Fixtures;

use LogicException;
use Psr\Http\Message\ResponseInterface;
use Psr\Http\Message\ServerRequestInterface;
use Psr\Http\Server\RequestHandlerInterface;

/**
 * Records the request it receives; the response is a PHPUnit stub given by the test.
 */
final class RecordingHandler implements RequestHandlerInterface
{
    public ?ServerRequestInterface $request = null;

    public function __construct(private readonly ResponseInterface $response)
    {
    }

    public function handle(ServerRequestInterface $request): ResponseInterface
    {
        $this->request = $request;

        return $this->response;
    }

    public function received(): ServerRequestInterface
    {
        return $this->request ?? throw new LogicException('The handler was not called');
    }
}
