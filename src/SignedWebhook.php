<?php

declare(strict_types=1);

namespace Compwright\EasyWebhook;

use DateTimeImmutable;
use Psr\Http\Message\RequestInterface;

class SignedWebhook implements SignedWebhookInterface
{
    use RequiredHeaderTrait;

    protected string $timestampHeader = 'x-webhook-timestamp';
    protected string $signatureHeader = 'x-webhook-signature';
    protected string $publicKeyIdHeader = 'x-webhook-key-id';
    protected int $algorithm = OPENSSL_ALGO_SHA256;

    final public function __construct(private RequestInterface $request)
    {
    }

    public function getTimestamp(): string
    {
        return $this->getRequiredHeader($this->timestampHeader);
    }

    public function getUtcDateTime(): DateTimeImmutable
    {
        return new DateTimeImmutable(
            $this->getTimestamp()
        );
    }

    public function getSignature(): string
    {
        return $this->getRequiredHeader($this->signatureHeader);
    }

    public function getAlgorithm(): int
    {
        return $this->algorithm;
    }

    public function getPublicKeyId(): string
    {
        return $this->getRequiredHeader($this->publicKeyIdHeader);
    }

    public function getDataToSign(): string
    {
        return $this->getTimestamp() . '.' . $this->request->getBody();
    }
}
