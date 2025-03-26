<?php

declare(strict_types=1);

namespace Compwright\EasyWebhook;

use DateTimeImmutable;
use OpenSSLAsymmetricKey;

class SignedWebhookVerifier
{
    protected string $expirationThreshold = '-5 minute UTC';

    public function setExpirationThreshold(string $expirationThreshold): self
    {
        $this->expirationThreshold = $expirationThreshold;
        return $this;
    }

    public function __invoke(SignedWebhookInterface $request, OpenSSLAsymmetricKey $key): void
    {
        // Prevent replay attacks
        $threshold = new DateTimeImmutable($this->expirationThreshold);
        if (new DateTimeImmutable($request->getTimestamp()) < $threshold) {
            throw new ExpiredWebhookException('Request expired');
        }

        $signature = base64_decode($request->getSignature(), true);
        if ($signature === false) {
            throw new HeaderException('Invalid signature format');
        }

        // Check the signature
        $ok = openssl_verify(
            $request->getDataToSign(),
            $signature,
            $key,
            $request->getAlgorithm()
        );

        if ($ok === 1) {
            return;
        }

        if ($ok === 0) {
            throw new SignatureException('Invalid signature');
        }

        if ($ok === false) {
            throw new SignatureException(
                openssl_error_string() ?: 'Invalid signature'
            );
        }
    }
}
