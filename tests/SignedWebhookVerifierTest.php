<?php

declare(strict_types=1);

namespace Compwright\EasyWebhook;

use DateTimeImmutable;
use DateTimeInterface;
use GuzzleHttp\Psr7\Request;
use OpenSSLAsymmetricKey;
use PHPUnit\Framework\TestCase;
use RuntimeException;

class SignedWebhookVerifierTest extends TestCase
{
    public function testExpired(): void
    {
        $request = new SignedWebhook(
            new Request(
                'POST',
                '/',
                [
                    'x-webhook-timestamp' => (new DateTimeImmutable('-6 minute UTC'))->format(DateTimeInterface::ISO8601)
                ]
            )
        );
        $verifier = new SignedWebhookVerifier();
        $this->expectExceptionObject(new ExpiredWebhookException('Request expired'));
        $verifier($request, '');
    }

    public function testMalformedPem(): void
    {
        $request = new SignedWebhook(
            new Request(
                'POST',
                '/',
                [
                    'x-webhook-timestamp' => (new DateTimeImmutable('-4 minute UTC'))->format(DateTimeInterface::ISO8601)
                ]
            )
        );
        $verifier = new SignedWebhookVerifier();
        $this->expectExceptionObject(new SignatureException('Error loading public key: error:1E08010C:DECODER routines::unsupported'));
        $verifier($request, 'foo');
    }

    private function getPrivateKey(): OpenSSLAsymmetricKey
    {
        $pk = openssl_pkey_new();

        if (false === $pk) {
            throw new RuntimeException('Failed to generate private key: ' . openssl_error_string());
        }

        return $pk;
    }

    private function getPublicKey(OpenSSLAsymmetricKey $pk): OpenSSLAsymmetricKey
    {
        $details = openssl_pkey_get_details($pk);

        if (false === $details) {
            throw new RuntimeException('Failed to read public key details: ' . openssl_error_string());
        }

        $pubkey = openssl_pkey_get_public($details['key']);

        if (false === $pubkey) {
            throw new RuntimeException('Failed to read public key PEM: ' . openssl_error_string());
        }

        return $pubkey;
    }

    public function testMalformedSignature(): void
    {
        $key = $this->getPublicKey($this->getPrivateKey());
        $request = new SignedWebhook(
            new Request(
                'POST',
                '/',
                [
                    'x-webhook-timestamp' => (new DateTimeImmutable('-4 minute UTC'))->format(DateTimeInterface::ISO8601),
                    'x-webhook-signature' => 'foo%',
                ]
            )
        );
        $verifier = new SignedWebhookVerifier();
        $this->expectExceptionObject(new HeaderException('Invalid signature format'));
        $verifier($request, $key);
    }

    public function testValid(): void
    {
        $pk = $this->getPrivateKey();
        $ts = (new DateTimeImmutable('-4 minute UTC'))->format(DateTimeInterface::ISO8601);
        $body = 'foo';
        $dataToSign = $ts . '.' . $body;
        $sig = '';
        $ok = openssl_sign($dataToSign, $sig, $pk, OPENSSL_ALGO_SHA256);
        if (false === $ok) {
            throw new RuntimeException('Signature generation failed: ' . openssl_error_string());
        }
        $request = new SignedWebhook(
            new Request(
                'POST',
                '/',
                [
                    'x-webhook-timestamp' => $ts,
                    'x-webhook-signature' => base64_encode($sig),
                ],
                $body
            )
        );
        $verifier = new SignedWebhookVerifier();
        $verifier($request, $this->getPublicKey($pk));
        // @phpstan-ignore-next-line method.alreadyNarrowedType
        $this->assertTrue(true);
    }

    public function testInvalid(): void
    {
        $pk = $this->getPrivateKey();
        $ts = (new DateTimeImmutable('-4 minute UTC'))->format(DateTimeInterface::ISO8601);
        $body = 'foo';
        $dataToSign = $ts . '.' . $body;
        $sig = '';
        $ok = openssl_sign($dataToSign, $sig, $pk, OPENSSL_ALGO_SHA256);
        if (false === $ok) {
            throw new RuntimeException('Signature generation failed: ' . openssl_error_string());
        }
        $request = new SignedWebhook(
            new Request(
                'POST',
                '/',
                [
                    'x-webhook-timestamp' => $ts,
                    'x-webhook-signature' => base64_encode($sig . 'foo'),
                ],
                $body
            )
        );
        $verifier = new SignedWebhookVerifier();
        $this->expectExceptionObject(new SignatureException('Invalid signature'));
        $verifier($request, $this->getPublicKey($pk));
    }
}
