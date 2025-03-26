<?php

declare(strict_types=1);

namespace Compwright\EasyWebhook;

interface SignedWebhookInterface
{
    public function getTimestamp(): string;

    public function getSignature(): string;

    public function getAlgorithm(): int;

    public function getPublicKeyId(): string;

    public function getDataToSign(): string;
}
