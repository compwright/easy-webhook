<?php

declare(strict_types=1);

namespace Compwright\EasyWebhook;

use Psr\Http\Message\RequestInterface;

/**
 * @property RequestInterface $request
 *
 * @phpstan-ignore-next-line trait.unused
 */
trait RequiredHeaderTrait
{
    /**
     * @throws HeaderException
     */
    protected function getRequiredHeader(string $header): string
    {
        if (!$this->request->hasHeader($header)) {
            throw new HeaderException('Missing required header: ' . $header);
        }

        $value = $this->request->getHeaderLine($header);

        if (empty($value)) {
            throw new HeaderException('Required header is blank: ' . $header);
        }

        return $value;
    }
}
