<?php

declare(strict_types=1);

namespace Compwright\EasyWebhook;

use Exception;

class ExpiredWebhookException extends Exception implements WebhookExceptionInterface
{
}
