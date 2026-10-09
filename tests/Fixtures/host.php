<?php

declare(strict_types=1);

use Naf\Auth\Credentials\CredentialsInterface;
use Naf\Auth\Identity\Identity;
use Naf\Auth\Identity\IdentityInterface;
use Naf\Auth\Provider\ProviderInterface;
use Naf\Auth\Support\PasswordHasher;
use Naf\CLI\Core\Console;
use Naf\MCP\Tools\ScopedToolInterface;
use Naf\MCP\Tools\UserToolInterface;

use function Naf\app;
use function Naf\Auth\auth;
use function Naf\MCP\tool;
use function Naf\OAuth\Server\token;

define('BASE_PATH', getenv('NAF_ALEXA_HOST_ROOT'));
require dirname(__DIR__, 2) . '/vendor/autoload.php';

app()->container()->set(PasswordHasher::class, new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]));
auth()->addProvider('test', new class implements ProviderInterface {
    public function authenticate(#[SensitiveParameter] CredentialsInterface $credentials): ?IdentityInterface
    {
        return null;
    }

    public function find(string $identifier): ?IdentityInterface
    {
        return $identifier === '42' ? new Identity('42', permissions: ['mcp:tools']) : null;
    }
});
tool()->register(new class implements UserToolInterface, ScopedToolInterface {
    public function name(): string
    {
        return 'my_account';
    }

    public function description(): string
    {
        return 'Read your own account identifier.';
    }

    public function inputSchema(): array
    {
        return ['type' => 'object', 'properties' => []];
    }

    public function requiredScopes(): array
    {
        return ['mcp:tools'];
    }

    public function handle(array $args): mixed
    {
        return ['account' => token()->user()->getIdentifier()];
    }
});

if (PHP_SAPI === 'cli') {
    exit(app()->container()->make(Console::class)->run($argv));
}
app()->run();
