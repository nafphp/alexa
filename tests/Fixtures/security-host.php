<?php

declare(strict_types=1);

use Naf\Auth\Credentials\CredentialsInterface;
use Naf\Auth\Credentials\PasswordCredentials;
use Naf\Auth\Identity\Identity;
use Naf\Auth\Identity\IdentityInterface;
use Naf\Auth\Provider\ProviderInterface;
use Naf\Auth\Support\PasswordHasher;
use Naf\CLI\Core\Console;
use Naf\MCP\Auth\AuthorizationException;
use Naf\MCP\Tools\ScopedToolInterface;
use Naf\MCP\Tools\ToolInterface;
use Naf\MCP\Tools\UserToolInterface;

use function Naf\app;
use function Naf\Auth\auth;
use function Naf\Form\csrf;
use function Naf\MCP\tool;
use function Naf\OAuth\Server\token;
use function Naf\param;
use function Naf\redirect;
use function Naf\response;
use function Naf\route;

define('BASE_PATH', getenv('NAF_ALEXA_HOST_ROOT'));
require dirname(__DIR__, 2) . '/vendor/autoload.php';

app()->container()->set(PasswordHasher::class, new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4]));
auth()->addProvider('test', new class implements ProviderInterface {
    public function authenticate(#[SensitiveParameter] CredentialsInterface $credentials): ?IdentityInterface
    {
        return $credentials instanceof PasswordCredentials && $credentials->password === 'test-password'
            ? $this->find($credentials->username) : null;
    }

    public function find(string $identifier): ?IdentityInterface
    {
        $permissions = json_decode(file_get_contents(BASE_PATH . '/permissions.json'), true, 512, JSON_THROW_ON_ERROR);

        return isset($permissions[$identifier]) ? new Identity($identifier, permissions: $permissions[$identifier]) : null;
    }
});
route()->add('GET', '/login', static fn() => response('<form method="post"><input name="_csrf" value="' . csrf()->generate() . '"></form>'), 'login');
route()->add('POST', '/login', static function () {
    $signedIn = auth()->authenticate(new PasswordCredentials((string) param()->get('username'), (string) param()->get('password')), 'test');

    return $signedIn ? redirect('/') : response('Invalid credentials', 401);
}, 'login.submit');
foreach (['public_ping' => [], 'service_ping' => ['mcp:service']] as $name => $scopes) {
    tool()->register(new class ($name, $scopes) implements ToolInterface, ScopedToolInterface {
        public function __construct(private string $toolName, private array $scopes)
        {
        }

        public function name(): string
        {
            return $this->toolName;
        }

        public function description(): string
        {
            return 'Check availability.';
        }

        public function inputSchema(): array
        {
            return ['type' => 'object'];
        }

        public function requiredScopes(): array
        {
            return $this->scopes;
        }

        public function handle(array $args): mixed
        {
            return ['status' => 'ok'];
        }
    });
}
foreach (['delete_note' => 'notes:delete', 'own_note' => 'mcp:tools'] as $name => $scope) {
    tool()->register(new class ($name, $scope) implements UserToolInterface, ScopedToolInterface {
        public function __construct(private string $toolName, private string $scope)
        {
        }

        public function name(): string
        {
            return $this->toolName;
        }

        public function description(): string
        {
            return 'Access a note belonging to the verified user.';
        }

        public function inputSchema(): array
        {
            return ['type' => 'object', 'properties' => ['id' => ['type' => 'string']], 'required' => ['id']];
        }

        public function requiredScopes(): array
        {
            return [$this->scope];
        }

        public function handle(array $args): mixed
        {
            $user   = token()->user()->getIdentifier();
            $owners = ['a' => 'alice', 'b' => 'bob'];
            if (($owners[$args['id']] ?? null) !== $user) {
                throw new AuthorizationException('This note does not belong to this account.');
            }
            file_put_contents(BASE_PATH . '/executed', $this->toolName . ':' . $user . "\n", FILE_APPEND);

            return ['user' => $user, 'note' => $args['id'], 'client' => token()->clientId()];
        }
    });
}
if (PHP_SAPI === 'cli') {
    exit(app()->container()->make(Console::class)->run($argv));
}
app()->run();
