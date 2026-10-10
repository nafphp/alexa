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

// Test-only barrier: neither endpoint may proceed before another HTTP worker arrives.
$barrier = $_SERVER['HTTP_X_NAF_TEST_BARRIER'] ?? '';
if (getenv('NAF_SECURITY_HTTP_WORKERS') === '4' && preg_match('/\A[a-f0-9]{32}\z/', $barrier)) {
    $path = BASE_PATH . '/barrier-' . $barrier;
    $file = fopen($path, 'c+');
    flock($file, LOCK_EX);
    fseek($file, 0, SEEK_END);
    fwrite($file, getmypid() . "\n");
    fflush($file);
    flock($file, LOCK_UN);
    fclose($file);
    $deadline = microtime(true) + 4;
    do {
        $participants = file($path, FILE_IGNORE_NEW_LINES);
        if (count(array_unique($participants)) === 2) {
            break;
        }
        if (microtime(true) >= $deadline) {
            throw new RuntimeException('A second HTTP worker did not reach the test barrier.');
        }
        usleep(1000);
    } while (true);
}

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
route()->add('GET', '/login', static fn() => response('<!doctype html><html lang="en"><title>Audit host sign in</title><main><h1>Audit host sign in</h1><form method="post"><input type="hidden" name="_csrf" value="' . csrf()->generate() . '"><label>Username <input name="username" autocomplete="username" required></label><label>Password <input type="password" name="password" autocomplete="current-password" required></label><button>Sign in</button></form></main></html>'), 'login');
route()->add('GET', '/', static fn() => response('<!doctype html><html lang="en"><title>Audit host</title><main><h1>Audit host</h1><p>Signed in.</p></main></html>'), 'home');
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
