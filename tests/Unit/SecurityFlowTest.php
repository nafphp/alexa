<?php

declare(strict_types=1);

namespace Tests\Unit;

use PDO;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

/** Browser cookies and HTTP endpoints; no direct issueCode shortcut. All credentials are disposable. */
final class SecurityFlowTest extends TestCase
{
    private string $root;
    private string $address;
    private mixed $process;
    private array $jars = [];
    private array $ids;
    private array $secrets;
    private bool $multipleWorkers = false;
    private const string RESOURCE = 'https://alexa.example.test/mcp';
    private const string REDIRECT = 'https://amazon.example.test/callback';

    protected function setUp(): void
    {
        $this->root = sys_get_temp_dir() . '/naf-security-' . bin2hex(random_bytes(6));
        mkdir($this->root);
        mkdir($this->root . '/app');
        $config = [
            'public_url'   => 'https://alexa.example.test',
            'database'     => ['driver' => 'sqlite', 'database' => $this->root . '/oauth.sqlite'],
            'oauth_server' => [
                'name'   => 'Test app', 'audience' => self::RESOURCE, 'login_route' => '/login', 'key_path' => $this->root . '/keys',
                'scopes' => ['notes:*' => ['permission' => 'notes.read'], '*' => ['permission' => 'notes.read'], 'notes:delete' => ['permission' => 'notes.delete']],
            ],
            'mcp'   => ['oauth' => ['resource' => self::RESOURCE, 'authorization_servers' => ['https://alexa.example.test'], 'scopes_supported' => ['mcp:tools', 'notes:*', '*', 'notes:delete']]],
            'alexa' => ['account_linking' => true, 'redirect_uris' => [self::REDIRECT], 'user_scopes' => ['mcp:tools', 'notes:*', '*', 'notes:delete']],
        ];
        file_put_contents($this->root . '/app/config.php', '<?php return ' . var_export($config, true) . ';');
        $this->permissions(['notes.read', 'notes.delete', 'mcp:tools']);
        $fixture               = dirname(__DIR__) . '/Fixtures/security-host.php';
        $environment           = ['NAF_ALEXA_HOST_ROOT' => $this->root, 'APP_ENV' => 'test'] + getenv();
        $this->multipleWorkers = getenv('NAF_SECURITY_HTTP_WORKERS') === '4';
        if ($this->multipleWorkers) {
            self::assertTrue(function_exists('posix_setsid') && function_exists('posix_kill') && function_exists('pcntl_exec'), 'Parallel HTTP tests require POSIX and PCNTL.');
            $environment['PHP_CLI_SERVER_WORKERS'] = '4';
        } else {
            unset($environment['PHP_CLI_SERVER_WORKERS']);
        }
        $setup  = proc_open([PHP_BINARY, $fixture, 'alexa:setup', '--migrate'], [0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w']], $pipes, null, $environment);
        $output = stream_get_contents($pipes[1]);
        $errors = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        self::assertSame(0, proc_close($setup), $output . $errors);
        preg_match_all('/client_id: ([a-zA-Z0-9_-]+)/', $output, $ids);
        preg_match_all('/shown once\): ([a-zA-Z0-9_-]+)/', $output, $secrets);
        $this->ids     = $ids[1];
        $this->secrets = $secrets[1];
        $listener      = stream_socket_server('tcp://127.0.0.1:0', $error, $message);
        $this->address = stream_socket_get_name($listener, false);
        fclose($listener);
        $command = [PHP_BINARY, '-d', 'session.save_path=' . $this->root, '-S', $this->address, $fixture];
        if ($this->multipleWorkers) {
            // Isolate the server and all its workers so teardown also stops its children.
            $command = [PHP_BINARY, dirname(__DIR__) . '/Fixtures/http-workers.php', ...array_slice($command, 1)];
        }
        $this->process = proc_open($command, [0 => ['file', '/dev/null', 'r'], 1 => ['file', $this->root . '/server.log', 'a'], 2 => ['file', $this->root . '/server.log', 'a']], $pipes, null, $environment);
        for ($i = 0; $i < 100; ++$i) {
            $socket = @stream_socket_client('tcp://' . $this->address, $error, $message, 0.1);
            if (is_resource($socket)) {
                fclose($socket);

                return;
            }
            usleep(20000);
        }
        self::fail('Local HTTP host did not start.');
    }

    protected function tearDown(): void
    {
        if (isset($this->process) && is_resource($this->process)) {
            if ($this->multipleWorkers) {
                posix_kill(-proc_get_status($this->process)['pid'], 15);
            }
            proc_terminate($this->process);
            proc_close($this->process);
        }
        if (isset($this->root) && is_dir($this->root)) {
            foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($this->root, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $file) {
                $file->isDir() ? rmdir($file->getPathname()) : unlink($file->getPathname());
            }
            rmdir($this->root);
        }
    }

    public static function wildcardScopes(): iterable
    {
        yield ['notes:*'];
        yield ['*'];
    }

    #[DataProvider('wildcardScopes')]
    public function testLiteralOAuthScopesCannotListOrCallDelete(string $scope): void
    {
        $this->permissions(['notes.read']);
        $this->login('alice');
        $user = $this->grant('alice', $scope);
        self::assertSame(200, $user['status']);
        $bearer  = $user['json']['access_token'];
        $listing = $this->rpc('tools/list', [], $bearer);
        $called  = $this->call('delete_note', 'a', $bearer);
        self::assertSame(403, $called['status'], 'User listing: ' . json_encode(array_column($listing['json']['result']['tools'], 'name')));
        self::assertNotContains('delete_note', array_column($listing['json']['result']['tools'], 'name'));
        self::assertFileDoesNotExist($this->root . '/executed');
    }

    public function testExplicitScopeAndCurrentPermissionsAndOwnership(): void
    {
        $this->login('alice');
        $this->login('bob');
        $alice = $this->grant('alice', 'notes:delete mcp:tools')['json']['access_token'];
        $bob   = $this->grant('bob', 'mcp:tools')['json']['access_token'];
        $a     = $this->call('delete_note', 'a', $alice);
        $b     = $this->call('own_note', 'b', $bob);
        self::assertSame(200, $a['status']);
        self::assertSame('alice', $a['json']['result']['structuredContent']['user']);
        self::assertSame('bob', $b['json']['result']['structuredContent']['user']);
        self::assertSame($a['json']['result']['structuredContent']['client'], $b['json']['result']['structuredContent']['client']);
        self::assertTrue($this->call('own_note', 'b', $alice)['json']['result']['isError']);
        self::assertTrue($this->call('own_note', 'a', $bob)['json']['result']['isError']);
        self::assertSame(2, substr_count(file_get_contents($this->root . '/executed'), "\n"));
        self::assertSame(401, $this->call('own_note', 'a', null, 'alice')['status']);
        self::assertSame(401, $this->call('own_note', 'a', 'invalid', 'alice')['status']);
        $this->permissions(['notes.read', 'mcp:tools']);
        self::assertSame(403, $this->call('delete_note', 'a', $alice)['status']);
        $form = $this->consent('alice', 'notes:delete');
        self::assertSame(302, $form['status']);
        self::assertStringContainsString('error=access_denied', $form['headers']['location']);
    }

    public function testServiceAndPublicToolsWorkButPersonalCallsNeedAUser(): void
    {
        $service = $this->request('/oauth/token', ['grant_type' => 'client_credentials', 'scope' => 'mcp:service', 'resource' => self::RESOURCE], basic: 0);
        self::assertSame(200, $service['status']);
        self::assertArrayNotHasKey('refresh_token', $service['json']);
        $bearer = $service['json']['access_token'];
        foreach (['public_ping', 'service_ping'] as $tool) {
            self::assertSame(200, $this->rpc('tools/call', ['name' => $tool], $bearer)['status']);
        }
        self::assertContains('own_note', array_column($this->rpc('tools/list', [], $bearer)['json']['result']['tools'], 'name'));
        $blocked = $this->call('own_note', 'a', $bearer);
        self::assertSame(401, $blocked['status']);
        self::assertArrayNotHasKey('www-authenticate', $blocked['headers']);
        self::assertSame(400, $this->request('/oauth/token', ['grant_type' => 'client_credentials', 'scope' => 'mcp:tools'], basic: 0)['status']);
    }

    public function testShortVerifierIsRejectedThroughLoginConsentAndTokenExchange(): void
    {
        $this->login('alice');
        $answer = $this->grant('alice', 'mcp:tools', 'x');
        self::assertSame(400, $answer['status']);
        self::assertSame('invalid_request', $answer['json']['error']);
    }

    public static function verifiers(): iterable
    {
        yield '42' => [str_repeat('v', 42), 400];
        yield '43' => [str_repeat('v', 43), 200];
        yield '128' => [str_repeat('v', 128), 200];
        yield '129' => [str_repeat('v', 129), 400];
        yield 'unreserved' => [str_repeat('v', 39) . '._~-', 200];
        yield 'space' => [str_repeat('v', 42) . ' ', 400];
        yield 'newline' => [str_repeat('v', 42) . "\n", 400];
        yield 'unicode' => [str_repeat('v', 42) . 'é', 400];
    }

    #[DataProvider('verifiers')]
    public function testPkceVerifierWireFormat(string $verifier, int $status): void
    {
        $this->login('alice');
        $answer = $this->grant('alice', 'mcp:tools', $verifier);
        self::assertSame($status, $answer['status'], $answer['body']);
        if ($status === 400) {
            self::assertSame('invalid_request', $answer['json']['error']);
        }
    }

    public function testChallengeFormatMethodMissingVerifierAndWrongProof(): void
    {
        $this->login('alice');
        foreach (['', str_repeat('v', 42), str_repeat('v', 44), str_repeat('v', 42) . '+', str_repeat('v', 42) . '='] as $challenge) {
            $query  = array_replace($this->authorizeQuery('mcp:tools'), ['code_challenge' => $challenge]);
            $answer = $this->request('/oauth/authorize?' . http_build_query($query), jar: 'alice');
            self::assertSame(302, $answer['status']);
            self::assertStringContainsString('error=invalid_request', $answer['headers']['location']);
        }
        foreach (['plain', ''] as $method) {
            $query = array_replace($this->authorizeQuery('mcp:tools'), ['code_challenge_method' => $method]);
            self::assertStringContainsString('error=invalid_request', $this->request('/oauth/authorize?' . http_build_query($query), jar: 'alice')['headers']['location']);
        }
        foreach ([null, str_repeat('w', 43)] as $verifier) {
            $form     = $this->fields($this->consent('alice')['body']);
            $approval = $this->request('/oauth/authorize', $form + ['approve' => 'yes'], 'alice');
            parse_str(parse_url($approval['headers']['location'], PHP_URL_QUERY), $query);
            $exchange = ['grant_type' => 'authorization_code', 'code' => $query['code'], 'redirect_uri' => self::REDIRECT];
            if ($verifier !== null) {
                $exchange['code_verifier'] = $verifier;
            }
            $answer = $this->request('/oauth/token', $exchange, basic: 1);
            self::assertSame(400, $answer['status']);
            self::assertSame($verifier === null ? 'invalid_request' : 'invalid_grant', $answer['json']['error']);
        }
    }

    public function testConsentIsBoundToSessionUserRequestAndCsrfAndSupportsParallelForms(): void
    {
        $query     = $this->authorizeQuery('mcp:tools');
        $anonymous = $this->request('/oauth/authorize?' . http_build_query($query), jar: 'anonymous');
        self::assertSame(302, $anonymous['status']);
        self::assertStringStartsWith('/login?next=', $anonymous['headers']['location']);
        $this->login('alice');
        $this->login('bob');
        $first  = $this->consent('alice');
        $second = $this->consent('alice');
        $one    = $this->fields($first['body']);
        $two    = $this->fields($second['body']);
        self::assertNotSame($one['_csrf'], $two['_csrf']);
        foreach ([[], ['_csrf' => 'wrong'], ['_csrf' => $two['_csrf']]] as $csrf) {
            self::assertSame(400, $this->request('/oauth/authorize', ['request_id' => $one['request_id'], 'approve' => 'yes'] + $csrf, 'alice')['status']);
        }
        self::assertSame(400, $this->request('/oauth/authorize', $one + ['approve' => 'yes'], 'bob')['status']);
        // A second login in the same browser changes the person and rotates the session.
        $this->login('switch', 'alice');
        $old = $this->fields($this->consent('switch')['body']);
        $this->login('switch', 'bob');
        self::assertSame(400, $this->request('/oauth/authorize', $old + ['approve' => 'yes'], 'switch')['status']);
        $approved = $this->request('/oauth/authorize', $one + ['approve' => 'yes', 'redirect_uri' => 'https://evil.test'], 'alice');
        self::assertSame(302, $approved['status']);
        self::assertStringStartsWith(self::REDIRECT . '?code=', $approved['headers']['location']);
        self::assertSame(400, $this->request('/oauth/authorize', $one + ['approve' => 'yes'], 'alice')['status']);
        $denied = $this->request('/oauth/authorize', $two, 'alice');
        self::assertSame(302, $denied['status']);
        self::assertStringContainsString('error=access_denied', $denied['headers']['location']);
        self::assertSame(400, $this->request('/oauth/authorize', $two, 'alice')['status']);
        $expired   = $this->fields($this->consent('alice')['body']);
        $statement = $this->db()->prepare('UPDATE oauth_requests SET expires_at = 0 WHERE id = ?');
        $statement->execute([$expired['request_id']]);
        self::assertSame(400, $this->request('/oauth/authorize', $expired + ['approve' => 'yes'], 'alice')['status']);
        $tampered = $this->request('/oauth/authorize?' . http_build_query(array_replace($query, ['redirect_uri' => 'https://evil.test'])), jar: 'alice');
        self::assertSame(400, $tampered['status']);
        self::assertArrayNotHasKey('location', $tampered['headers']);
    }

    public function testConsentHasCacheReferrerAndFramingProtection(): void
    {
        $this->login('alice');
        $page = $this->consent('alice');
        self::assertSame(200, $page['status']);
        self::assertStringContainsString('no-store', $page['headers']['cache-control'] ?? '');
        self::assertSame('no-referrer', $page['headers']['referrer-policy'] ?? '');
        self::assertSame('DENY', $page['headers']['x-frame-options'] ?? '');
        self::assertStringContainsString("frame-ancestors 'none'", $page['headers']['content-security-policy'] ?? '');
    }

    public function testCodeAndRefreshReplayRevocationAudienceAndClientRevocation(): void
    {
        $this->login('alice');
        $form     = $this->fields($this->consent('alice')['body']);
        $approval = $this->request('/oauth/authorize', $form + ['approve' => 'yes'], 'alice');
        parse_str(parse_url($approval['headers']['location'], PHP_URL_QUERY), $query);
        $exchange = ['grant_type' => 'authorization_code', 'code' => $query['code'], 'code_verifier' => str_repeat('v', 43), 'redirect_uri' => self::REDIRECT, 'resource' => self::RESOURCE];
        $user     = $this->request('/oauth/token', $exchange, basic: 1)['json'];
        self::assertArrayHasKey('access_token', $user);
        self::assertSame(400, $this->request('/oauth/token', $exchange, basic: 1)['status']);
        self::assertSame(401, $this->call('own_note', 'a', $user['access_token'])['status']);
        $user      = $this->grant('alice')['json'];
        $statement = $this->db()->prepare('UPDATE oauth_tokens SET expires_at = 0 WHERE token_hash = ?');
        $statement->execute([hash('sha256', $user['access_token'])]);
        self::assertSame(401, $this->call('own_note', 'a', $user['access_token'], 'alice')['status']);
        $rotated = $this->request('/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $user['refresh_token']], basic: 1)['json'];
        self::assertSame(200, $this->call('own_note', 'a', $rotated['access_token'])['status']);
        self::assertSame(400, $this->request('/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $user['refresh_token']], basic: 1)['status']);
        self::assertSame(401, $this->call('own_note', 'a', $rotated['access_token'])['status']);
        $user = $this->grant('alice')['json'];
        self::assertSame(200, $this->request('/oauth/revoke', ['token' => $user['refresh_token']], basic: 1)['status']);
        self::assertSame(401, $this->call('own_note', 'a', $user['access_token'])['status']);
        self::assertSame(400, $this->request('/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $user['refresh_token']], basic: 1)['status']);
        $user      = $this->grant('alice')['json'];
        $statement = $this->db()->prepare('UPDATE oauth_tokens SET audience = ? WHERE token_hash = ?');
        $statement->execute(['https://other.example.test/mcp', hash('sha256', $user['access_token'])]);
        self::assertSame(401, $this->call('own_note', 'a', $user['access_token'], 'alice')['status']);
        $user      = $this->grant('alice')['json'];
        $statement = $this->db()->prepare('UPDATE oauth_clients SET revoked_at = ? WHERE client_id = ?');
        $statement->execute([time(), $this->ids[1]]);
        self::assertSame(401, $this->call('own_note', 'a', $user['access_token'])['status']);
        self::assertSame(401, $this->request('/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $user['refresh_token']], basic: 1)['status']);
    }

    public function testInvalidScopePolicyPreventsHttpGrants(): void
    {
        $this->login('alice');
        $configuration                                                         = require $this->root . '/app/config.php';
        $configuration['oauth_server']['scopes']['notes:delete']['permission'] = false;
        file_put_contents($this->root . '/app/config.php', '<?php return ' . var_export($configuration, true) . ';');
        self::assertSame(500, $this->consent('alice', 'notes:delete')['status']);
        self::assertSame(0, (int) $this->db()->query('SELECT COUNT(*) FROM oauth_requests')->fetchColumn());
        self::assertSame(500, $this->request('/oauth/token', ['grant_type' => 'client_credentials', 'scope' => 'mcp:service', 'resource' => self::RESOURCE], basic: 0)['status']);
        self::assertSame(0, (int) $this->db()->query('SELECT COUNT(*) FROM oauth_tokens')->fetchColumn());
    }

    public function testOutstandingRefreshAndRevocationRequestsEndTheFamily(): void
    {
        $this->login('alice');
        for ($attempt = 0; $attempt < 10; ++$attempt) {
            $user      = $this->grant('alice')['json'];
            $responses = $this->concurrent([
                ['/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $user['refresh_token']]],
                ['/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $user['refresh_token']]],
            ]);
            $statuses = array_column($responses, 'status');
            sort($statuses);
            self::assertSame([200, 400], $statuses);
            foreach ($responses as $reply) {
                if ($reply['status'] === 200) {
                    self::assertSame(401, $this->call('own_note', 'a', $reply['json']['access_token'])['status']);
                }
            }
            $user      = $this->grant('alice')['json'];
            $responses = $this->concurrent([
                ['/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $user['refresh_token']]],
                ['/oauth/revoke', ['token' => $user['refresh_token']]],
            ]);
            self::assertSame(200, $responses[1]['status']);
            self::assertContains($responses[0]['status'], [200, 400]);
            if ($responses[0]['status'] === 200) {
                self::assertSame(401, $this->call('own_note', 'a', $responses[0]['json']['access_token'])['status']);
                self::assertSame(400, $this->request('/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $responses[0]['json']['refresh_token']], basic: 1)['status']);
            }
            self::assertSame(401, $this->call('own_note', 'a', $user['access_token'])['status']);
        }
    }

    /** With multiple workers, a barrier proves both HTTP requests overlap in distinct processes. */
    private function concurrent(array $requests): array
    {
        $sockets = [];
        $barrier = bin2hex(random_bytes(16));
        foreach ($requests as [$path, $parameters]) {
            $socket = stream_socket_client('tcp://' . $this->address, $error, $message, 5);
            stream_set_timeout($socket, 5);
            $body            = http_build_query($parameters);
            $basic           = base64_encode($this->ids[1] . ':' . $this->secrets[1]);
            $synchronization = $this->multipleWorkers ? "X-NAF-Test-Barrier: $barrier\r\n" : '';
            fwrite($socket, "POST $path HTTP/1.1\r\nHost: {$this->address}\r\nAuthorization: Basic $basic\r\n$synchronization" . "Content-Type: application/x-www-form-urlencoded\r\nContent-Length: " . strlen($body) . "\r\nConnection: close\r\n\r\n" . $body);
            $sockets[] = $socket;
            if ($this->multipleWorkers && count($sockets) === 1) {
                // Do not let one idle worker accept both sockets before dispatching either.
                $deadline = microtime(true) + 2;
                while (!is_file($this->root . '/barrier-' . $barrier) && microtime(true) < $deadline) {
                    usleep(1000);
                }
                self::assertFileExists($this->root . '/barrier-' . $barrier, 'The first HTTP worker must be waiting before the second connection starts.');
            }
        }
        $responses = [];
        foreach ($sockets as $socket) {
            $raw = stream_get_contents($socket);
            fclose($socket);
            [$headers, $body] = explode("\r\n\r\n", $raw, 2);
            $responses[]      = ['status' => (int) explode(' ', $headers)[1], 'json' => json_decode($body, true)];
        }
        if ($this->multipleWorkers) {
            $participants = file($this->root . '/barrier-' . $barrier, FILE_IGNORE_NEW_LINES);
            self::assertCount(2, array_unique($participants), 'Both HTTP requests must reach the barrier in distinct workers.');
        }

        return $responses;
    }

    public function testMcpBodyLimitIsAppliedOverHttp(): void
    {
        $service  = $this->request('/oauth/token', ['grant_type' => 'client_credentials', 'scope' => 'mcp:service', 'resource' => self::RESOURCE], basic: 0)['json']['access_token'];
        $response = $this->rpc('tools/call', ['name' => 'public_ping', 'arguments' => ['padding' => str_repeat('x', 1048576)]], $service);
        self::assertSame(413, $response['status']);
        self::assertSame(-32600, $response['json']['error']['code']);
    }

    public function testDisposableSecretsAndTokensAreHashedAndAbsentFromDefaultLogs(): void
    {
        $this->login('alice');
        $user     = $this->grant('alice')['json'];
        $snapshot = json_encode([
            $this->db()->query('SELECT secret_hash FROM oauth_clients')->fetchAll(PDO::FETCH_COLUMN),
            $this->db()->query('SELECT token_hash FROM oauth_tokens')->fetchAll(PDO::FETCH_COLUMN),
            $this->db()->query('SELECT token_hash FROM oauth_refresh_tokens')->fetchAll(PDO::FETCH_COLUMN),
        ], JSON_THROW_ON_ERROR);
        $logs = file_get_contents($this->root . '/server.log');
        foreach (glob($this->root . '/logs/*.log') ?: [] as $file) {
            $logs .= file_get_contents($file);
        }
        foreach ([...$this->secrets, $user['access_token'], $user['refresh_token']] as $secret) {
            self::assertStringNotContainsString($secret, $snapshot);
            self::assertStringNotContainsString($secret, $logs);
        }
    }

    private function permissions(array $alice): void
    {
        file_put_contents($this->root . '/permissions.json', json_encode(['alice' => $alice, 'bob' => ['mcp:tools']], JSON_THROW_ON_ERROR));
    }

    private function db(): PDO
    {
        return new PDO('sqlite:' . $this->root . '/oauth.sqlite');
    }

    private function login(string $jar, ?string $user = null): void
    {
        $form  = $this->fields($this->request('/login', jar: $jar)['body']);
        $login = $this->request('/login', $form + ['username' => $user ?? $jar, 'password' => 'test-password'], $jar);
        self::assertSame(302, $login['status'], $login['body']);
    }

    private function authorizeQuery(string $scope, string $verifier = ''): array
    {
        return ['client_id' => $this->ids[1], 'redirect_uri' => self::REDIRECT, 'response_type' => 'code', 'scope' => $scope, 'state' => 'state', 'resource' => self::RESOURCE, 'code_challenge_method' => 'S256', 'code_challenge' => rtrim(strtr(base64_encode(hash('sha256', $verifier === '' ? str_repeat('v', 43) : $verifier, true)), '+/', '-_'), '=')];
    }

    private function consent(string $jar, string $scope = 'mcp:tools', string $verifier = ''): array
    {
        return $this->request('/oauth/authorize?' . http_build_query($this->authorizeQuery($scope, $verifier)), jar: $jar);
    }

    private function fields(string $html): array
    {
        preg_match_all('/name="([^"]+)"\s+value="([^"]*)"/', $html, $matches, PREG_SET_ORDER);
        $fields = [];
        foreach ($matches as $match) {
            $fields[$match[1]] = html_entity_decode($match[2], ENT_QUOTES);
        }
        unset($fields['approve']);
        self::assertArrayHasKey('_csrf', $fields, $html);

        return $fields;
    }

    private function grant(string $jar, string $scope = 'mcp:tools', string $verifier = ''): array
    {
        $form     = $this->fields($this->consent($jar, $scope, $verifier)['body']);
        $approved = $this->request('/oauth/authorize', $form + ['approve' => 'yes'], $jar);
        self::assertSame(302, $approved['status'], $approved['body']);
        parse_str(parse_url($approved['headers']['location'], PHP_URL_QUERY), $query);
        self::assertArrayHasKey('code', $query);

        return $this->request('/oauth/token', ['grant_type' => 'authorization_code', 'code' => $query['code'], 'code_verifier' => $verifier === '' ? str_repeat('v', 43) : $verifier, 'redirect_uri' => self::REDIRECT, 'resource' => self::RESOURCE], basic: 1);
    }

    private function call(string $name, string $id, ?string $bearer, ?string $jar = null): array
    {
        return $this->rpc('tools/call', ['name' => $name, 'arguments' => ['id' => $id]], $bearer, $jar);
    }

    private function rpc(string $method, array $params, ?string $bearer, ?string $jar = null): array
    {
        return $this->request('/mcp', ['jsonrpc' => '2.0', 'id' => 1, 'method' => $method, 'params' => (object) $params], $jar, $bearer, json: true);
    }

    private function request(string $path, ?array $body = null, ?string $jar = null, ?string $bearer = null, ?int $basic = null, bool $json = false): array
    {
        $headers = ['Accept: application/json, text/event-stream', 'Content-Type: ' . ($json ? 'application/json' : 'application/x-www-form-urlencoded')];
        if ($jar !== null && isset($this->jars[$jar])) {
            $headers[] = 'Cookie: ' . implode('; ', $this->jars[$jar]);
        }
        if ($bearer !== null) {
            $headers[] = 'Authorization: Bearer ' . $bearer;
        }
        if ($basic !== null) {
            $headers[] = 'Authorization: Basic ' . base64_encode($this->ids[$basic] . ':' . $this->secrets[$basic]);
        }
        $context              = stream_context_create(['http' => ['method' => $body === null ? 'GET' : 'POST', 'header' => implode("\r\n", $headers), 'content' => $body === null ? '' : ($json ? json_encode($body, JSON_THROW_ON_ERROR) : http_build_query($body)), 'ignore_errors' => true, 'follow_location' => 0, 'timeout' => 5]]);
        $http_response_header = []; // PHP 8.3 requires a declared local for its HTTP wrapper.
        $raw                  = file_get_contents('http://' . $this->address . $path, false, $context);
        $responseHeaders      = function_exists('http_get_last_response_headers') ? http_get_last_response_headers() : $http_response_header;
        $reply                = [];
        foreach ($responseHeaders as $line) {
            if (!str_contains($line, ':')) {
                continue;
            }
            [$key, $value]           = explode(':', $line, 2);
            $reply[strtolower($key)] = trim($value);
            if ($jar !== null && strtolower($key) === 'set-cookie') {
                $cookie                                     = explode(';', trim($value))[0];
                $this->jars[$jar][explode('=', $cookie)[0]] = $cookie;
            }
        }

        return ['status' => (int) explode(' ', $responseHeaders[0])[1], 'json' => json_decode($raw, true), 'body' => $raw, 'headers' => $reply];
    }
}
