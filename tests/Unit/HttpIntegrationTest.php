<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\OAuth\Server\Model\AuthorizationRequest;
use Naf\OAuth\Server\Store\PdoTokens;
use PDO;
use PHPUnit\Framework\TestCase;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;

final class HttpIntegrationTest extends TestCase
{
    public function testInstalledHostSupportsDiscoveryServiceTokensPkceRefreshAndRevocation(): void
    {
        $root = sys_get_temp_dir() . '/naf-alexa-http-' . bin2hex(random_bytes(6));
        mkdir($root);
        mkdir($root . '/app');
        file_put_contents($root . '/app/config.php', <<<'PHP'
        <?php
        return [
            'public_url' => 'https://alexa.example.test',
            'database' => ['driver' => 'sqlite', 'database' => BASE_PATH . '/oauth.sqlite'],
            'auth' => ['session' => false],
            'oauth_server' => ['name' => 'Test app', 'audience' => 'https://alexa.example.test/mcp', 'login_route' => '/login', 'key_path' => BASE_PATH . '/keys'],
            'mcp' => ['oauth' => ['resource' => 'https://alexa.example.test/mcp', 'authorization_servers' => ['https://alexa.example.test']]],
            'alexa' => ['account_linking' => true, 'redirect_uris' => ['https://amazon.example.test/callback']],
        ];
        PHP);
        $fixture     = dirname(__DIR__) . '/Fixtures/host.php';
        $environment = ['NAF_ALEXA_HOST_ROOT' => $root, 'APP_ENV' => 'test'] + getenv();
        $setup       = proc_open([PHP_BINARY, $fixture, 'alexa:setup', '--migrate'], [
            0 => ['file', '/dev/null', 'r'], 1 => ['pipe', 'w'], 2 => ['pipe', 'w'],
        ], $pipes, null, $environment);
        $printed = stream_get_contents($pipes[1]);
        $errors  = stream_get_contents($pipes[2]);
        fclose($pipes[1]);
        fclose($pipes[2]);
        self::assertSame(0, proc_close($setup), $printed . $errors);
        preg_match_all('/client_id: ([a-zA-Z0-9_-]+)/', $printed, $ids);
        preg_match_all('/shown once\): ([a-zA-Z0-9_-]+)/', $printed, $secrets);
        self::assertCount(2, $ids[1]);
        self::assertCount(2, $secrets[1]);

        $listener = stream_socket_server('tcp://127.0.0.1:0', $error, $message);
        $address  = stream_socket_get_name($listener, false);
        fclose($listener);
        $process = proc_open([PHP_BINARY, '-S', $address, $fixture], [
            0 => ['file', '/dev/null', 'r'], 1 => ['file', $root . '/server.log', 'a'], 2 => ['file', $root . '/server.log', 'a'],
        ], $pipes, null, $environment);

        try {
            for ($attempt = 0; $attempt < 100; ++$attempt) {
                $socket = @stream_socket_client('tcp://' . $address, $error, $message, 0.1);
                if (is_resource($socket)) {
                    fclose($socket);
                    break;
                }
                usleep(20000);
            }
            $request = static function (string $path, ?array $body = null, array $headers = [], bool $form = false) use ($address): array {
                $context = stream_context_create(['http' => [
                    'method'        => $body === null ? 'GET' : 'POST',
                    'header'        => implode("\r\n", $headers + ['Accept' => 'Accept: application/json, text/event-stream', 'Content-Type' => 'Content-Type: ' . ($form ? 'application/x-www-form-urlencoded' : 'application/json')]),
                    'content'       => $body === null ? '' : ($form ? http_build_query($body) : json_encode($body, JSON_THROW_ON_ERROR)),
                    'ignore_errors' => true,
                    'timeout'       => 5,
                ]]);
                $body = file_get_contents('http://' . $address . $path, false, $context);

                return [(int) explode(' ', $http_response_header[0])[1], json_decode($body, true), $http_response_header];
            };
            [$status, $metadata] = $request('/.well-known/oauth-protected-resource/mcp');
            self::assertSame(200, $status, file_get_contents($root . '/server.log'));
            self::assertSame('https://alexa.example.test/mcp', $metadata['resource']);
            [$status, $metadata] = $request('/.well-known/oauth-authorization-server');
            self::assertSame(200, $status);
            self::assertSame(['S256'], $metadata['code_challenge_methods_supported']);
            self::assertContains('client_credentials', $metadata['grant_types_supported']);
            $basic              = ['Authorization' => 'Authorization: Basic ' . base64_encode($ids[1][0] . ':' . $secrets[1][0])];
            [$status, $service] = $request('/oauth/token', ['grant_type' => 'client_credentials', 'scope' => 'mcp:service', 'resource' => 'https://alexa.example.test/mcp'], $basic, true);
            self::assertSame(200, $status);
            self::assertArrayNotHasKey('refresh_token', $service);
            $bearer           = ['Authorization' => 'Authorization: Bearer ' . $service['access_token']];
            $rpc              = ['jsonrpc' => '2.0', 'id' => 1, 'method' => 'tools/list'];
            [$status, $tools] = $request('/mcp', $rpc, $bearer);
            self::assertSame(200, $status);
            self::assertSame('my_account', $tools['result']['tools'][0]['name']);
            $call                 = ['jsonrpc' => '2.0', 'id' => 2, 'method' => 'tools/call', 'params' => ['name' => 'my_account']];
            [$status, , $headers] = $request('/mcp', $call, $bearer);
            self::assertSame(401, $status);
            self::assertStringNotContainsString('WWW-Authenticate', implode("\n", $headers));
            [$status] = $request('/oauth/token', ['grant_type' => 'client_credentials', 'scope' => 'mcp:tools'], $basic, true);
            self::assertSame(400, $status);

            $verifier = str_repeat('v', 43);
            $tokens   = new PdoTokens(new PDO('sqlite:' . $root . '/oauth.sqlite'));
            $code     = $tokens->issueCode(new AuthorizationRequest(
                $ids[1][1],
                'https://amazon.example.test/callback',
                ['mcp:tools'],
                'state',
                rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '='),
                null,
                'https://alexa.example.test/mcp',
                'session',
                'test',
                '42',
            ), 60);
            $userBasic       = ['Authorization' => 'Authorization: Basic ' . base64_encode($ids[1][1] . ':' . $secrets[1][1])];
            [$status, $user] = $request('/oauth/token', [
                'grant_type'   => 'authorization_code', 'code' => $code, 'code_verifier' => $verifier,
                'redirect_uri' => 'https://amazon.example.test/callback', 'resource' => 'https://alexa.example.test/mcp',
            ], $userBasic, true);
            self::assertSame(200, $status, json_encode($user));
            [$status, $result] = $request('/mcp', $call, ['Authorization' => 'Authorization: Bearer ' . $user['access_token']]);
            self::assertSame(200, $status);
            self::assertSame(['account' => '42'], $result['result']['structuredContent']);
            [$status, $refreshed] = $request('/oauth/token', ['grant_type' => 'refresh_token', 'refresh_token' => $user['refresh_token']], $userBasic, true);
            self::assertSame(200, $status);
            [$status] = $request('/mcp', $call, ['Authorization' => 'Authorization: Bearer ' . $refreshed['access_token']]);
            self::assertSame(200, $status);
            [$status] = $request('/oauth/revoke', ['token' => $refreshed['access_token']], $userBasic, true);
            self::assertSame(200, $status);
            [$status] = $request('/mcp', $call, ['Authorization' => 'Authorization: Bearer ' . $refreshed['access_token']]);
            self::assertSame(401, $status);
        } finally {
            proc_terminate($process);
            proc_close($process);
            foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($root, RecursiveDirectoryIterator::SKIP_DOTS), RecursiveIteratorIterator::CHILD_FIRST) as $file) {
                if ($file->isDir()) {
                    rmdir($file->getPathname());
                } else {
                    unlink($file->getPathname());
                }
            }
            rmdir($root);
        }
    }
}
