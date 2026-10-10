<?php

declare(strict_types=1);

namespace Naf\Alexa\Commands;

use Naf\Alexa\Clients;
use Naf\Alexa\Manifest;
use Naf\Alexa\Settings;
use Naf\CLI\Core\AbstractCommand;
use Naf\CLI\Core\Input;
use Naf\CLI\Core\Output;
use Naf\Core\Route;
use Naf\MCP\Auth\McpIdentity;
use Naf\MCP\Support\ToolRegistry;
use Naf\MCP\Tools\ScopedToolInterface;
use Naf\MCP\Tools\UserToolInterface;
use Naf\OAuth\Server\Core\Discovery;
use PDO;
use RuntimeException;
use Throwable;

use function Naf\app;
use function Naf\Auth\auth;
use function Naf\config;

final class DoctorCommand extends AbstractCommand
{
    public const string NAME = 'alexa:doctor';

    public function __construct(
        private readonly Settings $settings,
        private readonly Clients $clients,
        private readonly PDO $connection,
        private readonly ToolRegistry $tools,
        private readonly Discovery $discovery,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setTitle('Alexa doctor')->setDescription('Check local Alexa server configuration and store-listing metadata.');
        $this->addOption('server-only');
    }

    public function run(Input $input, Output $output): int
    {
        $failed = false;
        $check  = static function (string $name, callable $test) use ($output, &$failed): void {
            try {
                $test();
                $output->writeLine('OK ' . $name, 'ok');
            } catch (Throwable $exception) {
                $failed = true;
                $output->writeLine('FAIL ' . $name . ': ' . $exception->getMessage(), 'error');
            }
        };
        $check('configuration', fn() => $this->settings->assertValid());
        $check('OAuth tables', function (): void {
            foreach (['oauth_clients', 'oauth_subjects', 'oauth_requests', 'oauth_families', 'oauth_codes', 'oauth_tokens', 'oauth_refresh_tokens'] as $table) {
                $this->connection->query('SELECT 1 FROM ' . $table . ' WHERE 1 = 0')->closeCursor();
            }
        });
        $check('protocol routes', static function (): void {
            $routes = app()->container()->get(Route::class)->all();
            foreach (['mcp_server_rpc' => ['POST', '/mcp'], 'mcp_resource_metadata_path' => ['GET', '/.well-known/oauth-protected-resource/mcp'], 'oauth.authorization_server' => ['GET', '/.well-known/oauth-authorization-server']] as $name => [$method, $path]) {
                if (($routes[$name]['method'] ?? null) !== $method || ($routes[$name]['path'] ?? null) !== $path) {
                    throw new RuntimeException('Restore the conventional route ' . $name . '.');
                }
            }
        });
        if ($this->settings->accountLinking()) {
            $check('account provider', static function (): void {
                if (auth()->providers() === []) {
                    throw new RuntimeException('Register the host authentication provider before using account linking.');
                }
            });
        }
        $check('OAuth discovery', function (): void {
            $document = $this->discovery->document();
            if (!in_array('S256', $document['code_challenge_methods_supported'] ?? [], true)
                || !in_array('client_credentials', $document['grant_types_supported'] ?? [], true)) {
                throw new RuntimeException('Discovery must advertise S256 and client_credentials.');
            }
        });
        $check('OAuth client separation', function (): void {
            if ($this->clients->find(false) === null
                || ($this->settings->accountLinking() && $this->clients->find(true) === null)) {
                throw new RuntimeException('Run alexa:setup to register the configured clients.');
            }
        });
        $check('tools and account-linking scopes', function (): void {
            $definitions = $this->tools->definitions(new McpIdentity('doctor', 'doctor', ['mcp:service']));
            if ($definitions === []) {
                throw new RuntimeException('Register at least one application MCP tool.');
            }
            foreach ($definitions as $definition) {
                $tool = $this->tools->getTool($definition['name']);
                if (!preg_match('/^[A-Za-z0-9_.-]{1,128}$/D', $tool->name()) || trim($tool->description()) === '') {
                    throw new RuntimeException('Tools need a valid MCP name and a useful description.');
                }
                if (($definition['inputSchema']['type'] ?? '') !== 'object') {
                    throw new RuntimeException($tool->name() . ': inputSchema must describe an object.');
                }
                $scopes = $tool instanceof ScopedToolInterface ? $tool->requiredScopes() : [];
                if ($tool instanceof UserToolInterface) {
                    if (!$this->settings->accountLinking() || $scopes === [] || array_diff($scopes, $this->settings->userScopes()) !== []) {
                        throw new RuntimeException($tool->name() . ': enable account linking and declare its user scopes.');
                    }
                } elseif ($scopes !== [] && !in_array('mcp:service', $scopes, true)) {
                    throw new RuntimeException($tool->name() . ': personal tools must also implement UserToolInterface.');
                }
            }
        });
        if ($input->getOption('server-only') === null) {
            $check('Alexa store listing', fn() => (new Manifest())->document($this->settings));
        }
        $output->writeLine('POST /mcp response mode: ' . (config('mcp:transport:streaming', false) === true ? 'SSE progress + result' : 'JSON result'));
        $output->writeLine('Local checks only. Verify public HTTPS, proxy flushing, login/consent, images and latency in the Alexa simulator before submission.');

        return $failed ? self::ERROR : self::SUCCESS;
    }
}
