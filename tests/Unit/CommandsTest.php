<?php

declare(strict_types=1);

namespace Tests\Unit;

use Naf\Alexa\Settings;
use Naf\Auth\Support\PasswordHasher;
use Naf\CLI\Core\Console;
use Naf\Core\Config;
use Naf\MCP\Support\ToolRegistry;
use Naf\MCP\Tools\ToolInterface;
use Naf\OAuth\Server\Store\ClientStoreInterface;
use Naf\OAuth\Server\Store\PdoClients;
use PDO;
use PHPUnit\Framework\TestCase;

use function Naf\app;
use function Naf\config;

final class CommandsTest extends TestCase
{
    private array $base;
    private PDO $connection;

    protected function setUp(): void
    {
        $this->base       = config();
        $this->connection = new PDO('sqlite::memory:');
        app()->container()->set(PDO::class, $this->connection);
        app()->container()->set(ClientStoreInterface::class, new PdoClients($this->connection, new PasswordHasher(PASSWORD_BCRYPT, ['cost' => 4])));
        app()->container()->get(ToolRegistry::class)->register(new class implements ToolInterface {
            public function name(): string
            {
                return 'ping';
            }

            public function description(): string
            {
                return 'Check service availability.';
            }

            public function inputSchema(): array
            {
                return ['type' => 'object', 'properties' => []];
            }

            public function handle(array $args): mixed
            {
                return ['status' => 'ok'];
            }
        });
    }

    protected function tearDown(): void
    {
        app()->container()->set(Config::class, new Config($this->base));
        app()->container()->set(Settings::class, new Settings($this->base));
    }

    public function testSetupMigratesOnlyOAuthRegistersAndReusesServiceClient(): void
    {
        [$status, $output] = $this->execute('alexa:setup', ['--migrate']);
        self::assertSame(0, $status, $output);
        self::assertStringContainsString('shown once', $output);
        $clients = app()->container()->get(ClientStoreInterface::class)->all();
        self::assertCount(1, $clients);
        self::assertSame(['client_credentials'], $clients[0]->grants);
        self::assertSame(['mcp:service'], $clients[0]->scopes);
        self::assertSame(['https://alexa.example.test/mcp'], $clients[0]->audiences);
        self::assertSame(1, (int) $this->connection->query('SELECT COUNT(*) FROM migrations')->fetchColumn());
        [$status, $output] = $this->execute('alexa:setup', ['--migrate']);
        self::assertSame(0, $status, $output);
        self::assertStringNotContainsString('client_secret', $output);
        self::assertCount(1, app()->container()->get(ClientStoreInterface::class)->all());
        [$status, $output] = $this->execute('alexa:doctor', ['--server-only']);
        self::assertSame(0, $status, $output);
        self::assertStringContainsString('Local checks only', $output);
        self::assertStringContainsString('JSON result', $output);
        [$status, $output] = $this->execute('alexa:doctor');
        self::assertSame(1, $status);
        self::assertStringContainsString('FAIL Alexa store listing', $output);
    }

    public function testAccountLinkingUsesASeparateClientWithoutServiceGrant(): void
    {
        $settings = array_replace_recursive($this->base, [
            'alexa'        => ['account_linking' => true, 'redirect_uris' => ['https://amazon.example.test/callback']],
            'oauth_server' => ['login_route' => '/login'],
        ]);
        app()->container()->set(Settings::class, new Settings($settings));
        [$status, $output] = $this->execute('alexa:setup', ['--migrate']);
        self::assertSame(0, $status, $output);
        $clients = app()->container()->get(ClientStoreInterface::class)->all();
        self::assertCount(2, $clients);
        $user = array_values(array_filter($clients, static fn($client) => $client->allows('authorization_code')))[0];
        self::assertSame(['authorization_code', 'refresh_token'], $user->grants);
        self::assertSame(['mcp:tools'], $user->scopes);
        self::assertFalse($user->allows('client_credentials'));
        self::assertSame(['https://amazon.example.test/callback'], $user->redirectUris);
    }

    public function testInvalidConfigurationDoesNotRunMigrationsOrCreateClients(): void
    {
        app()->container()->set(Settings::class, new Settings(array_replace_recursive($this->base, ['mcp' => ['auth' => ['enabled' => false]]])));
        [$status, $output] = $this->execute('alexa:setup', ['--migrate']);
        self::assertSame(1, $status);
        self::assertStringContainsString('Enable MCP authentication', $output);
        self::assertSame(0, (int) $this->connection->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'")->fetchColumn());
    }

    public function testMissingDatabaseSchemaIsDiagnosedWithoutAnImplicitMigration(): void
    {
        [$status, $output] = $this->execute('alexa:doctor', ['--server-only']);
        self::assertSame(1, $status);
        self::assertStringContainsString('FAIL OAuth tables', $output);
        self::assertSame(0, (int) $this->connection->query("SELECT COUNT(*) FROM sqlite_master WHERE type = 'table'")->fetchColumn());
    }

    public function testManifestExportIsValidatedAndDoesNotOverwriteOwnerFiles(): void
    {
        $listing = self::listing();
        app()->container()->set(Settings::class, new Settings(array_replace_recursive($this->base, ['alexa' => ['listing' => $listing]])));
        $path = sys_get_temp_dir() . '/naf-alexa-manifest-' . bin2hex(random_bytes(6)) . '.json';

        try {
            [$status, $output] = $this->execute('alexa:setup', ['--migrate', '--manifest=' . $path]);
            self::assertSame(0, $status, $output);
            $document = json_decode(file_get_contents($path), true, 512, JSON_THROW_ON_ERROR);
            self::assertSame('https://alexa.example.test/mcp', $document['integrations'][0]['config']['endpoints']['default']['uri']);
            self::assertSame(['US'], $document['storeListing']['distributionCountries']);
            self::assertStringNotContainsString('client_secret', file_get_contents($path));
            [$status] = $this->execute('alexa:setup', ['--manifest=' . $path]);
            self::assertSame(1, $status);
            self::assertSame($document, json_decode(file_get_contents($path), true));
        } finally {
            if (is_file($path)) {
                unlink($path);
            }
        }
    }

    public static function listing(): array
    {
        return [
            'name'                 => ['value' => 'Test app'],
            'shortDescription'     => 'Query your test application.',
            'fullDescription'      => 'Query data and check availability in your test application.',
            'examplePhrases'       => ['Check app availability', 'Show my app status', 'Ask the app to respond'],
            'privacyAndCompliance' => ['privacyPolicyUrl' => 'https://example.test/privacy', 'termsOfUseUrl' => 'https://example.test/terms'],
            'mediaAssets'          => [
                'icons'          => ['light' => array_map(static fn($size) => ['size' => $size, 'uri' => 'https://example.test/icon-' . $size . '.png'], ['72x72', '64x64', '88x88', '126x126', '180x180', '241x241'])],
                'carouselImages' => [['uri' => 'https://example.test/carousel.png', 'size' => '600x900', 'altText' => 'Test app status']],
            ],
        ];
    }

    private function execute(string $command, array $arguments = []): array
    {
        ob_start();

        try {
            $status = app()->container()->make(Console::class)->run(['naf', $command, ...$arguments]);
        } finally {
            $output = (string) ob_get_clean();
        }

        return [$status, preg_replace('/\x1b\[[0-9;]*m/', '', $output)];
    }
}
