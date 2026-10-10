<?php

declare(strict_types=1);

namespace Naf\Alexa\Commands;

use Naf\Alexa\Clients;
use Naf\Alexa\Manifest;
use Naf\Alexa\Settings;
use Naf\CLI\Core\AbstractCommand;
use Naf\CLI\Core\Input;
use Naf\CLI\Core\Output;
use Naf\Database\Core\MigrationRunner;
use Naf\OAuth\Server\Migrations\OAuthServerMigration;
use PDO;
use ReflectionClass;
use RuntimeException;
use Throwable;

final class SetupCommand extends AbstractCommand
{
    public const string NAME = 'alexa:setup';

    public function __construct(private readonly Settings $settings, private readonly Clients $clients, private readonly PDO $connection)
    {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->setTitle('Alexa setup')->setDescription('Register Alexa OAuth clients; optionally migrate OAuth tables and export addon.json.');
        $this->addOption('migrate')->addOption('manifest', expectsValue: true);
    }

    public function run(Input $input, Output $output): int
    {
        try {
            $this->settings->assertValid();
            $path     = $input->getOption('manifest');
            $document = null;
            if ($path !== null) {
                if (!is_string($path) || $path === '' || file_exists($path) || is_link($path) || !is_dir(dirname($path))) {
                    throw new RuntimeException('--manifest needs a new file path in an existing directory.');
                }
                $document = json_encode((new Manifest())->document($this->settings), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL;
            }
            if ($input->getOption('migrate') !== null) {
                $source = (new ReflectionClass(OAuthServerMigration::class))->getFileName();
                (new MigrationRunner($this->connection))->run([dirname($source)], 'up', OAuthServerMigration::class);
                $output->writeLine('OAuth migration is applied.', 'ok');
            }
            // Validate both existing registrations before creating either one.
            $this->clients->find(false);
            if ($this->settings->accountLinking()) {
                $this->clients->find(true);
            }
            foreach ($this->settings->accountLinking() ? [false, true] : [false] as $user) {
                [$client, $secret] = $this->clients->ensure($user);
                $output->writeLine(($user ? 'Account-linking' : 'Service') . ' client_id: ' . $client->id);
                if ($secret !== null) {
                    $output->writeLine('client_secret (shown once): ' . $secret);
                } else {
                    $output->writeLine('Existing registration retained. Use oauth:client:rotate-secret if a new secret is needed.');
                }
            }
            if ($document !== null) {
                $file = fopen($path, 'x');
                if ($file === false) {
                    throw new RuntimeException('Could not create the manifest file.');
                }

                try {
                    if (fwrite($file, $document) !== strlen($document)) {
                        throw new RuntimeException('Could not write the complete manifest.');
                    }
                } finally {
                    fclose($file);
                }
                $output->writeLine('Manifest written to ' . $path, 'ok');
            }
            $output->writeLine('Token endpoint: ' . $this->settings->issuer() . '/oauth/token');
            $output->writeLine('Resource: ' . $this->settings->resource());
            $output->writeLine('Run vendor/bin/naf alexa:doctor --server-only, then configure the separate clients in the Alexa AI CLI.');

            return self::SUCCESS;
        } catch (Throwable $exception) {
            $output->writeLine($exception->getMessage(), 'error');

            return self::ERROR;
        }
    }
}
