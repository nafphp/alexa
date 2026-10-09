<?php

declare(strict_types=1);

namespace Naf\Alexa;

use Naf\OAuth\Server\Model\Client;
use Naf\OAuth\Server\Store\ClientStoreInterface;
use RuntimeException;

final readonly class Clients
{
    public function __construct(private ClientStoreInterface $store, private Settings $settings)
    {
    }

    public function find(bool $user): ?Client
    {
        $matches = array_values(array_filter($this->store->all(), fn(Client $client) => $client->name === $this->settings->clientName($user)));
        if (count($matches) > 1) {
            throw new RuntimeException('Several Alexa clients have the same name; revoke the obsolete registrations.');
        }
        $client = $matches[0] ?? null;
        if ($client !== null && (!$client->isConfidential()
            || $client->grants !== $this->grants($user)
            || $client->scopes !== $this->scopes($user)
            || $client->redirectUris !== ($user ? $this->settings->redirectUris() : [])
            || $client->audiences !== [$this->settings->resource()])) {
            throw new RuntimeException('The existing Alexa client differs from the configuration; review and revoke it before setup.');
        }

        return $client;
    }

    /** @return array{0: Client, 1: ?string} Existing clients keep their secrets and tokens. */
    public function ensure(bool $user): array
    {
        if (($client = $this->find($user)) !== null) {
            return [$client, null];
        }

        return $this->store->register(
            name: $this->settings->clientName($user),
            redirectUris: $user ? $this->settings->redirectUris() : [],
            grants: $this->grants($user),
            scopes: $this->scopes($user),
            confidential: true,
            audiences: [$this->settings->resource()],
        );
    }

    private function grants(bool $user): array
    {
        return $user ? ['authorization_code', 'refresh_token'] : ['client_credentials'];
    }

    private function scopes(bool $user): array
    {
        return $user ? $this->settings->userScopes() : ['mcp:service'];
    }
}
