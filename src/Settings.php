<?php

declare(strict_types=1);

namespace Naf\Alexa;

use InvalidArgumentException;

/** Read the effective host configuration without mutating another plugin's settings. */
final readonly class Settings
{
    public function __construct(private array $config)
    {
    }

    public function issuer(): string
    {
        return rtrim((string) ($this->config['public_url'] ?? ''), '/');
    }

    public function resource(): string
    {
        return (string) ($this->config['mcp']['oauth']['resource'] ?? '');
    }

    public function accountLinking(): bool
    {
        return ($this->config['alexa']['account_linking'] ?? false) === true;
    }

    public function redirectUris(): array
    {
        return (array) ($this->config['alexa']['redirect_uris'] ?? []);
    }

    public function userScopes(): array
    {
        return (array) ($this->config['alexa']['user_scopes'] ?? ['mcp:tools']);
    }

    public function listing(): array
    {
        return (array) ($this->config['alexa']['listing'] ?? []);
    }

    public function clientName(bool $user): string
    {
        return 'Alexa ' . ($user ? 'account linking: ' : 'service: ') . $this->resource();
    }

    /** @return list<string> Local configuration errors, before setup writes anything. */
    public function problems(): array
    {
        $problems = [];
        $issuer   = $this->issuer();
        if (!self::isHttpsUrl($issuer) || !in_array(parse_url($issuer, PHP_URL_PATH), [null, '', '/'], true)) {
            $problems[] = 'public_url must be the public HTTPS origin of this NAF host.';
        }
        if ($this->resource() !== $issuer . '/mcp' || !self::isHttpsUrl($this->resource())) {
            $problems[] = 'mcp:oauth:resource must equal public_url + /mcp (ALEXA_MCP_RESOURCE).';
        }
        $mcp = $this->config['mcp'] ?? [];
        if (($mcp['auth']['enabled'] ?? true) !== true || ($mcp['auth']['driver'] ?? null) !== 'oauth') {
            $problems[] = 'Enable MCP authentication with mcp:auth:driver = oauth.';
        }
        if (($mcp['auth']['discovery_scope'] ?? null) !== 'mcp:service') {
            $problems[] = 'mcp:auth:discovery_scope must be mcp:service.';
        }
        if (($mcp['oauth']['authorization_servers'] ?? []) !== [$issuer]) {
            $problems[] = 'mcp:oauth:authorization_servers must contain this public_url only.';
        }
        $oauth = $this->config['oauth_server'] ?? [];
        if (($oauth['audience'] ?? '') !== $this->resource()) {
            $problems[] = 'oauth_server:audience must match the canonical MCP resource.';
        }
        if (($oauth['routes'] ?? true) !== true) {
            $problems[] = 'Enable the conventional OAuth routes for Alexa discovery.';
        }
        if (!is_string($oauth['name'] ?? null) || trim($oauth['name']) === '') {
            $problems[] = 'Set oauth_server:name (ALEXA_NAME) to your application name.';
        }
        $ttl = $oauth['access_token_ttl'] ?? 3600;
        if (!is_int($ttl) || $ttl < 1 || $ttl > 3600) {
            $problems[] = 'oauth_server:access_token_ttl must be between 1 and 3600 seconds.';
        }
        if (!array_key_exists('mcp:service', $oauth['scopes'] ?? [])) {
            $problems[] = 'Declare the mcp:service OAuth scope.';
        }
        if (($this->config['csrf_exempt_routes']['mcp_server_rpc'] ?? false) !== true) {
            $problems[] = 'Exempt the authenticated mcp_server_rpc route from browser CSRF checks.';
        }
        if ($this->accountLinking()) {
            if ($this->redirectUris() === []) {
                $problems[] = 'Set alexa:redirect_uris to the exact HTTPS callbacks supplied by Amazon.';
            }
            foreach ($this->redirectUris() as $uri) {
                if (!self::isHttpsUrl($uri, true)) {
                    $problems[] = 'Every Alexa redirect URI must be HTTPS without credentials or a fragment.';
                }
            }
            if ($this->userScopes() === []) {
                $problems[] = 'Account linking requires alexa:user_scopes.';
            }
            foreach ($this->userScopes() as $scope) {
                if (!is_string($scope) || $scope === 'mcp:service' || !isset($oauth['scopes'][$scope])) {
                    $problems[] = 'User scopes must be declared OAuth scopes, separate from mcp:service.';
                }
            }
            if (($mcp['oauth']['scopes_supported'] ?? null) !== $this->userScopes()) {
                $problems[] = 'mcp:oauth:scopes_supported must match alexa:user_scopes for account linking.';
            }
            if (!is_string($oauth['login_route'] ?? null) || trim($oauth['login_route']) === '') {
                $problems[] = 'Configure oauth_server:login_route for the host login screen.';
            }
        }

        return array_values(array_unique($problems));
    }

    public function assertValid(): void
    {
        if (($problems = $this->problems()) !== []) {
            throw new InvalidArgumentException(implode(PHP_EOL, $problems));
        }
    }

    public static function isHttpsUrl(mixed $url, bool $allowQuery = false): bool
    {
        if (!is_string($url) || filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }
        $parts = parse_url($url);

        return ($parts['scheme'] ?? '') === 'https' && !empty($parts['host'])
            && !isset($parts['user']) && !isset($parts['pass'])
            && !isset($parts['fragment']) && ($allowQuery || !isset($parts['query']));
    }
}
