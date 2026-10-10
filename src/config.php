<?php

declare(strict_types=1);

return [
    'public_url'   => 'ENV:PUBLIC_URL',
    'oauth_server' => [
        'name'     => 'ENV:ALEXA_NAME',
        'audience' => 'ENV:ALEXA_MCP_RESOURCE',
        'scopes'   => [
            'mcp:service' => ['label' => 'Discover tools and access public data', 'permission' => null],
            'mcp:tools'   => ['label' => 'Use your account through Alexa', 'permission' => 'mcp:tools'],
        ],
    ],
    'mcp' => [
        'auth'  => ['enabled' => true, 'driver' => 'oauth', 'discovery_scope' => 'mcp:service'],
        'oauth' => [
            'resource'              => 'ENV:ALEXA_MCP_RESOURCE',
            'authorization_servers' => ['ENV:PUBLIC_URL'],
            'scopes_supported'      => ['mcp:tools'],
        ],
    ],
    'alexa' => [
        'account_linking' => false,
        'redirect_uris'   => [],
        'user_scopes'     => ['mcp:tools'],
        // The en-US locale entry from Amazon's addon.json schema; no invented store copy.
        'listing' => [],
    ],
];
