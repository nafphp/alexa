<?php

declare(strict_types=1);

define('BASE_PATH', __DIR__ . '/Fixtures');
$_ENV['APP_ENV']            = 'test';
$_ENV['PUBLIC_URL']         = 'https://alexa.example.test';
$_ENV['ALEXA_MCP_RESOURCE'] = 'https://alexa.example.test/mcp';
$_ENV['ALEXA_NAME']         = 'Test app';

require dirname(__DIR__) . '/vendor/autoload.php';
