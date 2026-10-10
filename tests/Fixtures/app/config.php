<?php

declare(strict_types=1);

return [
    'database'     => ['driver' => 'sqlite', 'database' => ':memory:'],
    'auth'         => ['session' => false],
    'oauth_server' => ['key_path' => sys_get_temp_dir() . '/naf-alexa-no-keys'],
];
