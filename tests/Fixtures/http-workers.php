<?php

declare(strict_types=1);

if (posix_setsid() === -1) {
    throw new RuntimeException('Cannot isolate the HTTP worker process group.');
}
pcntl_exec(PHP_BINARY, array_slice($argv, 1));
throw new RuntimeException('Cannot start the HTTP workers.');
