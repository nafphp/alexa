<?php

declare(strict_types=1);

use Naf\Alexa\Commands\DoctorCommand;
use Naf\Alexa\Commands\SetupCommand;
use Naf\Alexa\Settings;

use function Naf\app;
use function Naf\CLI\command;
use function Naf\config;

app()->container()->set(Settings::class, static fn() => new Settings(config()));
command()->add(SetupCommand::class);
command()->add(DoctorCommand::class);
