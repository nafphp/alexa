<?php

declare(strict_types=1);

// Test-only dependency resolution while the prerequisite RCs await publication.
// Composer metadata shipped to applications keeps stable constraints throughout.
$root    = dirname(__DIR__);
$runtime = $root . '/.test-runtime';
if (!is_dir($runtime)) {
    mkdir($runtime);
}
$repositories = [['type' => 'path', 'url' => $root, 'options' => ['versions' => ['naf/alexa' => '0.1.0']]]];
$require      = ['naf/alexa' => '0.1.0'];
foreach (['mcp' => '0.2.5', 'oauth-server' => '0.2.4'] as $package => $version) {
    $local = getenv('NAF_TEST_' . strtoupper(str_replace('-', '_', $package)) . '_PATH');
    if ($local !== false && $local !== '') {
        $repositories[] = ['type' => 'path', 'url' => $local, 'options' => ['versions' => ['naf/' . $package => $version]]];
    } else {
        $repositories[]             = ['type' => 'vcs', 'url' => 'https://github.com/nafphp/' . $package];
        $require['naf/' . $package] = 'dev-v' . $version . '-rc as ' . $version;
    }
}
$package  = json_decode(file_get_contents($root . '/composer.json'), true, 512, JSON_THROW_ON_ERROR);
$composer = [
    'name'         => 'naf-tests/alexa',
    'require'      => $require + $package['require-dev'],
    'repositories' => $repositories,
    'autoload-dev' => ['psr-4' => ['Tests\\' => $root . '/tests/']],
    'config'       => ['vendor-dir' => $root . '/vendor', 'platform' => ['php' => '8.3.0']],
];
file_put_contents($runtime . '/composer.json', json_encode($composer, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR) . PHP_EOL);
passthru('composer update --working-dir=' . escapeshellarg($runtime) . ' --prefer-dist --no-interaction --no-progress', $status);
exit($status);
