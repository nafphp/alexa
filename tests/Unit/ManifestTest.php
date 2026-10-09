<?php

declare(strict_types=1);

namespace Tests\Unit;

use InvalidArgumentException;
use Naf\Alexa\Manifest;
use Naf\Alexa\Settings;
use PHPUnit\Framework\TestCase;

use function Naf\config;

final class ManifestTest extends TestCase
{
    public function testMissingIconSizeAndOversizedUnicodeNameAreRejected(): void
    {
        $listing = CommandsTest::listing();
        array_pop($listing['mediaAssets']['icons']['light']);

        try {
            (new Manifest())->document(new Settings(array_replace_recursive(config(), ['alexa' => ['listing' => $listing]])));
            self::fail('Missing icon accepted.');
        } catch (InvalidArgumentException $exception) {
            self::assertStringContainsString('six', $exception->getMessage());
        }
        $listing                  = CommandsTest::listing();
        $listing['name']['value'] = str_repeat('ä', 31);
        $this->expectException(InvalidArgumentException::class);
        (new Manifest())->document(new Settings(array_replace_recursive(config(), ['alexa' => ['listing' => $listing]])));
    }

    public function testHttpAndCredentialedUrlsAreRejected(): void
    {
        self::assertFalse(Settings::isHttpsUrl('http://example.test/mcp'));
        self::assertFalse(Settings::isHttpsUrl('https://owner:secret@example.test/mcp'));
        self::assertFalse(Settings::isHttpsUrl('https://example.test/mcp#fragment'));
        self::assertTrue(Settings::isHttpsUrl('https://example.test/mcp'));
    }
}
