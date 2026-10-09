<?php

declare(strict_types=1);

namespace Naf\Alexa;

use InvalidArgumentException;

/** The published MCP Toolkit addon.json format. Credentials are never part of the manifest. */
final class Manifest
{
    private const array ICON_SIZES = ['72x72', '64x64', '88x88', '126x126', '180x180', '241x241'];

    public function document(Settings $settings): array
    {
        $settings->assertValid();
        $listing = $settings->listing();
        $this->text($listing['name']['value'] ?? null, 30, 'name.value');
        $this->text($listing['shortDescription'] ?? null, 123, 'shortDescription');
        $this->text($listing['fullDescription'] ?? null, 4000, 'fullDescription');
        $phrases = $listing['examplePhrases'] ?? [];
        if (!is_array($phrases) || !array_is_list($phrases) || count($phrases) < 3 || count($phrases) > 4) {
            throw new InvalidArgumentException('listing.examplePhrases requires 3 or 4 phrases.');
        }
        foreach ($phrases as $phrase) {
            $this->text($phrase, 200, 'examplePhrases');
        }
        foreach (['privacyPolicyUrl', 'termsOfUseUrl'] as $key) {
            if (!Settings::isHttpsUrl($listing['privacyAndCompliance'][$key] ?? null, true)) {
                throw new InvalidArgumentException('listing.privacyAndCompliance.' . $key . ' must be HTTPS.');
            }
        }
        foreach (['light', 'dark'] as $mode) {
            $icons = $listing['mediaAssets']['icons'][$mode] ?? [];
            if ($mode === 'dark' && $icons === []) {
                continue;
            }
            if (!is_array($icons) || !array_is_list($icons)) {
                throw new InvalidArgumentException('listing.mediaAssets.icons must contain image lists.');
            }
            $sizes = [];
            foreach ($icons as $icon) {
                $this->image($icon);
                $sizes[] = $icon['size'] ?? '';
            }
            sort($sizes);
            $required = self::ICON_SIZES;
            sort($required);
            if ($sizes !== $required) {
                throw new InvalidArgumentException('listing.mediaAssets.icons.' . $mode . ' requires all six Amazon icon sizes.');
            }
        }
        foreach (['carouselImages' => '600x900', 'bannerImages' => '1200x600'] as $key => $size) {
            $images = $listing['mediaAssets'][$key] ?? [];
            if (!is_array($images) || !array_is_list($images) || ($key === 'carouselImages' && $images === [])) {
                throw new InvalidArgumentException('listing.mediaAssets.' . $key . ' requires an image list.');
            }
            foreach ($images as $image) {
                $this->image($image);
                $this->text($image['altText'] ?? null, 250, $key . '.altText');
                if (($image['size'] ?? '') !== $size) {
                    throw new InvalidArgumentException($key . ' images must have size ' . $size . '.');
                }
            }
        }
        $listing['default'] = 'DEFAULT';

        return [
            'manifestVersion' => '1.0',
            'storeListing'    => ['distributionCountries' => ['US'], 'locales' => ['en-US' => $listing]],
            'integrations'    => [[
                'type'   => 'MCP',
                'config' => ['endpoints' => ['default' => ['type' => 'HTTPS', 'uri' => $settings->resource()]]],
            ]],
        ];
    }

    private function text(mixed $value, int $limit, string $name): void
    {
        if (!is_string($value) || trim($value) === '' || mb_strlen($value) > $limit) {
            throw new InvalidArgumentException('listing.' . $name . ' must contain 1–' . $limit . ' characters.');
        }
    }

    private function image(mixed $image): void
    {
        $uri = is_array($image) ? ($image['uri'] ?? null) : null;
        if (!Settings::isHttpsUrl($uri, true)
            || !in_array(strtolower(pathinfo(parse_url($uri, PHP_URL_PATH) ?? '', PATHINFO_EXTENSION)), ['png', 'jpg', 'jpeg', 'webp'], true)) {
            throw new InvalidArgumentException('Media URIs must be HTTPS PNG, JPG, JPEG or WEBP URLs.');
        }
    }
}
