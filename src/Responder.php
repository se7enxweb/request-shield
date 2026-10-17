<?php
/**
 * This file is part of cjw-network/request-shield.
 *
 * @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
 * @license MIT, see LICENSE
 */

declare(strict_types=1);

namespace CjwNetwork\RequestShield;

/**
 * Sends the answer for a request the application does not get to see:
 * a few hundred bytes, never cacheable, nothing that reveals the rule.
 */
class Responder
{
    /**
     * @param array<string, string> $texts in the visitor's language (Texts::all())
     * @param (callable(string, array<string, mixed>): ?string)|null $pages the Pages hook (PageHook::asker()): the site's own refusal page, or null for the shield's
     * @param ?string $logo the site's logo for the built-in page (set challenge-logo)
     * @param bool $api the request is a program's (api-path, it asks for or sends JSON): the refusal as JSON (0030)
     * @param array<int|string, array<string, string>> $errorPages the site's own pages (set error-page): status => language => HTML
     */
    public function send(Decision $decision, Request $request, bool $debugHeader = false, ?string $page = null, ?string $rule = null, array $texts = [], ?string $home = null,
        ?callable $pages = null, ?string $logo = null, bool $api = false, ?string $reference = null, array $errorPages = []): void
    {
        if ($api && $page === null) {
            $this->headers($decision, $debugHeader, $rule, false, true);
            if ($request->method !== 'HEAD') {
                echo json_encode(ErrorPage::json($decision, $reference), JSON_UNESCAPED_SLASHES), "\n";
            }
            return;
        }
        [$body, $builtIn] = $this->page($decision, $page, $texts, $home, $pages, $request, $logo, $reference, $errorPages);
        $this->headers($decision, $debugHeader, $rule, $builtIn);
        if ($request->method !== 'HEAD') {
            echo $body;
        }
    }

    /**
     * The check for an API: 429, the task as JSON and in a header; the client
     * solves it and repeats the request with Request-Shield-Solution -- or
     * waits Retry-After, where there is one.
     *
     * @param array{algorithm: string, challenge: string, maxnumber: int, salt: string, signature: string} $challenge
     */
    public function api(Decision $decision, array $challenge, bool $debugHeader = false, ?string $rule = null): string
    {
        if (!headers_sent()) {
            http_response_code(429);
            foreach (self::apiHeaderLines($decision, $challenge, $debugHeader, $rule) as $line) {
                header($line);
            }
        }
        return (string) json_encode(['error' => $decision->spent ? 'rate_limited' : 'challenge', 'retryAfter' => $decision->retryAfter ?: null,
            'challenge' => $challenge, 'solution' => 'Request-Shield-Solution'], JSON_UNESCAPED_SLASHES);
    }

    /**
     * The header lines of the check for an API or a background request, without
     * sending them -- what api() sends, and what `request-shield test` shows.
     *
     * @param array{algorithm: string, challenge: string, maxnumber: int, salt: string, signature: string} $challenge
     * @return list<string>
     */
    public static function apiHeaderLines(Decision $decision, array $challenge, bool $debugHeader = false, ?string $rule = null): array
    {
        $json = (string) json_encode($challenge, JSON_UNESCAPED_SLASHES);
        $out = ['Content-Type: application/json; charset=utf-8', 'Cache-Control: no-store',
            'Request-Shield-Challenge: ' . rtrim(strtr(base64_encode($json), '+/', '-_'), '=')];
        if ($decision->retryAfter > 0) {
            $out[] = 'Retry-After: ' . $decision->retryAfter;
        }
        if ($debugHeader) {
            $out[] = 'X-RS: ' . $decision->action . ' ' . $decision->reason . ($rule !== null ? '; rule=' . $rule : '');
        }
        return $out;
    }

    public function headers(Decision $decision, bool $debugHeader = false, ?string $rule = null, bool $builtIn = false, bool $json = false): void
    {
        if (headers_sent()) {
            return;
        }
        http_response_code($decision->status);
        foreach (self::headerLines($decision, $debugHeader, $rule, $builtIn, $json) as $line) {
            header($line);
        }
    }

    /**
     * The header lines of a refusal's or a check's page, without sending them --
     * what headers() sends, and what `request-shield test` and the demo show
     * an example answers with (0031 F.3).
     *
     * @return list<string>
     */
    public static function headerLines(Decision $decision, bool $debugHeader = false, ?string $rule = null, bool $builtIn = false, bool $json = false): array
    {
        $out = [$json ? 'Content-Type: application/json; charset=utf-8' : 'Content-Type: text/html; charset=utf-8', 'Cache-Control: no-store', 'X-Robots-Tag: noindex',
            'Vary: Accept-Language'];    // the texts are in the visitor's language
        if ($builtIn) {
            $out[] = 'Content-Security-Policy: ' . ErrorPage::CSP;     // the shield's own page loads nothing (0030)
        }
        if ($json) {
            $out[] = 'X-Content-Type-Options: nosniff';
        }
        if ($decision->retryAfter > 0) {
            $out[] = 'Retry-After: ' . $decision->retryAfter;
        }
        if ($decision->status === 405) {
            $out[] = 'Allow: GET, HEAD, POST';
        }
        if ($debugHeader) {
            $out[] = 'X-RS: ' . $decision->action . ' ' . $decision->reason . ($rule !== null ? '; rule=' . $rule : '');
        }
        return $out;
    }

    /**
     * The page: the one given (the check page), a plugin's (the Pages hook, 0031 B.10),
     * the site's own file (set error-page), else the shield's built-in error page (0030).
     *
     * @param array<string, string> $texts
     * @param (callable(string, array<string, mixed>): ?string)|null $pages
     */
    public function body(Decision $decision, ?string $page = null, array $texts = [], ?string $home = null, ?callable $pages = null, ?Request $request = null,
        ?string $logo = null, ?string $reference = null): string
    {
        return $this->page($decision, $page, $texts, $home, $pages, $request, $logo, $reference)[0];
    }

    /**
     * The page, and whether it is the shield's built-in one (only that one gets its strict CSP).
     *
     * @param array<string, string> $texts
     * @param (callable(string, array<string, mixed>): ?string)|null $pages
     * @param array<int|string, array<string, string>> $errorPages the site's own pages (set error-page): status => language => HTML
     * @return array{0: string, 1: bool}
     */
    public function page(Decision $decision, ?string $page, array $texts, ?string $home, ?callable $pages, ?Request $request, ?string $logo = null, ?string $reference = null,
        array $errorPages = []): array
    {
        if ($page !== null) {
            return [$page, false];
        }
        $texts += Texts::all('en');
        if ($pages !== null) {
            $own = $pages(Pages::ERROR, ['status' => $decision->status, 'decision' => $decision, 'reason' => $decision->reason, 'retryAfter' => $decision->retryAfter,
                'texts' => $texts, 'lang' => $texts['lang'] ?? 'en', 'home' => $home, 'request' => $request, 'reference' => $reference]);
            if ($own !== null) {
                return [$own, false];
            }
        }
        // The site's own page from a file (set error-page), its placeholders filled in: the site's, no CSP of the shield's.
        $file = ErrorPage::own($errorPages, $decision->status, $texts['lang'] ?? 'en');
        if ($file !== null) {
            return [ErrorPage::fill($file, $decision, $texts, $home, $reference), false];
        }
        return [ErrorPage::render($decision, $texts, $home, $logo, $reference, $reference !== null ? time() : null), true];
    }
}
