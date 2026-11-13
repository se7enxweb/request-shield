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
 * The shield serves the dashboard's pages itself (0031 B.6): a request the
 * rules let through whose path is a route (Routes) is answered here, before
 * the application -- behind Access::gate(), the route's role, with no-store
 * and noindex on every answer. A site wires nothing.
 *
 * Who may open a page: a `restrict` rule covering it (the address already
 * passed it when we get here: that is the administrator), or a login the
 * gate knows (dashboard-access). A route with
 * neither is refused -- `check` warns about it.
 *
 * In a build without the pages (the mini file alone, without the WAF plugin), a route
 * answers 404: the shield still never hands its own addresses to the site.
 */
final class Dashboard
{
    /**
     * The route of a request, or null -- cheap for the many requests that are
     * none: one stripos per place the routes lie (Routes::bases(); usually
     * just dashboard-path), then the table.
     *
     * @return array{key: string, ext: ?string, tab: ?array{0: string, 1: string}, role: string, order: int, page?: string, path: string}|null
     */
    public static function routeFor(Settings $s, Request $request): ?array
    {
        if ($s->routes === []) {
            return null;
        }
        foreach ($s->routeBases ?: [$s->dashboardPath] as $base) {
            if (stripos($request->path, $base) !== false) {
                /** @var array{key: string, ext: ?string, tab: ?array{0: string, 1: string}, role: string, order: int, page?: string, path: string}|null */
                return Routes::match($s, $request->matchPath());
            }
        }
        return null;
    }

    /**
     * Whether a `restrict` rule covers a path: the address that gets here passed it.
     */
    public static function restricted(Settings $s, string $path): bool
    {
        foreach ($s->restricted as $r) {
            foreach ($r['paths'] as $pattern) {
                if (@preg_match($pattern, $path) === 1) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * The routes nobody guards: no `restrict` rule covers them and the gate
     * has no logins -- for `check`.
     *
     * @return list<string>
     */
    public static function unguarded(Settings $s): array
    {
        if (Access::enabled($s)) {
            return [];
        }
        $open = [];
        foreach ($s->routes as $path => $route) {
            if (!self::restricted($s, $path)) {
                $open[] = $path;
            }
        }
        return $open;
    }

    /**
     * The answer for a route.
     *
     * @param array{key: string, ext: ?string, tab: ?array{0: string, 1: string}, role: string, order: int, page?: string, path: string} $route Routes::match()
     * @param array<mixed> $get $_GET
     * @param array<mixed> $post $_POST
     */
    public static function serve(Settings $s, Request $request, array $route, array $get, array $post, ?string $ruleFile = null): Response
    {
        $path = $request->matchPath();
        $prefix = substr($path, 0, max(0, strlen(rtrim($path, '/')) - strlen(rtrim($route['path'], '/'))));
        $lang = is_string($get['lang'] ?? null) ? $get['lang'] : 'auto';
        $home = $prefix . '/';
        $homeLabel = $request->host;
        $admin = self::restricted($s, $path);
        $own = Access::headers($s);
        $api = $route['key'] === 'api';
        $cors = $api ? self::cors($s, $request) : [];
        // The shield's own page holds its restrict rule in every mode. Enforced, the rule has refused
        // other addresses before this; in mode monitor it only logs them, and reaching the page would
        // otherwise count as having passed it.
        if ($admin && (new Rule\RestrictedPathRule($s->restricted))->check($request, microtime(true)) !== null) {
            if ($api) {
                return self::problem(403, 'Forbidden', 'This address may not use the API (restrict).', [...$own, ...$cors]);
            }
            return Response::html(403, self::plain($request, $lang, 'This page is only for certain addresses.',
                'Diese Seite ist nur für bestimmte Adressen.'), $own);
        }
        if ($api && $request->method === 'OPTIONS') {
            // A browser's preflight carries no token: the API's page answers it (api-origins), before any login.
            $page = $route['page'] ?? null;
            if (is_string($page) && class_exists($page) && is_subclass_of($page, RoutePage::class)) {
                return $page::serve($s, $request, $route, ['who' => '', 'prefix' => '', 'get' => $get, 'post' => $post, 'method' => 'OPTIONS', 'lang' => $lang,
                    'accept' => null, 'links' => [], 'ip' => $request->clientIp, 'home' => '/', 'homeLabel' => '', 'ruleFile' => $ruleFile])->withHeaders($own);
            }
        }
        if (!$admin && !Access::enabled($s)) {
            if ($api) {
                return self::problem(403, 'Forbidden', 'The API is not set up: a restrict rule for ' . $s->dashboardPath . '/** or a login (dashboard-access) is needed.', [...$own, ...$cors]);
            }
            // Nobody guards this page: refused, and check says what to do.
            return Response::html(403, self::plain($request, $lang, 'This page is not set up: a restrict rule for ' . $s->dashboardPath . '/** or a login (dashboard-access) is needed.',
                'Diese Seite ist nicht eingerichtet: eine restrict-Regel für ' . $s->dashboardPath . '/** oder ein Login (dashboard-access) fehlt.'), $own);
        }
        $gate = Access::gate($s, $request, $get, $post, ['admin' => $admin, 'lang' => $lang, 'home' => $home, 'homeLabel' => $homeLabel]);
        if ($gate['who'] === null && $api) {
            // A program gets JSON, never the login form (RFC 9457); a login's own answers (a signed link, sign-out) are no API's.
            $status = in_array($gate['status'], [401, 403, 429], true) ? $gate['status'] : 401;
            return self::problem($status, $status === 429 ? 'Too many requests' : ($status === 403 ? 'Forbidden' : 'Unauthorized'),
                $status === 429 ? 'Too many wrong tokens from this address: wait a minute.' : 'Send a token: Authorization: Bearer <token> (request-shield access-token).',
                [...array_values(array_filter($gate['headers'], static fn (string $h): bool => stripos($h, 'Set-Cookie:') !== 0 && stripos($h, 'Location:') !== 0)),
                    ...($status === 401 ? ['WWW-Authenticate: Bearer'] : []), ...$cors]);
        }
        if ($gate['who'] === null) {
            return new Response($gate['status'], array_merge(['Content-Type: text/html; charset=utf-8'], $gate['headers']), (string) $gate['body']);
        }
        $who = $gate['who'];
        if ($route['role'] === 'admin' && $who !== '*' && $api) {
            return self::problem(403, 'Forbidden', 'This endpoint is the administrator\'s.', [...$gate['headers'], ...$cors]);
        }
        if ($route['role'] === 'admin' && $who !== '*') {
            return Response::html(403, self::plain($request, $lang, 'This page is the administrator\'s.', 'Diese Seite ist dem Administrator vorbehalten.'), $gate['headers']);
        }
        $page = $route['page'] ?? null;
        if ($page === null || !class_exists($page) || !is_subclass_of($page, RoutePage::class)) {
            return Response::html(404, self::plain($request, $lang, 'This page is not part of this build.', 'Diese Seite ist nicht Teil dieser Ausgabe.'), $gate['headers']);
        }
        $links = Access::links($s, $who, Routes::links($s, $prefix));
        $ctx = ['who' => $who, 'prefix' => $prefix, 'get' => $get, 'post' => $post, 'method' => $request->method, 'lang' => $lang,
            'accept' => $request->header('accept-language'), 'links' => $links, 'ip' => $request->clientIp, 'home' => $home, 'homeLabel' => $homeLabel, 'ruleFile' => $ruleFile];
        return $page::serve($s, $request, $route, $ctx)->withHeaders($gate['headers']);
    }

    /**
     * CORS for an API answer: the Origin back, when api-origins names it (the API plugin's setting).
     *
     * @return list<string>
     */
    private static function cors(Settings $s, Request $request): array
    {
        $origin = (string) $request->header('origin');
        $allowed = $s->ext['api']['origins'] ?? [];
        return $origin !== '' && is_array($allowed) && in_array(strtolower(rtrim($origin, '/')), $allowed, true) ? ['Access-Control-Allow-Origin: ' . $origin, 'Vary: Origin'] : [];
    }

    /**
     * A problem for a program (RFC 9457): the API's answer when it cannot answer.
     *
     * @param list<string> $headers
     */
    private static function problem(int $status, string $title, string $detail, array $headers = []): Response
    {
        return new Response($status, ['Content-Type: application/problem+json; charset=utf-8', 'X-Content-Type-Options: nosniff', ...$headers],
            (string) json_encode(['type' => 'about:blank', 'title' => $title, 'status' => $status, 'detail' => $detail], JSON_UNESCAPED_SLASHES));
    }

    /** A short page of the shield's own: one sentence, in the reader's language. */
    private static function plain(Request $request, string $lang, string $en, string $de): string
    {
        $german = Texts::language($lang, $request->header('accept-language')) === 'de';
        $e = static fn (string $v): string => htmlspecialchars($v, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        return '<!doctype html><html lang="' . ($german ? 'de' : 'en') . '"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">'
            . '<title>request-shield</title><style>body{margin:0;padding:40px 20px;font:15px/1.5 system-ui,sans-serif;color:#1d2127;background:#f6f7f9}p{max-width:36em;margin:0 auto}</style></head><body>'
            . '<p>' . $e($german ? $de : $en) . '</p></body></html>';
    }
}
