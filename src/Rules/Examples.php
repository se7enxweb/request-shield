<?php
/**
 * This file is part of cjw-network/request-shield.
 *
 * @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
 * @license MIT, see LICENSE
 */

declare(strict_types=1);

namespace CjwNetwork\RequestShield\Rules;

use CjwNetwork\RequestShield\Challenge\PassCookie;
use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\IpAddress;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Shield;
use CjwNetwork\RequestShield\Store\MemoryStore;

/**
 * The examples next to the rules (expect lines, proposal 0029), decided:
 * request-shield test. Each example on a fresh store in memory, with the
 * rules switched on (monitor as enforce) unless asked for as written; nothing
 * is written to the site's store, log or statistics.
 *
 * @phpstan-type Example array{method: string, url: string, outcome: string, by: ?string, rule: ?string, from: string, pass: bool, times: int, headers: array<string, string>, text: ?string, at: string, site: ?string, ua: ?string, demo: ?string}
 * @phpstan-type Result array{example: Example, about: ?string, status: string, got: string, gotRule: ?string, why: string, http: int, headers: list<string>}
 */
final class Examples
{
    /** The browser an example comes from: a real one, so no rule about bots or tools decides by accident. */
    public const USER_AGENT = 'Mozilla/5.0 (X11; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0';

    /**
     * @param list<string> $files the rule files, the main one last (as read())
     * @param ?string $only the examples of this rule only
     * @return array{results: list<Result>, without: list<string>}
     *   results: one per example, status pass|fail|skip; without: the site's
     *   rules (not the built-in ones) no example is about
     */
    public static function run(array $files, bool $asWritten = false, ?string $only = null): array
    {
        $base = RuleFile::read($files);
        /** @var array<string, Example> $examples by where they are written: the base's, then each site block's */
        $examples = [];
        $ids = self::ruleIds($base['config']);
        foreach ($base['examples'] as $x) {
            $examples[$x['at']] = $x;
        }
        $sites = [];
        foreach ((array) ($base['config']['sites'] ?? []) as $site) {
            if (is_string($site)) {
                $sites[$site] = true;
            }
        }
        foreach (array_keys($sites) as $site) {
            $read = RuleFile::read($files, (string) $site);
            $ids += self::ruleIds($read['config']);
            foreach ($read['examples'] as $x) {
                if ($x['site'] !== null || !isset($examples[$x['at']])) {
                    $examples[$x['at']] = $x;
                }
            }
        }
        $dir = sys_get_temp_dir() . '/request-shield-test-' . getmypid() . '-' . bin2hex(random_bytes(4));
        $settings = [];
        $results = [];
        $covered = [];
        try {
            foreach ($examples as $x) {
                $about = $x['by'] ?? $x['rule'];
                if ($about !== null) {
                    $covered[$about] = true;
                }
                if ($only !== null && $about !== $only) {
                    continue;
                }
                $site = $x['site'];
                $key = $site ?? '';
                if (!isset($settings[$key])) {
                    $settings[$key] = self::settings($files, $site, $asWritten, $dir);
                }
                $results[] = self::decide($settings[$key], $x, $asWritten);
            }
        } finally {
            if (is_dir($dir)) {
                foreach (glob($dir . '/*') ?: [] as $f) {
                    @unlink($f);
                }
                @rmdir($dir);
            }
        }
        $without = [];
        foreach ($ids as $id => $at) {
            if (!isset($covered[$id]) && strncmp($at, 'built-in', 8) !== 0) {
                $without[] = $id;
            }
        }
        return ['results' => $results, 'without' => $without];
    }

    /**
     * The settings an example is decided with: switched on (or as written),
     * with a store, a secret and no log of their own -- a test never touches
     * the site's.
     *
     * @param list<string> $files
     */
    private static function settings(array $files, ?string $site, bool $asWritten, string $dir): Settings
    {
        $c = $asWritten ? RuleFile::read($files, $site)['config'] : RuleFile::switchedOn($files, $site);
        unset($c['monitorRules']);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }
        $c['storeDir'] = $dir;
        $c['store'] = 'memory';
        $c['challenge'] = (is_array($c['challenge'] ?? null) ? $c['challenge'] : []);
        $c['challenge']['secret'] = bin2hex(random_bytes(32));
        $c['challenge']['dnsLookups'] = 0;              // no DNS from a test
        $c['log'] = (is_array($c['log'] ?? null) ? $c['log'] : []);
        $c['log']['file'] = null;
        $c['live'] = ['enabled' => false];
        return Settings::from($c);
    }

    /**
     * One example, decided as `request-shield test` decides it: on a fresh
     * store, with its pass, its count and its headers (the demo's answer to
     * a row that needs them, 0031 F.4).
     *
     * @param Example $x
     * @return Result
     */
    public static function one(Settings $s, array $x): array
    {
        return self::decide($s, $x, true);
    }

    /**
     * @param Example $x
     * @return Result
     */
    private static function decide(Settings $s, array $x, bool $asWritten): array
    {
        $about = $x['by'] ?? (in_array($x['outcome'], ['passes', 'uncached', 'answered'], true) ? null : $x['rule']);
        // A path is a path ("//admin/" too -- parse_url() would take "admin" for a host);
        // only a full address names a scheme and a host.
        if ($x['url'][0] === '/') {
            $q = strpos($x['url'], '?');
            $parts = $q === false ? ['path' => $x['url']] : ['path' => substr($x['url'], 0, $q), 'query' => substr($x['url'], $q + 1)];
        } else {
            $parts = parse_url($x['url']);
            $parts = is_array($parts) ? $parts : [];
        }
        $host = isset($parts['host']) ? strtolower($parts['host']) : ($x['site'] ?? ($s->hosts[0] ?? 'www.example.org'));
        $path = ($parts['path'] ?? '/') . (isset($parts['query']) ? '?' . $parts['query'] : '');
        $https = ($parts['scheme'] ?? 'https') === 'https';
        $server = ['REQUEST_METHOD' => $x['method'], 'REQUEST_URI' => $path, 'QUERY_STRING' => $parts['query'] ?? '',
            'HTTP_HOST' => $host, 'SERVER_NAME' => $host, 'SERVER_PORT' => $https ? '443' : '80', 'REMOTE_ADDR' => $x['from'],
            'HTTP_USER_AGENT' => $x['ua'] ?? self::USER_AGENT, 'HTTP_ACCEPT' => 'text/html,application/xhtml+xml,*/*;q=0.8', 'HTTP_ACCEPT_LANGUAGE' => 'en'];
        if ($https) {
            $server['HTTPS'] = 'on';
        }
        foreach ($x['headers'] as $name => $value) {
            $server['HTTP_' . strtoupper(str_replace('-', '_', $name))] = $value;
        }
        if ($x['method'] !== 'GET' && $x['method'] !== 'HEAD') {
            $server['CONTENT_TYPE'] = 'application/x-www-form-urlencoded';
        }
        $now = (float) time();
        if ($x['pass']) {
            // A pass, as the check would have issued it: the visitor solved it before.
            $cookie = (new PassCookie(\CjwNetwork\RequestShield\Challenge\Secret::resolve($s->challenge->secret, $s->storeDir), $s->challenge->bindUserAgent))
                ->issue(IpAddress::bucket($x['from'], $s->ipv6Prefix), $x['ua'] ?? self::USER_AGENT, (int) $now + $s->challenge->passTtl);
            $server['HTTP_COOKIE'] = $s->challenge->cookie . '=' . $cookie;
        }
        $shield = new Shield($s, new MemoryStore());
        $request = Request::fromServer($server, $s->trustedProxies);
        $d = Decision::allow();
        $final = $d;
        $json = null;
        for ($i = 0; $i < $x['times']; $i++) {
            $request = Request::fromServer($server, $s->trustedProxies);
            $d = $shield->decide($request, $now);
            $settled = $shield->settle($d, $request, $now);
            $final = $settled['decision'];
            $json = $settled['json'];
            if (!$final->passes() && $s->bans !== []) {
                $shield->signals($final, $request, $now);       // as protect(): refusals may lead to a ban
            }
        }
        if ($s->mode === 'monitor' && !$final->passes()) {
            $final = Decision::allowUncached('monitor');    // as protect(): watched, let through, never cached (--as-written)
        }
        $got = self::outcome($final);
        if ($got === 'check' && $json !== null) {
            $got = 'json-check';        // the check as JSON (an API, a background request), not the page
        }
        // What the visitor would get: the site's own answer (200, its headers) when it passes,
        // else the shield's status and headers -- the same lines Responder sends.
        $http = $final->passes() ? 200 : $final->status;
        $headers = $final->passes() ? [] : ($got === 'json-check' && $json !== null ? \CjwNetwork\RequestShield\Responder::apiHeaderLines($final, $json)
            : \CjwNetwork\RequestShield\Responder::headerLines($final));
        $gotRule = $final->passes() && $final->action === Decision::ALLOW ? null : $shield->explain($d, $request);
        if ($about !== null && !self::inEffect($s, $about) && !(isset($s->origins['monitor'][$about]) && !$asWritten)) {
            $why = isset($s->origins['monitor'][$about]) ? "$about is only watched (monitor) -- test without --as-written" : "$about is not in effect here (taken back or replaced)";
            return ['example' => $x, 'about' => $x['by'] ?? $x['rule'], 'status' => 'skip', 'got' => $got, 'gotRule' => $gotRule, 'why' => $why, 'http' => $http, 'headers' => $headers];
        }
        $ok = ($got === $x['outcome'] || ($x['outcome'] === 'answered' && ($got === 'passes' || $got === 'uncached'))
            || ($x['outcome'] === 'check' && $got === 'json-check')) && ($about === null || $gotRule === $about);
        $why = $ok ? '' : 'expected ' . $x['outcome'] . ($about !== null ? " by $about" : '') . ', got ' . $got . ($gotRule !== null ? " by $gotRule" : '');
        return ['example' => $x, 'about' => $x['by'] ?? $x['rule'], 'status' => $ok ? 'pass' : 'fail', 'got' => $got, 'gotRule' => $gotRule, 'why' => $why, 'http' => $http, 'headers' => $headers];
    }

    /** How a decision reads in an expect line: passes, uncached, check, or the status refused with. */
    public static function outcome(Decision $d): string
    {
        switch ($d->action) {
            case Decision::ALLOW:
                return 'passes';
            case Decision::ALLOW_UNCACHED:
                return 'uncached';
            case Decision::CHALLENGE:
                return 'check';
        }
        return (string) $d->status;
    }

    /** Whether a rule still decides anything here: named in the settings' origins or bans (not only described or watched). */
    private static function inEffect(Settings $s, string $id): bool
    {
        if ($id === 'built-in') {
            return true;                // the fixed checks: always there
        }
        foreach ($s->bans as $b) {
            if ($b['rule'] === $id) {
                return true;
            }
        }
        // A deny line: in the list, not in the origins -- every one of them in the table's
        // names ($s->deny holds only the first ones, for the pages).
        if (strpos("\n" . ($s->denyTable['ids'] ?? ''), "\n" . $id . "\n") !== false) {
            return true;
        }
        foreach ($s->feeds as $f) {
            if ($f['rule'] === $id && $f['state'] === 'in force') {
                return true;            // a feed line whose list is used: in the feeds, not in the origins
            }
        }
        foreach ($s->origins as $section => $map) {
            if (in_array($section, ['at', 'rev', 'text', 'monitor', 'area', 'warnings'], true)) {
                continue;
            }
            if (in_array($id, $map, true)) {
                return true;
            }
        }
        return false;
    }

    /**
     * The rules with an ID that decide something about a request -- the ones
     * an example can be about (not the statistics' access lines, say).
     *
     * @param array<string, mixed> $config
     * @return array<string, string> ID => where it is written
     */
    private static function ruleIds(array $config): array
    {
        $origins = is_array($config['origins'] ?? null) ? $config['origins'] : [];
        $at = is_array($origins['at'] ?? null) ? $origins['at'] : [];
        $deciding = [];
        foreach ($origins as $section => $map) {
            if (in_array($section, ['at', 'rev', 'text', 'monitor', 'area', 'warnings', 'dashboardAccess', 'plugins', 'feeds', 'backend'], true) || !is_array($map)) {
                continue;
            }
            array_walk_recursive($map, static function ($v) use (&$deciding): void {
                if (is_string($v)) {
                    $deciding[$v] = true;
                }
            });
        }
        foreach ((array) ($origins['monitor'] ?? []) as $id => $rule) {
            $deciding[(string) $id] = true;
        }
        $out = [];
        foreach ($at as $id => $where) {
            if (isset($deciding[$id]) && is_string($where)) {
                $out[(string) $id] = $where;
            }
        }
        return $out;
    }
}
