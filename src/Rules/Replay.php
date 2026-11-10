<?php
/**
 * This file is part of cjw-network/request-shield.
 *
 * @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
 * @license MIT, see LICENSE
 */

declare(strict_types=1);

namespace CjwNetwork\RequestShield\Rules;

use CjwNetwork\RequestShield\Settings;

/**
 * The replay (proposal 0016, first part): requests known to be good -- a
 * session someone clicked through, recorded by the browser or by end-to-end
 * tests as a HAR file; a web server's access log; or a list of addresses --
 * sent through the rules as request-shield test sends its examples: each on
 * a fresh store, nothing counted, monitor rules switched on unless as written.
 * Says which of them the rules would refuse or check, and by which rule.
 *
 * Read: the shape the requests need -- method, address, the headers a rule
 * looks at (Origin, Referer, Content-Type, User-Agent, Accept …); never a
 * cookie, never a body. Static files (style sheets, scripts, pictures, fonts)
 * are left out unless all are asked for: a web server answers them without PHP.
 *
 * @phpstan-type Recorded array{method: string, url: string, headers: array<string, string>, from: ?string, found?: bool}
 * @phpstan-type Replayed array{method: string, url: string, count: int, got: string, rule: ?string, http: int, kind: string, found: bool}
 */
final class Replay
{
    /** The headers a replayed request keeps: those a rule may look at. Never Cookie or Authorization. */
    public const HEADERS = ['origin', 'referer', 'content-type', 'user-agent', 'accept', 'accept-language', 'x-requested-with'];

    /** Files a web server answers itself, without PHP. */
    public const STATIC = '/\.(css|js|mjs|map|png|jpe?g|gif|webp|avif|svg|ico|bmp|woff2?|ttf|otf|eot|mp4|webm|mp3|ogg|wav|pdf|zip|txt|xml|json)$/i';

    /**
     * The requests of a recording: a HAR file (JSON, log.entries), a web
     * server's access log (combined or common: only answers 2xx and 3xx, the
     * others were no good requests), or one address per line ("GET /path",
     * "/path", a full address; # starts a comment).
     *
     * @return array{format: string, requests: list<Recorded>, skipped: int}
     */
    public static function read(string $text): array
    {
        $trim = ltrim($text);
        // A learning run: any of its first lines one of its objects (a rotated file may begin in the middle of one).
        foreach (array_slice(preg_split('/\R/', $trim) ?: [], 0, 20) as $line) {
            $one = $line !== '' && $line[0] === '{' ? json_decode($line, true) : null;
            if (is_array($one) && isset($one['method'], $one['path'], $one['t'])) {
                return self::learned($text);
            }
        }
        if ($trim !== '' && $trim[0] === '{') {
            return self::har($text);
        }
        $out = [];
        $skipped = 0;
        $format = 'list';
        foreach (preg_split('/\R/', $text) ?: [] as $n => $line) {
            $line = trim($line);
            if ($line === '' || $line[0] === '#') {
                continue;
            }
            // 203.0.113.9 - - [04/Oct/2026:10:00:00 +0200] "GET /path?x=1 HTTP/1.1" 200 1234 "https://…/" "Mozilla/5.0 …"
            if (preg_match('#^(\S+) \S+ \S+ \[[^\]]*\] "([A-Z]{1,10}) (\S+) [^"]*" (\d{3}) \S+(?: "([^"]*)" "([^"]*)")?#', $line, $m) === 1) {
                $format = 'access log';
                if ((int) $m[4] >= 400) {
                    $skipped++;                 // the site refused it, or failed: no request to keep working
                    continue;
                }
                $headers = [];
                foreach ([5 => 'referer', 6 => 'user-agent'] as $i => $name) {
                    $v = (string) ($m[$i] ?? '');       // the combined format has them, the common one not
                    if ($v !== '' && $v !== '-') {
                        $headers[$name] = $v;
                    }
                }
                $out[] = ['method' => $m[2], 'url' => $m[3], 'headers' => $headers, 'from' => @inet_pton($m[1]) !== false ? $m[1] : null];
            } elseif (preg_match('#^(?:([A-Z]{1,10})\s+)?((?:https?://|/)\S*)$#', $line, $m) === 1) {
                $out[] = ['method' => $m[1] !== '' ? $m[1] : 'GET', 'url' => $m[2], 'headers' => [], 'from' => null];
            } else {
                throw new \InvalidArgumentException('line ' . ($n + 1) . ': a request is "GET /path", "/path", a full address, or an access log line -- not "' . substr($line, 0, 80) . '"');
            }
        }
        return ['format' => $format, 'requests' => $out, 'skipped' => $skipped];
    }

    /**
     * A learning run's recording (request-shield learn, <store-dir>/learned.jsonl):
     * the requests clicked -- only those the shield let through and the site
     * answered below 400, as with an access log -- and what their pages offered:
     * each form (its method, its fields; a POST with the site's own Origin, as a
     * browser sends it), each link and each address a script named (a GET). The
     * recording holds no values: each parameter gets one of its type ($sample).
     *
     * @return array{format: string, requests: list<Recorded>, skipped: int}
     */
    private static function learned(string $text): array
    {
        $out = [];
        $skipped = 0;
        $found = [];
        foreach (preg_split('/\R/', $text) ?: [] as $line) {
            $r = $line === '' ? null : json_decode($line, true);
            if (!is_array($r) || !is_string($r['method'] ?? null) || !is_string($r['path'] ?? null) || !is_string($r['host'] ?? null)) {
                continue;
            }
            $origin = 'https://' . $r['host'];
            $status = is_int($r['status'] ?? null) ? $r['status'] : 200;
            if (!in_array($r['decided'] ?? 'allow', ['allow', 'allow-uncached'], true) || $status >= 400) {
                $skipped++;                     // refused then, or the site failed it: no request to keep working
            } else {
                /** @var array<string, string> $query */
                $query = is_array($r['query'] ?? null) ? $r['query'] : [];
                $headers = $r['method'] === 'GET' || $r['method'] === 'HEAD' ? [] : ['origin' => $origin];
                if (is_string($r['type'] ?? null)) {
                    $headers['content-type'] = $r['type'];
                }
                $out[] = ['method' => $r['method'], 'url' => $origin . self::sampled($r['path'], $query), 'headers' => $headers, 'from' => null, 'found' => false];
            }
            $f = is_array($r['found'] ?? null) ? $r['found'] : [];
            foreach (is_array($f['forms'] ?? null) ? $f['forms'] : [] as $form) {
                if (is_array($form) && is_string($form['action'] ?? null) && is_string($form['method'] ?? null)) {
                    $fields = [];
                    foreach (is_array($form['fields'] ?? null) ? array_keys($form['fields']) : [] as $name) {
                        $fields[(string) $name] = '';       // a form field's type is an input's (email, hidden): any value, "1"
                    }
                    $post = $form['method'] === 'POST';
                    $found[$form['method'] . ' ' . $origin . $form['action'] . ' ' . json_encode($post ? [] : $fields)] = ['method' => $form['method'],
                        'url' => $origin . self::sampled($form['action'], $post ? [] : $fields),
                        'headers' => $post ? ['origin' => $origin, 'content-type' => 'application/x-www-form-urlencoded'] : [], 'from' => null, 'found' => true];
                }
            }
            foreach (['links', 'scripts'] as $k) {
                foreach (is_array($f[$k] ?? null) ? $f[$k] : [] as $target) {
                    if (is_string($target)) {
                        $found['GET ' . $origin . $target] = ['method' => 'GET', 'url' => $origin . self::sampled($target, []), 'headers' => [], 'from' => null, 'found' => true];
                    }
                }
            }
        }
        return ['format' => 'learning run', 'requests' => array_merge($out, array_values($found)), 'skipped' => $skipped];
    }

    /** One value of each type -- the narrowest that is still of it; a name of no known type gets "1", which every type takes. */
    private const SAMPLE = ['int' => '1', 'number' => '1.5', 'id' => 'a1', 'word' => 'word', 'list' => 'a,b', 'text' => 'two words', '' => '1'];

    /**
     * An address to replay: the path ("*" where the page had a placeholder: "1"),
     * its parameters each with a value of its type -- the names of a target
     * ("/news/?page&sort") get "1".
     *
     * @param array<string, string> $types name => type
     */
    private static function sampled(string $target, array $types): string
    {
        $q = strpos($target, '?');
        $path = str_replace('*', '1', $q === false ? $target : substr($target, 0, $q));
        if ($q !== false) {
            foreach (explode('&', substr($target, $q + 1)) as $name) {
                if ($name !== '') {
                    $types[$name] ??= '';
                }
            }
        }
        $pairs = [];
        foreach ($types as $name => $type) {
            $pairs[] = rawurlencode((string) $name) . '=' . rawurlencode(self::SAMPLE[$type] ?? '1');
        }
        return $path . ($pairs === [] ? '' : '?' . implode('&', $pairs));
    }

    /** @return array{format: string, requests: list<Recorded>, skipped: int} */
    private static function har(string $text): array
    {
        $har = json_decode($text, true);
        $log = is_array($har) && is_array($har['log'] ?? null) ? $har['log'] : [];
        $entries = is_array($log['entries'] ?? null) ? $log['entries'] : null;
        if ($entries === null) {
            throw new \InvalidArgumentException('not a HAR file: no log.entries');
        }
        $out = [];
        $skipped = 0;
        foreach ($entries as $entry) {
            $r = is_array($entry) && is_array($entry['request'] ?? null) ? $entry['request'] : null;
            $url = is_string($r['url'] ?? null) ? $r['url'] : '';
            if ($r === null || preg_match('#^https?://#i', $url) !== 1) {
                $skipped++;                     // data:, blob:, a browser's own
                continue;
            }
            $headers = [];
            foreach (is_array($r['headers'] ?? null) ? $r['headers'] : [] as $h) {
                $name = is_array($h) && is_string($h['name'] ?? null) ? strtolower($h['name']) : '';
                if (in_array($name, self::HEADERS, true) && is_string($h['value'] ?? null)) {
                    $headers[$name] = $h['value'];
                }
            }
            $out[] = ['method' => is_string($r['method'] ?? null) ? strtoupper($r['method']) : 'GET', 'url' => $url, 'headers' => $headers, 'from' => null];
        }
        return ['format' => 'HAR', 'requests' => $out, 'skipped' => $skipped];
    }

    /**
     * Each different request once (with how often it came), decided as an
     * example is: on a fresh store, nothing counted. The settings come per
     * website (a site block's for its names).
     *
     * @param list<Recorded> $requests
     * @param callable(string): Settings $settingsFor the settings for a host ('' for an address without one)
     * @param ?string $ip the visitor's address for every request; null: each request's own (an access log), else 198.51.100.7
     * @return array{results: list<Replayed>, total: int, static: int, foreign: int}
     */
    public static function run(array $requests, callable $settingsFor, ?string $ip, bool $all = false): array
    {
        $base = $settingsFor('');
        $hosts = $base->hosts !== [] ? array_map('strtolower', $base->hosts) : self::mainHost($requests);
        $hosts = array_merge($hosts, array_keys($base->sites));
        $seen = [];
        $static = 0;
        $foreign = 0;
        foreach ($requests as $r) {
            $host = strtolower((string) parse_url($r['url'], PHP_URL_HOST));
            if ($host !== '' && $hosts !== [] && !self::named($host, $hosts)) {
                $foreign++;                     // another website's: a CDN, a font, an analytics script
                continue;
            }
            $path = (string) parse_url($r['url'], PHP_URL_PATH);
            if (!$all && preg_match(self::STATIC, $path) === 1) {
                $static++;
                continue;
            }
            $from = $ip ?? $r['from'] ?? RuleFile::EXAMPLE_FROM;
            $key = $r['method'] . ' ' . $r['url'] . ' ' . $from . ' ' . json_encode($r['headers']);
            if (isset($seen[$key])) {
                $seen[$key]['count']++;
                $seen[$key]['found'] = $seen[$key]['found'] && ($r['found'] ?? false);     // clicked once: clicked
                continue;
            }
            $seen[$key] = ['r' => $r, 'from' => $from, 'count' => 1, 'host' => $host, 'found' => $r['found'] ?? false];
        }
        $results = [];
        foreach ($seen as $x) {
            $r = $x['r'];
            $s = $settingsFor($x['host']);
            $ex = ['method' => $r['method'], 'url' => $r['url'], 'outcome' => 'answered', 'by' => null, 'rule' => null, 'from' => $x['from'], 'pass' => false, 'times' => 1,
                'headers' => array_diff_key($r['headers'], ['user-agent' => 1]), 'text' => null, 'at' => 'replay', 'site' => null, 'ua' => $r['headers']['user-agent'] ?? null, 'demo' => null];
            $d = Examples::one($s, $ex);
            $kind = in_array($d['got'], ['passes', 'uncached'], true) ? 'pass' : ($d['got'] === 'check' || $d['got'] === 'json-check' ? 'check' : 'refused');
            $results[] = ['method' => $r['method'], 'url' => $r['url'], 'count' => $x['count'], 'got' => $d['got'], 'rule' => $d['gotRule'], 'http' => $d['http'], 'kind' => $kind, 'found' => $x['found']];
        }
        return ['results' => $results, 'total' => count($requests), 'static' => $static, 'foreign' => $foreign];
    }

    /**
     * Without host rules: the host most of the recording asked, taken for the site's.
     *
     * @param list<Recorded> $requests
     * @return list<string>
     */
    private static function mainHost(array $requests): array
    {
        $count = [];
        foreach ($requests as $r) {
            $h = strtolower((string) parse_url($r['url'], PHP_URL_HOST));
            if ($h !== '') {
                $count[$h] = ($count[$h] ?? 0) + 1;
            }
        }
        arsort($count);
        return $count === [] ? [] : [(string) array_key_first($count)];
    }

    /** @param list<string> $names names and "*.domain" */
    private static function named(string $host, array $names): bool
    {
        foreach ($names as $n) {
            if ($n === $host || (strncmp($n, '*.', 2) === 0 && substr($host, -strlen($n) + 1) === substr($n, 1))) {
                return true;
            }
        }
        return false;
    }
}
