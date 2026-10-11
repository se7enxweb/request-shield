<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Cache\CacheExtension;
use CjwNetwork\RequestShield\Cache\CachePlugin;
use CjwNetwork\RequestShield\Cache\FileCache;
use CjwNetwork\RequestShield\Cache\MemoryCache;
use CjwNetwork\RequestShield\Cache\Tags;
use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Http;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Rules\RuleFile;
use CjwNetwork\RequestShield\Settings;

/**
 * The HTTP cache as a plugin (0031 G.2, RSF04-03): public answers of the
 * addresses a cache may keep, answered before the application -- never a
 * page that may be someone's own; nothing at all without set http-cache on.
 */

function cacheDir(): string
{
    $dir = sys_get_temp_dir() . '/rs-cache-' . getmypid() . '-' . mt_rand();
    mkdir($dir);
    return $dir;
}

function cacheSettings(string $dir, string $rules): Settings
{
    file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\n$rules");
    return Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
}

function cacheReq(string $uri, array $headers = [], string $method = 'GET'): Request
{
    $server = ['REQUEST_URI' => $uri, 'REQUEST_METHOD' => $method, 'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => '198.51.100.7', 'HTTPS' => 'on'];
    foreach ($headers as $k => $v) {
        $server['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
    }
    return Request::fromServer($server);
}

return [
    'RSF04-03 one answer, one spelling: a redirect to another spelling of its own address is never kept; a purge by address reaches every spelling; a # sent, a whole URL as target or X-Original-URL is never kept' => function (): void {
        $dir = cacheDir();
        try {
            $s = cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\nset http-cache-memory-object 0\n");
            $p = new CachePlugin($s);
            $c = new FileCache("$dir/store/http-cache");
            $h = ['Content-Type: text/html', 'Cache-Control: public, max-age=600'];
            foreach (['/hello/?' => '/hello/', '/hello//' => '/hello/', '/h%65llo/' => '/hello/', '/hello/?b=1&a=2' => 'https://www.example.org/hello/?a=2&b=1'] as $from => $to) {
                truthy(!$p->keep($c, cacheReq($from)->cacheKey(), 301, [...$h, "Location: $to"], ''), "$from -> $to: a redirect to itself, not kept");
            }
            foreach (['/p?b=1&a=2' => '?a=2&b=1', '/dir/p' => 'p', '/dir/q' => './q', '/r' => '//www.example.org/r', '/s' => '/s?sid=1', '/t' => 'https://www.example.org/t?x=1'] as $from => $to) {
                truthy(!$p->keep($c, cacheReq($from)->cacheKey(), 302, [...$h, "Location: $to"], ''), "$from -> $to: may come back here, not kept");
            }
            truthy($p->keep($c, cacheReq('/old')->cacheKey(), 301, [...$h, 'Location: /new'], ''), 'a redirect to another address is kept');
            truthy($p->keep($c, cacheReq('/u')->cacheKey(), 301, [...$h, 'Location: https://example.org/u'], ''), 'to another host: kept');
            truthy($p->keep($c, Request::fromServer(['REQUEST_URI' => '/v', 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'www.example.org'])->cacheKey(), 301, [...$h, 'Location: https://www.example.org/v'], ''), 'http to https: kept');
            same(CachePlugin::address('/news/item?a=1&b=2'), CachePlugin::address('/n%65ws//item?b=2&a=1'), 'one address for every spelling of a path');
            same(CachePlugin::address('/caf%C3%A9'), CachePlugin::address('/caf%c3%a9'), 'hex in either case');
            foreach (['/hello/#x' => [], '/x' => ['X-Original-URL' => '/admin'], '/y' => ['X-Rewrite-URL' => '/admin']] as $uri => $headers) {
                $r = cacheReq($uri, $headers);
                truthy($p->keep($c, $r->cacheKey(), 200, $h, 'page') && $p->handle($r, Decision::allow()) === null, "$uri " . json_encode($headers) . ': never answered from the cache');
            }
            $abs = Request::fromServer(['REQUEST_URI' => 'http://evil.example/x', 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => '198.51.100.7', 'HTTPS' => 'on']);
            $c->put($abs->cacheKey(), 200, $h, 'abs', 60, microtime(true));
            same(null, $p->handle($abs, Decision::allow()), 'a whole URL as the target: not answered from the cache');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 without set http-cache on there is no cache: no plugin, no handler -- a request pays nothing' => function (): void {
        $dir = cacheDir();
        try {
            $off = cacheSettings($dir, '');
            truthy(!in_array(CachePlugin::class, $off->plugins, true) && ($off->hooks['handler'] ?? []) === [], 'off: nothing to ask');
            $on = cacheSettings($dir, "set http-cache on\n");
            truthy(in_array(CachePlugin::class, $on->plugins, true) && in_array(CachePlugin::class, $on->hooks['handler'] ?? [], true), 'on: the plugin, as a handler');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 what is kept: 200, 301, 308, public, no cookie set, no Vary but encoding, within its size -- for its own max-age, else the ttl; expired is gone; purge by path' => function (): void {
        $dir = cacheDir();
        try {
            $s = cacheSettings($dir, "set http-cache on\nset http-cache-ttl 2m\nset http-cache-max-object 1K\nset http-cache-memory-object 0\n");     // the disk; memory: its own test
            $p = new CachePlugin($s);
            $c = new FileCache("$dir/c");
            $ok = ['Content-Type: text/html', 'X-RS: allow', 'Set-Cookie-Not: x'];
            truthy($p->keep($c, 'https://www.example.org/a', 200, $ok, 'A'), 'a plain page');
            foreach ([[404, $ok, 'B', '404'], [200, [...$ok, 'Set-Cookie: s=1'], 'B', 'a cookie set'], [200, [...$ok, 'Cache-Control: private'], 'B', 'private'],
                [200, [...$ok, 'Cache-Control: no-store'], 'B', 'no-store'], [200, [...$ok, 'Vary: Cookie'], 'B', 'Vary: Cookie'], [200, $ok, str_repeat('x', 1025), 'too large'],
                [200, [...$ok, 'Cache-Control: max-age=0'], 'B', 'max-age=0'], [200, [...$ok, 'Vary: Accept-Encoding', 'Vary: Cookie'], 'B', 'a second Vary line'],
                [200, [...$ok, 'Cache-Control: public', 'Cache-Control: private'], 'B', 'a second Cache-Control line'], [200, [...$ok, 'Content-Encoding: gzip'], 'B', 'gzip the application made'],
                [200, [...$ok, 'Pragma: no-cache'], 'B', 'Pragma: no-cache'], [200, [...$ok, 'Expires: Thu, 01 Jan 1970 00:00:00 GMT'], 'B', 'an Expires gone by'],
                [200, [...$ok, "Content-Disposition: attachment; filename=\"\xe4.txt\""], 'B', 'a header that is no UTF-8'],
                [200, [...$ok, 'X-Exp-Cache: MISS (stored)'], 'B', 'the site\'s own HTTP cache keeps it (Exponential 6): never two caches in a row']] as [$status, $h, $body, $why]) {
                truthy(!$p->keep($c, 'https://www.example.org/b', $status, $h, $body), "not kept: $why");
            }
            truthy($p->keep($c, 'https://www.example.org/v', 200, [...$ok, 'Vary: Accept-Encoding', 'Cache-Control: public, s-maxage=10, max-age=99'], 'V'), 'Vary on encoding only');
            $none = new CachePlugin(cacheSettings($dir, "set http-cache on\nset http-cache-ttl 0\n"));
            $shared = new ReflectionProperty(CachePlugin::class, 'shared');
            $shared->setAccessible(true);                                 // PHP 8.0
            $shared->setValue($none, true);
            truthy(!$none->keep($c, 'https://www.example.org/r', 200, [...$ok, 'Cache-Control: private'], 'R', '/r', null, true),
                'a role\'s page called shared, http-cache-ttl 0 and no max-age: nothing to keep it for');
            $a = $c->get('https://www.example.org/a', microtime(true));
            same(['A', ['Content-Type: text/html', 'Set-Cookie-Not: x']], [$a['body'] ?? null, $a['headers'] ?? null], 'the headers of one answer dropped (X-RS)');
            same(120, ($a['expires'] ?? 0) - ($a['stored'] ?? 0), 'the ttl when the answer says nothing');
            $v = $c->get('https://www.example.org/v', microtime(true));
            same(10, ($v['expires'] ?? 0) - ($v['stored'] ?? 0), 's-maxage first');
            same(null, $c->get('https://www.example.org/v', microtime(true) + 11), 'expired: gone');
            $c->put('https://www.example.org/news/1', 200, [], 'n', 60, microtime(true));
            $c->put('https://www.example.org/shop/1', 200, [], 's', 60, microtime(true));
            $c->put('https://www.example.org/news%3Fx', 200, [], 'q', 60, microtime(true), '/news%3Fx');
            same(2, $c->purge('/news'), 'purge below a path, by the path kept with the answer');
            same(2, $c->stats()['entries'], 'a and shop/1 are left (v expired above)');
            same(1, $c->purge(null, microtime(true) + 90), 'expired: what has run out (shop/1, 60 s; a has 120 s)');
            same(1, $c->stats()['entries'], 'a is left');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 the handler answers a kept page before the application, with Age and its ETag -- never a request with a session, a token, a form, or one the rules made uncacheable' => function (): void {
        $dir = cacheDir();
        try {
            $s = cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\n");
            $p = new CachePlugin($s);
            $c = new FileCache("$dir/store/http-cache");
            $c->put(cacheReq('/a')->cacheKey(), 200, ['Content-Type: text/html', 'ETag: "e1"'], 'kept', 60, microtime(true) - 5);
            $r = $p->handle(cacheReq('/a'), Decision::allow());
            truthy($r !== null && $r->body === 'kept' && in_array('X-RS-Cache: hit', $r->headers, true) && preg_grep('/^Age: [5-9]$/', $r->headers) !== [], 'a hit: ' . json_encode($r));
            same(304, $p->handle(cacheReq('/a', ['If-None-Match' => '"e1"']), Decision::allow())->status ?? 0, 'its ETag: 304');
            same('', $p->handle(cacheReq('/a', [], 'HEAD'), Decision::allow())->body ?? 'x', 'HEAD: no body');
            same(null, $p->handle(cacheReq('/a', ['Cookie' => 'session=1']), Decision::allow()), 'a session cookie: the page may be someone\'s own');
            truthy($p->handle(cacheReq('/a', ['Cookie' => '_ga=GA1.2; rsp=2.x']), Decision::allow()) !== null, 'analytics and the pass: harmless');
            same(null, $p->handle(cacheReq('/a', ['Authorization' => 'Bearer x']), Decision::allow()), 'a token');
            same(null, $p->handle(cacheReq('/a', [], 'POST'), Decision::allow()), 'a form');
            same(null, $p->handle(cacheReq('/a'), Decision::allowUncached('query parameter')), 'the rules said: not for a cache');
            same(null, $p->handle(cacheReq('/a', ['Host' => 'www.example.org:1337']), Decision::allow()), 'a port the list does not name: links built from it must not be kept');
            same(null, $p->handle(cacheReq('/a', ['Host' => 'made.up.example']), Decision::allow()), 'a made-up name');
            same(null, (new CachePlugin(cacheSettings($dir, "set http-cache on\n")))->handle(cacheReq('/a'), Decision::allow()), 'no http-cache-hosts: nothing');
            same(null, $p->handle(cacheReq('/a?x=1&x=2'), Decision::allow()), 'a parameter twice: PHP takes the last, the key sorts');
            same(null, $p->handle(cacheReq('/a%2Fb'), Decision::allow()), 'an encoded / in the path');
            $c->put(cacheReq('/r')->cacheKey(), 301, ['Location: /x', 'ETag: "e2"'], '', 60, microtime(true));
            same(301, $p->handle(cacheReq('/r', ['If-None-Match' => '"e2"']), Decision::allow())->status ?? 0, 'a kept redirect stays a redirect, ETag or not');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 end to end: the second request is answered from the cache and the site does not run; a made-up parameter, a session and a page that sets a cookie never are; purge empties it' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        $dir = cacheDir();
        mkdir("$dir/docroot");
        file_put_contents("$dir/docroot/index.php", '<?php
            file_put_contents(__DIR__ . "/../runs", "x", FILE_APPEND);
            if (strpos($_SERVER["REQUEST_URI"], "/account") !== false) { setcookie("session", "1"); }
            header("Cache-Control: public, max-age=60");
            if (strpos($_SERVER["REQUEST_URI"], "/clean") !== false) { echo "junk"; ob_clean(); echo "real " . hrtime(true); return; }
            if (strpos($_SERVER["REQUEST_URI"], "/cut") !== false) { echo "part "; while (ob_get_level() > 0) { ob_end_flush(); } echo "rest " . hrtime(true); return; }
            if (strpos($_SERVER["REQUEST_URI"], "/big") !== false) { for ($i = 0; $i < 40; $i++) { echo str_repeat("x", 65536); flush(); } echo hrtime(true); return; }
            header("Cache-Control: public, max-age=60");
            echo "page " . $_SERVER["REQUEST_URI"] . " " . hrtime(true);');
        file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nset http-cache on\ncache-query page\nset http-cache-memory-object 0\n");     // php -S has APCu: the disk here, memory in its own test
        $port = freePort();
        file_put_contents("$dir/site.rules", "set http-cache-hosts 127.0.0.1:$port\n", FILE_APPEND);
        $proc = proc_open(sprintf('REQUEST_SHIELD_CONFIG=%s exec %s -d auto_prepend_file=%s -S 127.0.0.1:%d -t %s > /dev/null 2>&1',
            escapeshellarg("$dir/site.rules"), serverPhp(), escapeshellarg(rsEntry()), $port, escapeshellarg("$dir/docroot")), [], $pipes);
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
            usleep(100000);
        }
        try {
            $get = static function (string $uri, array $headers = []) use ($port): array {
                $h = '';
                foreach ($headers as $k => $v) {
                    $h .= "$k: $v\r\n";
                }
                $out = (string) @file_get_contents("http://127.0.0.1:$port$uri", false, stream_context_create(['http' => ['header' => $h, 'ignore_errors' => true, 'timeout' => 10]]));
                return [implode("\n", $http_response_header ?? []), $out];
            };
            $runs = static fn (): int => strlen((string) @file_get_contents("$dir/runs"));
            [$h1, $b1] = $get('/index.php?page=2');
            [$h2, $b2] = $get('/index.php?page=2');
            truthy(strpos($h1, 'X-RS-Cache: miss') !== false && strpos($h2, 'X-RS-Cache: hit') !== false && $b1 === $b2 && $runs() === 1, "the site ran once: $h2 / " . $runs());
            [$h3, $b3] = $get('/index.php?made=up');
            [, $b4] = $get('/index.php?made=up');
            truthy(strpos($h3, 'X-RS-Cache') === false && $b3 !== $b4, 'a made-up parameter: never kept');
            [, $b5] = $get('/index.php?page=2', ['Cookie' => 'session=abc']);
            truthy($b5 !== $b1, 'with a session: the site\'s own answer');
            $get('/index.php/account');
            [$h6] = $get('/index.php/account');
            truthy(strpos($h6, 'X-RS-Cache: hit') === false, 'a page that sets a cookie: never kept');
            [, $c1] = $get('/index.php/clean');
            [$c2h, $c2] = $get('/index.php/clean');
            truthy(strpos($c1, 'junk') === false && strpos($c2h, 'X-RS-Cache: hit') === false && $c1 !== $c2, "what ob_clean() threw away: never kept, nor is the answer ($c2h)");
            $get('/index.php/cut');
            [$k2h, $k2] = $get('/index.php/cut');
            truthy(strpos($k2h, 'X-RS-Cache: hit') === false && strpos($k2, 'part rest') === 0, "an answer ended before the script: never kept ($k2h)");
            $get('/index.php/big');
            [$g2h, $g2] = $get('/index.php/big');
            truthy(strpos($g2h, 'X-RS-Cache: hit') === false && strlen($g2) > 40 * 65536, 'larger than http-cache-max-object: never kept, and sent whole');
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli()) . ' cache ' . escapeshellarg("$dir/site.rules") . ' purge 2>&1', $out, $code);
            truthy($code === 0 && strpos(implode("\n", $out), 'removed') === 0, implode("\n", $out));
            [$h7] = $get('/index.php?page=2');
            truthy(strpos($h7, 'X-RS-Cache: miss') !== false, 'after purge: asked again');
        } finally {
            proc_terminate($proc);
            proc_close($proc);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 the purge times (0039): files, with APCu a copy for Tags::MEMORY seconds -- a purge from another process (the command line) counts once it has run out' => function (): void {
        $dir = cacheDir();
        try {
            $file = new Tags($dir, false);
            same(0.0, $file->newest(['a', 'b']), 'nothing purged');
            truthy($file->purge(['a'], 1000.5) && $file->newest(['a', 'b']) === 1000.5 && $file->newest(['b']) === 0.0, 'one tag');
            $file->purge([Tags::ALL], 2000.25);
            same(2000.25, $file->newest(['b']), 'everything: every tag');
            truthy(!$file->purgedSince(['b'], 2000.5) && $file->purgedSince(['b'], 2000.25) && $file->purgedSince(['a'], 1000.0), 'purged since: at or after the time');
            // An answer made after the last purge of anything reads no tag: a tag's time written
            // past the last purge (no purge() does that) is not seen.
            $h = md5('x');
            @mkdir("$dir/tags/" . substr($h, 0, 2), 0750, true);
            file_put_contents("$dir/tags/" . substr($h, 0, 2) . "/$h", '9999.0');
            truthy(!$file->purgedSince(['x'], 2500.0) && $file->newest(['x']) === 9999.0, 'nothing purged since: one read, no tag read');
            if (\CjwNetwork\RequestShield\Capability::apcu()) {
                $mem = new Tags($dir, true);
                same(2000.25, $mem->newest(['a']), 'APCu: read from the files the first time');
                $file->purge(['a'], 3000.0);
                same(2000.25, $mem->newest(['a']), 'a purge only in the files: the copy lags ...');
                apcu_delete(new \APCUIterator('/^rshield:hc:/'));
                same(3000.0, $mem->newest(['a']), '... until it runs out (or is dropped)');
                $mem->purge(['c'], 4000.0);
                same([4000.0, 4000.0], [$mem->newest(['c']), $file->newest(['c'])], 'a purge through APCu writes the file too');
                // A purge whose file cannot be written (a file where its folder should be): said to
                // have failed, and not kept in APCu either -- it must not count for a while and lapse.
                $h = md5('t');
                file_put_contents("$dir/tags/" . substr($h, 0, 2), 'not a folder');
                truthy(!$mem->purge(['t'], 5000.0), 'a purge that cannot be written: false');
                truthy($mem->newest(['t']) < 5000.0, '... and not in memory');
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 tags (0039): kept with the answer, taken out of what is kept; a purge of one of them, of its address or of everything makes it out of date' => function (): void {
        foreach ([\CjwNetwork\RequestShield\Capability::apcu()] as $apcu) {      // as the plugin finds it; the other way: Tags' own test
            $dir = cacheDir();
            try {
                $s = cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\nset http-cache-tag-headers X-My-Tags\nset http-cache-memory-object 0\n");
                $p = new CachePlugin($s);
                $c = new FileCache("$dir/store/http-cache");
                $tags = new Tags("$dir/store/http-cache", $apcu);
                $born = microtime(true) - 1;
                $h = ['Content-Type: text/html', 'xkey: content-52 location-2 ez-all', 'X-Cache-Tags: c1,c2', 'X-My-Tags: mine', 'X-LiteSpeed-Tag: public:ls1', 'Surrogate-Key: sk1', 'X-Location-Id: 7'];
                truthy($p->keep($c, cacheReq('/a?b=2&a=1')->cacheKey(), 200, $h, 'A', '/a', $born), 'kept');
                $a = $c->get(cacheReq('/a?b=2&a=1')->cacheKey(), microtime(true));
                same(['Content-Type: text/html'], $a['headers'] ?? null, 'no tag header is kept: they name content');
                same(['content-52', 'location-2', 'ez-all', 'c1', 'c2', 'ls1', 'sk1', 'mine', 'location-7', 'rs-url:/a?a=1&b=2'], $a['tags'] ?? null, 'the tags, LiteSpeed\'s public: off, the address');
                truthy($tags->newest($a['tags'] ?? []) < ($a['born'] ?? 0), 'nothing purged yet');
                $tags->purge(['other'], microtime(true));
                truthy($tags->newest($a['tags'] ?? []) < ($a['born'] ?? 0), 'another tag: still good');
                truthy($p->handle(cacheReq('/a?a=1&b=2'), Decision::allow()) !== null, 'a hit');
                foreach ([['location-7'], ['rs-url:' . CachePlugin::address('/a?b=2&a=1')], [Tags::ALL]] as $purged) {
                    $c->put(cacheReq('/a?a=1&b=2')->cacheKey(), 200, [], 'A', 60, microtime(true), '/a', $a['tags'] ?? [], microtime(true));
                    truthy($p->handle(cacheReq('/a?a=1&b=2'), Decision::allow()) !== null, 'kept again: a hit');
                    usleep(1000);
                    $tags->purge($purged, microtime(true));
                    $stale = (new CachePlugin($s))->handle(cacheReq('/a?a=1&b=2'), Decision::allow());
                    same(null, $stale, 'purged ' . implode(' ', $purged) . ': out of date' . ($apcu ? ' (APCu)' : ''));
                }
                $t2 = new Tags("$dir/store/http-cache", $apcu);
                truthy($t2->newest(['zzz']) > 0.0, 'everything was purged: any tag is out of date for older answers');
                // What is not kept.
                foreach ([[[...$h, 'Surrogate-Control: content="ESI/1.0"'], 'ESI'], [['X-LiteSpeed-Tag: private:u1'], 'a LiteSpeed private: tag'],
                    [['xkey: ' . implode(' ', range(1, 501))], 'more than 500 tags']] as [$hh, $why]) {
                    truthy(!$p->keep($c, cacheReq('/n')->cacheKey(), 200, $hh, 'N'), "not kept: $why");
                }
            } finally {
                exec('rm -rf ' . escapeshellarg($dir));
            }
        }
    },
    'RSF04-03 purges as requests (0039): Exponential Platform\'s, Ibexa\'s and FOSHttpCache\'s dialects, only from http-cache-purgers or with the token -- anyone else meets the rules (null)' => function (): void {
        $dir = cacheDir();
        try {
            $s = cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\nset http-cache-purge-token s3cret-token-0123456789\n");
            truthy(in_array(CachePlugin::class, $s->hooks['methodHandler'] ?? [], true), 'the plugin answers methods the site does not take');
            $local = static fn (string $uri, array $h, string $m = 'PURGE'): Request => Request::fromServer(['REQUEST_URI' => $uri, 'REQUEST_METHOD' => $m,
                'HTTP_HOST' => '127.0.0.1', 'REMOTE_ADDR' => '127.0.0.1'] + array_combine(array_map(static fn ($k) => 'HTTP_' . strtoupper(str_replace('-', '_', $k)), array_keys($h)), array_values($h)));
            foreach ([
                [['/', ['key' => 'content-52 location-2']], ['content-52', 'location-2'], 'Exponential: PURGE + key'],
                [['/', ['key' => 'ez-all']], ['ez-all'], 'Exponential: key: ez-all (every page carries it)'],
                [['/', ['X-Location-Id' => '*']], [Tags::ALL], 'Exponential\'s older call: everything'],
                [['/', ['X-Location-Id' => '(1|22|3)']], ['location-1', 'location-22', 'location-3'], 'Exponential\'s older call: locations'],
                [['/', ['X-Location-Id' => '12']], ['location-12'], 'one location'],
                [['/', ['X-Cache-Tags' => 'c1,c2']], ['c1', 'c2'], 'FOSHttpCache / Ibexa local: X-Cache-Tags'],
                [['/', ['xkey-purge' => 'c1 l2'], 'PURGEKEYS'], ['c1', 'l2'], 'Ibexa with Varnish: PURGEKEYS + xkey-purge'],
                [['/', ['xkey-softpurge' => 'c9'], 'PURGEKEYS'], ['c9'], 'xkey-softpurge: a purge, for now'],
                [['/news/?b=1&a=2', []], ['rs-url:/news/?a=2&b=1'], 'PURGE <address>: its address, the query sorted'],
                [['/', ['X-Location-Id' => 'drop table']], null, 'nothing that can be purged'],
                [['/', [], 'PURGEKEYS'], null, 'PURGEKEYS without keys'],
            ] as [$args, $want, $why]) {
                same($want, CachePlugin::purgeOf($local(...$args)), $why);
            }
            same(null, (new CachePlugin($s))->handleMethod($local('/', ['key' => 'c1'])), 'by default nobody purges by address: not even this machine (a local proxy makes every visitor 127.0.0.1)');
            $s = cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\nset http-cache-purge-token s3cret-token-0123456789\nset http-cache-purgers 127.0.0.1 ::1\n");
            $p = new CachePlugin($s);
            same(200, $p->handleMethod($local('/', ['key' => 'c1']))->status ?? 0, 'from this machine, named: purged');
            same(null, $p->handleMethod(cacheReq('/', ['key' => 'c1'], 'PURGE')), 'from anywhere else: the rules decide (405)');
            same(null, $p->handleMethod($local('/', ['key' => 'c1', 'X-Forwarded-For' => '203.0.113.9'])), 'through a proxy the shield does not trust: not this machine');
            same(200, $p->handleMethod(cacheReq('/', ['key' => 'c1', 'X-Invalidate-Token' => 's3cret-token-0123456789'], 'PURGE'))->status ?? 0, 'with the token: purged');
            same(null, $p->handleMethod(cacheReq('/', ['key' => 'c1', 'X-Invalidate-Token' => 's3cret-token-012345678x'], 'PURGE')), 'a wrong token');
            same(null, $p->handleMethod($local('/', [], 'BAN')), 'BAN: not taken (patterns need an index)');
            same(400, $p->handleMethod($local('/', [], 'PURGEKEYS'))->status ?? 0, 'a purger\'s request that names nothing: 400');
            $p->purgeFromAnswer('public, tag=public:c7, /x?b=1&a=1');
            $t = new Tags("$dir/store/http-cache", \CjwNetwork\RequestShield\Capability::apcu());
            truthy($t->newest(['c7']) > 0.0 && $t->newest(['rs-url:/x?a=1&b=1']) > 0.0 && $t->newest(['c1']) > 0.0 && $t->newest(['c8']) === 0.0, 'X-LiteSpeed-Purge in an answer: tags and addresses');
            $p->purgeFromAnswer('private, *');
            same(0.0, $t->newest(['c8']), 'private, *: a browser\'s cache, not this one');
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli()) . ' cache ' . escapeshellarg("$dir/site.rules") . ' purge --tag=c8,c9 2>&1', $out, $code);
            truthy($code === 0 && (new Tags("$dir/store/http-cache", false))->newest(['c9']) > 0.0, 'the command line: purge --tag= ' . implode("\n", $out));
            same(['removed' => 0], \CjwNetwork\RequestShield\Cache\Api\Purge::handle($s, ['tags' => 'c10'], []), 'the API: tags');
            truthy((new Tags("$dir/store/http-cache", false))->newest(['c10']) > 0.0, '... purged');
            foreach (["set http-cache-purge-token short\n" => 'a short token', "set http-cache-purgers localhost\n" => 'a name, not an address'] as $bad => $why) {
                try {
                    cacheSettings($dir, "set http-cache on\n$bad");
                    throw new TestFailure("accepted: $why");
                } catch (\InvalidArgumentException $e) {
                    truthy(strpos($e->getMessage(), 'short') === false || $why !== 'a short token', 'the token is never in the message');
                }
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 roles (0039): a harmless cookie is never a session cookie -- the session\'s MAC is the same with or without it' => function (): void {
        if (!\CjwNetwork\RequestShield\Capability::apcu()) {
            skip('APCu not enabled (php -d apc.enable_cli=1): roles need it');
        }
        $dir = cacheDir();
        try {
            $p = new CachePlugin(cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\nset http-cache-session-cookie sess*\nset http-cache-cookies sess_ga*\n"));
            $of = new \ReflectionMethod($p, 'sessionOf');
            $of->setAccessible(true);
            $alone = $of->invoke($p, cacheReq('/', ['Cookie' => 'sess=abc']));
            truthy(is_string($alone), 'a session cookie: a MAC');
            same($alone, $of->invoke($p, cacheReq('/', ['Cookie' => 'sess=abc; sess_ga=1'])), 'a cookie that is harmless and looks like a session: not part of it');
            same(null, $of->invoke($p, cacheReq('/', ['Cookie' => 'sess_ga=1'])), 'only a harmless one: no session');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 end to end, a page per role (0039): the application names the role (cacheContext), the next request with that session cookie gets the role\'s page -- not another role\'s, not with a forged cookie, not after logout or a purge of rs-context; only pages called shared' => function (): void {
        $fpm = fpmBinary();
        if (!function_exists('proc_open') || $fpm === null) {
            skip('no PHP-FPM here (TESTS_PHP_FPM)');
        }
        $dir = cacheDir();
        mkdir("$dir/docroot");
        // An adapter in a few lines: the role from the login cookie (here its first letters), told to the shield.
        file_put_contents("$dir/docroot/index.php", '<?php
            file_put_contents(__DIR__ . "/../runs", "x", FILE_APPEND);
            $shield = \CjwNetwork\RequestShield\Shield::active();
            $login = $_COOKIE["wordpress_logged_in_abc"] ?? null;
            if (isset($_GET["logout"])) { $shield?->forgetContext(); echo "bye"; return; }
            $role = $login === null ? "anonymous" : (strncmp($login, "ed", 2) === 0 ? "editor" : "author");
            if ($login !== null && !isset($_GET["silent"])) { $shield?->cacheContext($role, !isset($_GET["own"])); }
            if (isset($_GET["fos"])) { header("Vary: X-User-Hash"); }
            header("Cache-Control: public, s-maxage=600");
            echo "page for $role " . hrtime(true);');
        file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nset http-cache on\ncache-query own logout silent fos\nset http-cache-hosts www.example.org\n"
            . "set http-cache-session-cookie wordpress_logged_in_*\nset http-cache-purgers 127.0.0.1 ::1\n");
        $port = freePort();
        $proc = startFpm($fpm, $dir, $port);
        try {
            $send = static function (string $method, string $uri, array $headers = []) use ($port, $dir): array {
                $params = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri, 'QUERY_STRING' => (string) parse_url($uri, PHP_URL_QUERY),
                    'SCRIPT_FILENAME' => "$dir/docroot/index.php", 'SCRIPT_NAME' => '/index.php', 'DOCUMENT_ROOT' => "$dir/docroot", 'SERVER_PROTOCOL' => 'HTTP/1.1',
                    'SERVER_NAME' => 'www.example.org', 'SERVER_PORT' => '80', 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_HOST' => 'www.example.org',
                    'REQUEST_SHIELD_CONFIG' => "$dir/site.rules", 'PHP_VALUE' => 'auto_prepend_file=' . rsEntry()];
                foreach ($headers as $k => $v) {
                    $params['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
                }
                return fcgi($port, $params);
            };
            $as = static fn (string $login, string $uri = '/index.php'): array => $send('GET', $uri, ['Cookie' => "wordpress_logged_in_abc=$login; _ga=1"]);
            $hit = static fn (array $r): bool => strpos($r[1], 'X-RS-Cache: hit') !== false;
            [, , $anon] = $send('GET', '/index.php');
            $r = $send('GET', '/index.php');
            truthy($hit($r) && $r[2] === $anon, 'anonymous: kept as before');
            if (!serverApcu()) {
                // Without APCu roles stay off (0039): a session's page is the visitor's own -- the
                // application makes it every time, nothing is kept for it, anonymous visitors keep theirs.
                $runs = strlen((string) file_get_contents("$dir/runs"));
                $first = $as('ed-1');
                $again = $as('ed-1');
                truthy(!$hit($first) && !$hit($again) && strpos($again[2], 'page for editor') === 0 && $again[2] !== $first[2]
                    && strlen((string) file_get_contents("$dir/runs")) === $runs + 2, 'no APCu: a session\'s page from the application, each time -- ' . $again[1]);
                truthy(stripos($first[1], 'X-RS-Cache: miss') === false, 'no APCu: nothing kept for a session (no miss that a later request could hit) -- ' . $first[1]);
                $r = $send('GET', '/index.php');
                truthy($hit($r) && $r[2] === $anon, 'no APCu: anonymous visitors still get their kept page, never a session\'s');
                return;
            }
            if (strpos($as('ed-1')[1], 'X-RS-Cache: miss') === false) {
                throw new TestFailure('a session the shield does not know yet: the application runs');
            }
            $r = $as('ed-1');
            truthy($hit($r) && strpos($r[2], 'page for editor') === 0, 'the same session again: the editors\' page from the cache -- ' . $r[1]);
            truthy(stripos($r[1], 'Cache-Control: private, no-cache') !== false && stripos($r[1], 's-maxage') === false, 'a role\'s page leaves private: ' . $r[1]);
            $as('au-1');
            $r = $as('au-1');
            truthy($hit($r) && strpos($r[2], 'page for author') === 0, 'another role: its own page');
            $r = $send('GET', '/index.php');
            truthy($hit($r) && $r[2] === $anon, 'anonymous visitors never get a role\'s page');
            $r = $as('ed-forged');
            truthy(!$hit($r), 'a cookie the application never named a role for: the application runs');
            $as('ed-1', '/index.php?own=1');
            truthy(!$hit($as('ed-1', '/index.php?own=1')), 'a page the application did not call shared: not kept for the role');
            $runs = strlen((string) file_get_contents("$dir/runs"));
            $r = $send('GET', '/index.php', ['Cookie' => 'wordpress_logged_in_abc=ed-1; cart=3']);
            truthy(!$hit($r) && strlen((string) file_get_contents("$dir/runs")) === $runs + 1, 'a session and another cookie (a cart): the page may be the visitor\'s own');
            $as('ed-1', '/index.php?logout=1');
            truthy(!$hit($as('ed-1')), 'after logout (forgetContext) the session finds no role');
            truthy($hit($as('ed-1')), '... until the application names it again');
            truthy(!$hit($as('ed-1', '/index.php?silent=1&fos=1')) && !$hit($as('ed-1', '/index.php?silent=1&fos=1')),
                'a remembered role, but the application did not name it in this request (a session ended): not kept for the role');
            $as('ed-1');
            truthy($hit($as('ed-1')), 'the editors\' page is kept ...');
            same(200, $send('PURGE', '/index.php')[0], 'PURGE <address>');
            truthy(!$hit($as('ed-1')), '... and purged by its address like any page');
            $send('GET', '/index.php?fos=1');
            $r = $send('GET', '/index.php?fos=1');
            truthy($hit($r) && stripos($r[1], 'Vary: X-User-Hash') !== false, 'Vary on the role\'s hash: kept for anonymous visitors, and left in the answer for a cache in front: ' . $r[1]);
            $forged = $send('GET', '/index.php?fos=1', ['X-User-Hash' => 'editors-hash']);
            truthy(!$hit($forged) && !$hit($send('GET', '/index.php?fos=1', ['X-User-Hash' => 'editors-hash'])), 'a role\'s hash sent by the client: the application answers, nothing is kept or given from the cache');
            same(200, $send('PURGE', '/', ['key' => 'rs-context'])[0], 'PURGE + key: rs-context (roles changed)');
            truthy(!$hit($as('au-1')), 'the roles and the role\'s pages purged');
        } finally {
            proc_terminate($proc);
            proc_close($proc);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 memory (0039, http-cache-memory-object): a small answer in APCu, not on the disk; a larger one, or one that lives longer than an hour, on the disk; the share; a purge of the memory sends to the disk, and the disk\'s answer comes back' => function (): void {
        if (!\CjwNetwork\RequestShield\Capability::apcu()) {
            skip('no APCu (php -d apc.enable_cli=1)');
        }
        $dir = cacheDir();
        try {
            $s = cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\nset http-cache-memory-object 1K\nset http-cache-memory 2K\n");
            $p = new CachePlugin($s);
            $c = new FileCache("$dir/store/http-cache");
            $m = new MemoryCache("$dir/store/http-cache", 1024, 2048);
            $born = microtime(true) - 1;
            $key = static fn (string $path): string => cacheReq($path)->cacheKey();
            $ok = ['Content-Type: text/html', 'Cache-Control: public, max-age=600'];
            truthy($p->keep($c, $key('/s'), 200, $ok, 'small', '/s', $born), 'kept');
            truthy($m->get($key('/s'), microtime(true)) !== null && $c->get($key('/s'), microtime(true)) === null, 'a small answer: in memory, not on the disk');
            $r = $p->handle(cacheReq('/s'), Decision::allow());
            truthy($r !== null && $r->body === 'small' && in_array('X-RS-Cache: hit', $r->headers, true), 'answered from memory: ' . json_encode($r));
            truthy($p->keep($c, $key('/big'), 200, $ok, str_repeat('b', 2000), '/big', $born), 'kept');
            truthy($m->get($key('/big'), microtime(true)) === null && $c->get($key('/big'), microtime(true)) !== null, 'larger than http-cache-memory-object: on the disk');
            truthy($p->keep($c, $key('/long'), 200, ['Content-Type: text/html', 'Cache-Control: public, max-age=86400'], 'long', '/long', $born), 'kept');
            $inMemory = $m->get($key('/long'), microtime(true));
            truthy($inMemory !== null && $inMemory['expires'] - time() > 3600 && $c->get($key('/long'), microtime(true)) !== null,
                'a day: in memory (for an hour) and on the disk (for the rest)');
            // The share: with ~1 KB of others, a second answer of ~1 KB does not fit into 2K -- it goes to the disk.
            $p->keep($c, $key('/f1'), 200, $ok, str_repeat('x', 900), '/f1', $born);
            $p->keep($c, $key('/f2'), 200, $ok, str_repeat('x', 900), '/f2', $born);
            truthy($m->bytes(microtime(true)) <= 2048 && $m->get($key('/f2'), microtime(true)) === null && $c->get($key('/f2'), microtime(true)) !== null,
                'past http-cache-memory: the disk takes it (' . $m->bytes(microtime(true)) . ' bytes counted)');
            truthy(!$p->keep($c, $key('/u'), 200, ['Content-Type: text/html', "X-Name: \xff"], 'u', '/u', $born), 'a header that is no UTF-8: kept nowhere');
            // The command line's purge (a tag every answer in memory counts): memory out of date, the disk's answer is served -- and comes back to memory.
            usleep(10000);
            truthy(MemoryCache::forget("$dir/store/http-cache", true, microtime(true)), 'forget');
            same(null, $p->handle(cacheReq('/s'), Decision::allow()), 'memory purged: the small one is gone (it was only there)');
            $r = $p->handle(cacheReq('/long'), Decision::allow());
            truthy($r !== null && $r->body === 'long', 'the disk still has the long one');
            $back = $m->get($key('/long'), microtime(true));
            truthy($back !== null && $back['kept'] > $back['born'], 'and it is in memory again, counted from now: ' . json_encode($back));
            truthy((new CachePlugin($s))->handle(cacheReq('/long'), Decision::allow()) !== null, 'the next request: a hit');
            // http-cache-memory-object 0: no memory at all.
            $off = new CachePlugin(cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\nset http-cache-memory-object 0\n"));
            $off->keep($c, $key('/o'), 200, $ok, 'o', '/o', $born);
            truthy($m->get($key('/o'), microtime(true)) === null && $c->get($key('/o'), microtime(true)) !== null, 'memory off: the disk');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 the cache\'s sizes: a size too large for an integer, or a cap under 1M, is a mistake in the rule file; a rewritten answer counts once' => function (): void {
        $dir = cacheDir();
        try {
            $error = static function (string $line) use ($dir): string {
                try {
                    cacheSettings($dir, "set http-cache on\n$line\n");
                } catch (\Throwable $e) {
                    return get_class($e) . ': ' . $e->getMessage();
                }
                return 'accepted';
            };
            $huge = $error('set http-cache-memory 999999999999G');
            truthy(strpos($huge, 'RuleFileException') !== false && strpos($huge, 'http-cache-memory is a size') !== false, 'too large: ' . $huge);
            truthy($error('set http-cache-disk 100K') !== 'accepted', 'a cap under 1M: refused');
            same('accepted', $error('set http-cache-disk 0'), 'no cap');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 with APCu: a rewritten answer counts once against its folder\'s share; after APCu was short of room nothing goes into memory for a while' => function (): void {
        if (!\CjwNetwork\RequestShield\Capability::apcu()) {
            skip('no APCu (php -d apc.enable_cli=1)');
        }
        $dir = cacheDir();
        try {
            $c = new FileCache("$dir/c", 1048576 * 256, true);
            for ($i = 0; $i < 20; $i++) {
                $c->put('https://www.example.org/same', 200, [], str_repeat('x', 1000), 60, microtime(true));
            }
            $prefix = 'rshield:hc:' . substr(md5("$dir/c"), 0, 12) . ':';
            $count = apcu_fetch($prefix . 'd:' . substr(sha1('https://www.example.org/same'), 0, 2));
            truthy(is_int($count) && $count < 2000, 'one answer written twenty times: counted once (' . var_export($count, true) . ')');
            $m = new MemoryCache("$dir/c", 1024, 1048576);
            truthy($m->put('k1', 200, [], 'a', time(), time() + 60, microtime(true), [], microtime(true), microtime(true)), 'room: kept in memory');
            apcu_store($prefix . 'm:full', true, 10);       // as put() leaves it when APCu would keep less than a quarter free
            truthy(!$m->put('k2', 200, [], 'a', time(), time() + 60, microtime(true), [], microtime(true), microtime(true)) && $m->get('k2', microtime(true)) === null,
                'APCu short of room a moment ago: not kept in memory');
            truthy($m->bytes(microtime(true)) > 0 && $m->bytes(microtime(true)) < 1000, 'the mark is not counted as bytes');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 end to end, memory: under PHP-FPM a hit comes from APCu -- the folder on the disk gone, still a hit; a PURGE of its tag at once; a large answer on the disk' => function (): void {
        $fpm = fpmBinary();
        if (!function_exists('proc_open') || $fpm === null) {
            skip('no PHP-FPM here (TESTS_PHP_FPM)');
        }
        if (!extension_loaded('apcu')) {
            skip('no APCu');
        }
        $dir = cacheDir();
        mkdir("$dir/docroot");
        file_put_contents("$dir/docroot/index.php", '<?php
            file_put_contents(__DIR__ . "/../runs", "x", FILE_APPEND);
            header("Cache-Control: public, max-age=600");
            header("xkey: page-" . ($_GET["p"] ?? "0"));
            echo ($_GET["p"] ?? "") === "big" ? str_repeat("b", 300000) : "page " . hrtime(true);');
        file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nset http-cache on\ncache-query p\nset http-cache-hosts www.example.org\nset http-cache-purgers 127.0.0.1 ::1\n");
        $port = freePort();
        $proc = startFpm($fpm, $dir, $port);
        try {
            $send = static function (string $method, string $uri, array $headers = []) use ($port, $dir): array {
                $params = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri, 'QUERY_STRING' => (string) parse_url($uri, PHP_URL_QUERY),
                    'SCRIPT_FILENAME' => "$dir/docroot/index.php", 'SCRIPT_NAME' => '/index.php', 'DOCUMENT_ROOT' => "$dir/docroot", 'SERVER_PROTOCOL' => 'HTTP/1.1',
                    'SERVER_NAME' => 'www.example.org', 'SERVER_PORT' => '80', 'REMOTE_ADDR' => '127.0.0.1', 'HTTP_HOST' => 'www.example.org',
                    'REQUEST_SHIELD_CONFIG' => "$dir/site.rules", 'PHP_VALUE' => 'auto_prepend_file=' . rsEntry()];
                foreach ($headers as $k => $v) {
                    $params['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
                }
                return fcgi($port, $params);
            };
            $hit = static fn (array $r): bool => strpos($r[1], 'X-RS-Cache: hit') !== false;
            $send('GET', '/index.php?p=1');
            truthy($hit($send('GET', '/index.php?p=1')), 'the second request: a hit');
            exec('rm -rf ' . escapeshellarg("$dir/store/http-cache") . '/[0-9a-f][0-9a-f]');
            $r = $send('GET', '/index.php?p=1');
            truthy($hit($r) && strlen((string) @file_get_contents("$dir/runs")) === 1, 'the answers\' folders gone from the disk: still a hit, from memory -- ' . $r[1]);
            same(200, $send('PURGE', '/', ['key' => 'page-1'])[0], 'PURGE + key');
            truthy(!$hit($send('GET', '/index.php?p=1')), 'purged by its tag: at once, from memory too');
            $send('GET', '/index.php?p=big');
            truthy($hit($send('GET', '/index.php?p=big')) && glob("$dir/store/http-cache/*/*/*.cache") !== [], 'larger than http-cache-memory-object (256K): kept on the disk');
        } finally {
            proc_terminate($proc);
            proc_close($proc);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 the disk\'s cap (http-cache-disk): each folder holds a 256th of it -- past it the expired, then the oldest go; with APCu counted as written, without at the sweep' => function (): void {
        $dir = cacheDir();
        try {
            // Keys of one folder ("aa"): the cap is per folder.
            $keys = [];
            for ($i = 0; count($keys) < 8; $i++) {
                if (strncmp(sha1("https://www.example.org/p$i"), 'aa', 2) === 0) {
                    $keys[] = "https://www.example.org/p$i";
                }
            }
            $held = static function () use ($dir): int {
                $n = 0;
                foreach (glob("$dir/c/aa/*/*.cache") ?: [] as $f) {
                    $n += (int) filesize($f);
                }
                return $n;
            };
            $files = static fn (string $d): array => glob("$d/aa/*/*.cache") ?: [];
            foreach ([\CjwNetwork\RequestShield\Capability::apcu(), false] as $apcu) {
                exec('rm -rf ' . escapeshellarg("$dir/c"));
                $c = new FileCache("$dir/c", 256 * 1000, $apcu);       // 1000 bytes a folder
                $now = microtime(true);
                $base = time() - 100;
                foreach ($keys as $n => $k) {
                    truthy($c->put($k, 200, [], str_repeat('x', 300), 60, $now), 'written');
                    foreach ($files("$dir/c") as $f) {
                        touch($f, filemtime($f) ?: time());      // keep the older ones older
                    }
                    // Written one second after the one before, all in the past: the answer being
                    // written (its mtime now, when put() trims with APCu) is always the newest, as on
                    // a real site -- not older than the ones before or as old as the first when a
                    // second passes during the loop.
                    $file = "$dir/c/aa/" . substr(sha1($k), 2, 2) . '/' . sha1($k) . '.cache';
                    if (is_file($file)) {
                        touch($file, $base + $n);
                    }
                }
                if (!$apcu) {
                    $c->trim('aa', microtime(true));        // the sweep's turn (one store in a hundred)
                }
                truthy($held() <= 1000, ($apcu ? 'APCu' : 'no APCu') . ': the folder within its share: ' . $held() . ' bytes');
                truthy($c->get($keys[7], microtime(true)) !== null && $c->get($keys[0], microtime(true)) === null, 'the newest kept, the oldest gone');
            }
            // The command line: every folder.
            $c = new FileCache("$dir/c", 256 * 1000);
            foreach ($keys as $k) {
                $c->put($k, 200, [], str_repeat('x', 300), 60, microtime(true));
            }
            truthy($c->trimAll(microtime(true)) <= 256 * 1000 && $held() <= 1000, 'trimAll: within the cap');
            truthy((new FileCache("$dir/c"))->trim('aa', microtime(true)) === $held(), 'no cap: only measured');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 Purger (0031 G.5): the application purges tags in the same process -- the cache makes their answers out of date, "*" everything, a value split as the tag headers are, a piece no answer can carry left out; Shield::purge() asks only a plugin that has it' => function (): void {
        $dir = cacheDir();
        try {
            $s = cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\n");
            same([CachePlugin::class], $s->hooks['purger'] ?? null, 'the cache has the capability');
            same([], cacheSettings($dir, '')->hooks['purger'] ?? [], 'without the cache: no purger');
            $p = new CachePlugin($s);
            $tags = new Tags("$dir/store/http-cache", \CjwNetwork\RequestShield\Capability::apcu());
            $before = microtime(true) - 1;
            $p->purge(['content-5', "two\nparts", str_repeat('x', 201)]);
            truthy($tags->purgedSince(['content-5'], $before) && !$tags->purgedSince(['content-6'], $before), 'its tag purged, another not');
            truthy($tags->purgedSince(['two'], $before) && $tags->purgedSince(['parts'], $before), 'a value with a line break: split, as the tag headers are');
            truthy(!$tags->purgedSince([str_repeat('x', 201)], $before), 'a piece over 200 bytes: no tag, not purged');
            $p->purge(['*']);
            truthy($tags->purgedSince(['content-6'], $before), '"*": everything');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 the cache\'s page in the dashboard (0047\'s area "Cache"): a tab only while the cache is on, memory and disk against their caps, purges by tag, below a path, everything -- with the page\'s token only' => function (): void {
        $dir = cacheDir();
        try {
            $s = cacheSettings($dir, "set http-cache on\nset http-cache-hosts www.example.org\nset http-cache-memory-object 0\nset http-cache-disk 10M\n");
            $pages = static fn (\CjwNetwork\RequestShield\Settings $x): array => array_keys(array_filter($x->routes, static fn ($r): bool => is_array($r) && ($r['key'] ?? null) === 'cache'));
            same(['/rs/cache'], $pages($s), 'the route below dashboard-path');
            same([], $pages(cacheSettings($dir, '')), 'the cache off: no page');
            $p = new CachePlugin($s);
            $c = new FileCache("$dir/store/http-cache");
            $p->keep($c, 'https://www.example.org/news/a', 200, ['Cache-Control: max-age=60', 'xkey: c52'], 'A', '/news/a');
            $p->keep($c, 'https://www.example.org/about', 200, ['Cache-Control: max-age=60'], 'B', '/about');
            $html = \CjwNetwork\RequestShield\Cache\CachePage::render($s, ['action' => '/rs/cache', 'lang' => 'en', 'ip' => '203.0.113.5']);
            truthy(strpos($html, '2 answers') !== false && strpos($html, 'of 10.0 MB (http-cache-disk)') !== false && strpos($html, 'No answers in memory') !== false, 'what it holds: ' . strip_tags($html));
            $token = \CjwNetwork\RequestShield\Cache\CachePage::token($s, '203.0.113.5');
            $handle = static fn (array $post, string $ip = '203.0.113.5'): array => \CjwNetwork\RequestShield\Cache\CachePage::handle($s, $post, $ip, 'en');
            same(false, $handle(['do' => 'all', 'token' => 'x'])['ok'], 'a wrong token: nothing');
            same(false, $handle(['do' => 'all', 'token' => $token], '198.51.100.9')['ok'], 'another address\'s token: nothing');
            $before = microtime(true) - 1;
            truthy($handle(['do' => 'tags', 'token' => $token, 'tags' => 'c52'])['ok'] && (new Tags("$dir/store/http-cache", \CjwNetwork\RequestShield\Capability::apcu()))->purgedSince(['c52'], $before), 'purge a tag');
            $r = $handle(['do' => 'path', 'token' => $token, 'path' => '/news/']);
            truthy($r['ok'] && $c->get('https://www.example.org/news/a', microtime(true)) === null && $c->get('https://www.example.org/about', microtime(true)) !== null, 'below a path: ' . $r['message']);
            same(false, $handle(['do' => 'path', 'token' => $token, 'path' => 'news'])['ok'], 'a path starts with /');
            truthy($handle(['do' => 'all', 'token' => $token])['ok'] && $c->stats()['entries'] === 0, 'everything');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 http-cache-user-context: on, off, or an address -- its scheme and host in small letters, its path as given' => function (): void {
        $dir = cacheDir();
        try {
            $of = static fn (string $v): string => CacheExtension::of(cacheSettings($dir, "set http-cache on\nset http-cache-user-context $v\n"))['userContext'];
            same(['on', '', 'http://backend.example:8080/Shop/App'], [$of('ON'), $of('Off'), $of('HTTP://Backend.Example:8080/Shop/App/')]);
            $bad = null;
            try {
                $of('ftp://backend.example');
            } catch (\Throwable $e) {
                $bad = $e->getMessage();
            }
            truthy(is_string($bad) && strpos($bad, 'http-cache-user-context is on, off or the address') !== false, 'another scheme: refused -- ' . var_export($bad, true));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 end to end, the role from FOSHttpCache\'s user hash (0039, http-cache-user-context): asked once per session as a Varnish asks it, the application sees the hash, sessions of a role share its page; a purge of the hash\'s tag asks again; a client asking for or sending a hash gets 400' => function (): void {
        $fpm = fpmBinary();
        if (!function_exists('proc_open') || $fpm === null) {
            skip('no PHP-FPM here (TESTS_PHP_FPM)');
        }
        if (!extension_loaded('apcu')) {
            skip('no APCu: roles stay off without it');
        }
        $dir = cacheDir();
        mkdir("$dir/docroot");
        // Exponential Platform without its AppCache, in a few lines: the hash lookup and a page that varies by it.
        file_put_contents("$dir/docroot/index.php", '<?php
            $login = $_COOKIE["eZSESSID98"] ?? "";
            if (strtok($_SERVER["REQUEST_URI"], "?") === "/_fos_user_context_hash") {
                if (($_SERVER["HTTP_ACCEPT"] ?? "") !== "application/vnd.fos.user-context-hash") { http_response_code(406); return; }
                file_put_contents(__DIR__ . "/../lookups", "x", FILE_APPEND);
                $kind = substr($login, 0, 2);
                if ($kind === "er" || $kind === "e5") { http_response_code($kind === "er" ? 503 : 500); return; }
                if ($kind === "rd" && !isset($_GET["to"])) { header("Location: /_fos_user_context_hash?to=1", true, 302); return; }
                if ($kind !== "nh") {
                    header("X-User-Hash: " . ($kind === "rd" ? "hash-redirected" : ($kind === "m0" ? "hash-m0" : ($kind === "ed" ? "hash-editors" : "hash-authors"))));
                }
                header("Content-Type: application/vnd.fos.user-context-hash");
                header("Cache-Control: max-age=" . ($kind === "m0" ? 0 : 600));
                header("Vary: Cookie");
                header("xkey: ez-user-context-hash");
                return;
            }
            file_put_contents(__DIR__ . "/../runs", "x", FILE_APPEND);
            header("Vary: X-User-Hash");
            header("Cache-Control: public, s-maxage=600");
            header("xkey: ez-all");
            echo "page for " . ($_SERVER["HTTP_X_USER_HASH"] ?? "nobody") . " " . hrtime(true);');
        $lookupPort = freePort();
        file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nset http-cache on\ncache-query x\nset http-cache-hosts www.example.org\n"
            . "set http-cache-session-cookie eZSESSID*\nset http-cache-user-context http://127.0.0.1:$lookupPort\nset http-cache-user-hash-header X-User-Hash\n"
            . "set http-cache-purgers 127.0.0.1 ::1\n");
        $port = freePort();
        $proc = startFpm($fpm, $dir, $port);
        // The lookup's server: the same site and rules (here php -S; in production the same pool).
        $web = proc_open(sprintf('REQUEST_SHIELD_CONFIG=%s exec %s -d apc.enable_cli=1 -d auto_prepend_file=%s -S 127.0.0.1:%d %s > %s 2>&1',
            escapeshellarg("$dir/site.rules"), serverPhp(), escapeshellarg(rsEntry()), $lookupPort, escapeshellarg("$dir/docroot/index.php"), escapeshellarg("$dir/web.log")), [], $pipes);
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $lookupPort); $i++) {
            usleep(100000);
        }
        try {
            $send = static function (string $method, string $uri, array $headers = [], string $addr = '127.0.0.1') use ($port, $dir): array {
                $params = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri, 'QUERY_STRING' => (string) parse_url($uri, PHP_URL_QUERY),
                    'SCRIPT_FILENAME' => "$dir/docroot/index.php", 'SCRIPT_NAME' => '/index.php', 'DOCUMENT_ROOT' => "$dir/docroot", 'SERVER_PROTOCOL' => 'HTTP/1.1',
                    'SERVER_NAME' => 'www.example.org', 'SERVER_PORT' => '80', 'REMOTE_ADDR' => $addr, 'HTTP_HOST' => 'www.example.org',
                    'REQUEST_SHIELD_CONFIG' => "$dir/site.rules", 'PHP_VALUE' => 'auto_prepend_file=' . rsEntry()];
                foreach ($headers as $k => $v) {
                    $params['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
                }
                return fcgi($port, $params);
            };
            $as = static fn (string $login, array $more = [], string $addr = '127.0.0.1'): array => $send('GET', '/index.php', ['Cookie' => "eZSESSID98=$login; _ga=1"] + $more, $addr);
            $hit = static fn (array $r): bool => strpos($r[1], 'X-RS-Cache: hit') !== false;
            $count = static fn (string $f): int => strlen((string) @file_get_contents("$dir/$f"));
            $r = $as('ed-1');
            truthy(!$hit($r) && strpos($r[2], 'page for hash-editors') === 0 && $count('lookups') === 1,
                'a new session: the hash asked once, the application sees it as behind a Varnish -- ' . $r[1] . $r[2] . @file_get_contents("$dir/web.log"));
            truthy(stripos($r[1], 'Cache-Control: private, no-cache') !== false, 'a role\'s page leaves private: ' . $r[1]);
            $r = $as('ed-2');
            truthy($hit($r) && strpos($r[2], 'page for hash-editors') === 0 && $count('lookups') === 2 && $count('runs') === 1,
                'another editor\'s session: its hash asked, the editors\' page from the cache -- the application does not run');
            $r = $as('ed-1');
            truthy($hit($r) && $count('lookups') === 2, 'the same session again: its hash remembered (max-age), not asked again');
            $r = $as('au-1');
            truthy(!$hit($r) && strpos($r[2], 'page for hash-authors') === 0, 'another role: its own page');
            same(400, $as('ed-1', ['Accept' => 'application/vnd.fos.user-context-hash'])[0], 'a client asking for a hash: 400, as the Varnish configurations answer');
            same(400, $as('ed-1', ['X-User-Hash' => 'hash-editors'])[0], 'a client sending a hash: 400');
            same(400, $send('GET', '/_fos_user_context_hash', ['Cookie' => 'eZSESSID98=ed-1', 'Accept' => 'application/vnd.fos.user-context-hash', 'X-RS-Lookup' => str_repeat('0', 64)])[0],
                'a forged X-RS-Lookup: 400');
            // The shield's own MAC, but not its lookup: another path, another method, a hash sent along -- 400 as any other.
            $set = Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
            $key = \CjwNetwork\RequestShield\Challenge\Secret::resolve($set->challenge->secret, $set->storeDir);
            $mac = hash_hmac('sha256', 'lookup|' . hash_hmac('sha256', 'session|eZSESSID98=ed-1', $key), $key);
            $own = ['Cookie' => 'eZSESSID98=ed-1', 'Accept' => 'application/vnd.fos.user-context-hash', 'X-RS-Lookup' => $mac];
            same(200, $send('GET', '/_fos_user_context_hash', $own)[0], 'the shield\'s own lookup: the application answers');
            same([400, 400, 400], [$send('GET', '/index.php', $own)[0], $send('POST', '/_fos_user_context_hash', $own)[0], $send('GET', '/_fos_user_context_hash', $own + ['X-User-Hash' => 'x'])[0]],
                'its MAC on another path, with POST, with a hash: 400');
            same(200, $send('PURGE', '/', ['key' => 'ez-user-context-hash'])[0], 'PURGE + key: ez-user-context-hash (roles changed in the CMS)');
            $before = $count('lookups');
            truthy($hit($as('ed-1')) && $count('lookups') === $before + 1, 'the hashes purged: asked again (the page itself still the editors\')');
            // No hash in the answer: the cache skipped, that session not asked again for a while -- the others are.
            $before = $count('lookups');
            $r = $as('nh-1');
            truthy(!$hit($r) && strpos($r[2], 'page for nobody') === 0 && $count('lookups') === $before + 1, 'an answer without a hash: the application runs without one');
            $as('nh-1');
            truthy($count('lookups') === $before + 1, 'the same session: not asked again at once');
            truthy($hit($as('ed-3')) && $count('lookups') === $before + 2, 'another session: asked -- one session\'s answer pauses nobody else');
            // A redirect is no hash: not followed (it could lead anywhere, the session cookie with it).
            $before = $count('lookups');
            $r = $as('rd-1');
            truthy(strpos($r[2], 'page for nobody') === 0 && $count('lookups') === $before + 1, 'a redirect: not followed, no hash -- ' . $r[2]);
            // max-age=0: the hash holds for this request only.
            $before = $count('lookups');
            $as('m0-1');
            $r = $as('m0-1');
            truthy(strpos($r[2], 'page for hash-m0') === 0 && $count('lookups') === $before + 2, 'max-age=0: asked for every request -- ' . $r[2]);
            // A cookie value no browser sends (a quote): never put into a request of the shield's.
            $before = $count('lookups');
            $r = $as('ed"x');
            truthy(!$hit($r) && $count('lookups') === $before, 'an odd session cookie: not asked');
            // Made-up sessions from one address: at most 30 lookups a minute, then the cache is skipped.
            $before = $count('lookups');
            for ($i = 0; $i < 32; $i++) {
                $as("au-flood-$i", [], '198.51.100.9');
            }
            same(30, $count('lookups') - $before, 'one address, 32 new sessions: 30 asked');
            truthy($hit($as('au-other', [], '198.51.100.10')) && $count('lookups') === $before + 31, 'another address: still asked');
            // A 500 may be what one made-up cookie causes: only that session waits.
            $before = $count('lookups');
            $as('e5-1');
            truthy($hit($as('ed-5')) && $count('lookups') === $before + 2, 'a 500: the next session is still asked');
            // The application does not answer (503): nobody is asked for a while, the site answers without the cache.
            $before = $count('lookups');
            $r = $as('er-1');
            truthy(!$hit($r) && strpos($r[2], 'page for nobody') === 0 && $count('lookups') === $before + 1, 'a 503: no hash');
            $r = $as('ed-4');
            truthy(!$hit($r) && strpos($r[2], 'page for nobody') === 0 && $count('lookups') === $before + 1, 'after a 503: a new session is not asked (the pause), the application answers');
        } finally {
            proc_terminate($web);
            proc_close($web);
            proc_terminate($proc);
            proc_close($proc);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 end to end, http-cache-user-context on: the shield asks the site itself, at the address the visitor used' => function (): void {
        if (!function_exists('proc_open') || PHP_OS_FAMILY !== 'Linux') {
            skip('no proc_open, or no PHP_CLI_SERVER_WORKERS (Linux only)');
        }
        if (!extension_loaded('apcu')) {
            skip('no APCu: roles stay off without it');
        }
        $dir = cacheDir();
        mkdir("$dir/docroot");
        file_put_contents("$dir/docroot/index.php", '<?php
            if (strtok($_SERVER["REQUEST_URI"], "?") === "/_fos_user_context_hash") {
                file_put_contents(__DIR__ . "/../lookups", "x", FILE_APPEND);
                header("X-User-Context-Hash: hash-" . substr($_COOKIE["PHPSESSID"] ?? "", 0, 2));
                header("Cache-Control: max-age=600");
                return;
            }
            header("Vary: X-User-Context-Hash");
            header("Cache-Control: public, s-maxage=600");
            echo "page for " . ($_SERVER["HTTP_X_USER_CONTEXT_HASH"] ?? "nobody") . " " . hrtime(true);');
        $port = freePort();
        file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nset http-cache on\ncache-query x\nset http-cache-hosts 127.0.0.1:$port\n"
            . "set http-cache-session-cookie PHPSESSID\nset http-cache-user-context on\n");
        // php -S prepends nothing to its router: the router loads the shield, as auto_prepend_file would.
        file_put_contents("$dir/router.php", '<?php require ' . var_export(rsEntry(), true) . '; require __DIR__ . "/docroot/index.php";');
        // Several workers: the lookup is a second request to the same server while the first waits.
        $web = proc_open(sprintf('PHP_CLI_SERVER_WORKERS=3 REQUEST_SHIELD_CONFIG=%s exec %s -d apc.enable_cli=1 -S 127.0.0.1:%d %s > %s 2>&1',
            escapeshellarg("$dir/site.rules"), serverPhp(), $port, escapeshellarg("$dir/router.php"), escapeshellarg("$dir/web.log")), [], $pipes);
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
            usleep(100000);
        }
        try {
            $get = static function (string $session) use ($port): array {
                $r = Http::get("http://127.0.0.1:$port/", ['Cookie' => "PHPSESSID=$session"], 5);
                return [$r['status'] ?? 0, implode("\n", array_map(static fn ($k, $v): string => "$k: $v", array_keys($r['headers'] ?? []), $r['headers'] ?? [])), $r['body'] ?? ''];
            };
            $count = static fn (): int => strlen((string) @file_get_contents("$dir/lookups"));
            $r = $get('ed-1');
            truthy(strpos($r[2], 'page for hash-ed') === 0 && $count() === 1, 'asked at http://127.0.0.1:<port> itself: ' . $r[2] . @file_get_contents("$dir/web.log"));
            $r = $get('ed-2');
            truthy(strpos($r[1], 'x-rs-cache: hit') !== false && $count() === 2, 'another session of the role: the role\'s page from the cache -- ' . $r[1]);
        } finally {
            proc_terminate($web);
            proc_close($web);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF04-03 end to end, Exponential Platform\'s dialect (0039): xkey kept and taken out, PURGE + key from 127.0.0.1 makes its pages run again, X-Location-Id: * everything, an address; a stranger\'s PURGE gets 405; X-LiteSpeed-Purge in a POST\'s answer' => function (): void {
        $fpm = fpmBinary();
        if (!function_exists('proc_open') || $fpm === null) {
            skip('no PHP-FPM here (TESTS_PHP_FPM): the built-in server refuses PURGE itself');
        }
        $dir = cacheDir();
        mkdir("$dir/docroot");
        file_put_contents("$dir/docroot/index.php", '<?php
            file_put_contents(__DIR__ . "/../runs", "x", FILE_APPEND);
            if ($_SERVER["REQUEST_METHOD"] === "POST") { header("X-LiteSpeed-Purge: tag=content-60"); echo "saved"; return; }
            $id = (int) ($_GET["id"] ?? 52);
            header("Cache-Control: public, s-maxage=600");
            header("xkey: content-$id location-" . ($id + 100) . " ez-all");
            header("X-Location-Id: " . ($id + 100));
            echo "page $id " . hrtime(true);');
        file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nset http-cache on\ncache-query id\nset http-cache-hosts www.example.org\nset http-cache-purgers 127.0.0.1 ::1\n");
        $port = freePort();
        $proc = startFpm($fpm, $dir, $port);
        try {
            // As nginx hands it to PHP-FPM: what the purge client sent -- the method, the address, the headers.
            $send = static function (string $method, string $uri, array $headers = [], string $body = '', string $from = '127.0.0.1') use ($port, $dir): array {
                $params = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $uri, 'QUERY_STRING' => (string) parse_url($uri, PHP_URL_QUERY),
                    'SCRIPT_FILENAME' => "$dir/docroot/index.php", 'SCRIPT_NAME' => '/index.php', 'DOCUMENT_ROOT' => "$dir/docroot", 'SERVER_PROTOCOL' => 'HTTP/1.1',
                    'SERVER_NAME' => 'www.example.org', 'SERVER_PORT' => '80', 'REMOTE_ADDR' => $from, 'HTTP_HOST' => 'www.example.org',
                    'REQUEST_SHIELD_CONFIG' => "$dir/site.rules", 'PHP_VALUE' => 'auto_prepend_file=' . rsEntry()];
                foreach ($headers as $k => $v) {
                    $params['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
                }
                if ($body !== '') {
                    $params += ['CONTENT_TYPE' => 'application/x-www-form-urlencoded', 'CONTENT_LENGTH' => (string) strlen($body)];
                }
                return fcgi($port, $params, $body);
            };
            $runs = static fn (): int => strlen((string) @file_get_contents("$dir/runs"));
            [, $h1] = $send('GET', '/index.php?id=52');
            [, $h2, $b2] = $send('GET', '/index.php?id=52');
            truthy(strpos($h1, 'X-RS-Cache: miss') !== false && strpos($h2, 'X-RS-Cache: hit') !== false && $runs() === 1, "kept: $h2");
            truthy(stripos($h1 . $h2, 'xkey') === false && stripos($h1 . $h2, 'x-location-id') === false, 'xkey and X-Location-Id never reach the visitor, on a miss nor on a hit: ' . $h1);
            $send('GET', '/index.php?id=60');
            [$st, , $pb] = $send('PURGE', '/', ['key' => 'content-52']);
            same([200, "Purged\n"], [$st, $pb], 'PURGE + key from 127.0.0.1');
            [, $h3, $b3] = $send('GET', '/index.php?id=52');
            truthy(strpos($h3, 'X-RS-Cache: miss') !== false && $b3 !== $b2, "purged: the page runs again ($h3)");
            [, $h4] = $send('GET', '/index.php?id=60');
            truthy(strpos($h4, 'X-RS-Cache: hit') !== false, 'another content: still kept');
            [$st5] = $send('PURGE', '/', ['key' => 'ez-all', 'X-Forwarded-For' => '203.0.113.9']);
            same(405, $st5, 'a PURGE that came through an untrusted proxy: 405, as any unknown method');
            same(405, $send('PURGE', '/', ['key' => 'ez-all'], '', '203.0.113.9')[0], 'a stranger\'s PURGE: 405');
            [, $h6] = $send('GET', '/index.php?id=60');
            truthy(strpos($h6, 'X-RS-Cache: hit') !== false, '... and nothing purged');
            [$st7] = $send('POST', '/index.php', [], 'a=1');
            same(200, $st7, 'a form');
            [, $h8] = $send('GET', '/index.php?id=60');
            truthy(strpos($h8, 'X-RS-Cache: miss') !== false, 'the POST\'s answer purged content-60 (X-LiteSpeed-Purge)');
            $send('GET', '/index.php?id=60');
            same(200, $send('PURGE', '/index.php?id=60')[0], 'PURGE <address>');
            [, $h9] = $send('GET', '/index.php?id=60');
            truthy(strpos($h9, 'X-RS-Cache: miss') !== false, 'the address purged');
            $send('GET', '/index.php?id=52');
            same(200, $send('PURGE', '/', ['X-Location-Id' => '*'])[0], 'X-Location-Id: *');
            [, $h10] = $send('GET', '/index.php?id=52');
            truthy(strpos($h10, 'X-RS-Cache: miss') !== false, 'everything purged');
            same(200, $send('PURGEKEYS', '/', ['xkey-purge' => 'content-52'])[0], 'Ibexa\'s PURGEKEYS too');
            [, $h11] = $send('GET', '/index.php?id=52');
            truthy(strpos($h11, 'X-RS-Cache: miss') !== false, 'purged by PURGEKEYS');
        } finally {
            proc_terminate($proc);
            proc_close($proc);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
];
