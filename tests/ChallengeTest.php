<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\ChallengeSettings;
use CjwNetwork\RequestShield\Challenge\ChallengePage;
use CjwNetwork\RequestShield\Challenge\Gate;
use CjwNetwork\RequestShield\Challenge\PassCookie;
use CjwNetwork\RequestShield\Challenge\ProofOfWork;
use CjwNetwork\RequestShield\Challenge\SearchEngines;
use CjwNetwork\RequestShield\Challenge\Secret;
use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Shield;
use CjwNetwork\RequestShield\Store\MemoryStore;

const SECRET = 'test-secret-0123456789abcdef0123456789abcdef';

/** What the page's script does: find the number, build the payload. */
function solveInPhp(array $c): string
{
    for ($n = 0; $n <= $c['maxnumber']; $n++) {
        if (hash('sha256', $c['salt'] . $n) === $c['challenge']) {
            $json = json_encode(['algorithm' => $c['algorithm'], 'challenge' => $c['challenge'], 'number' => $n, 'salt' => $c['salt'], 'signature' => $c['signature'], 'took' => 1]);
            return rtrim(strtr(base64_encode($json), '+/', '-_'), '=');
        }
    }
    throw new TestFailure('no solution');
}

function creq(string $uri = '/', array $cookies = [], string $method = 'GET', string $ip = '203.0.113.7', string $ua = 'Mozilla/5.0 Test'): Request
{
    $c = [];
    foreach ($cookies as $k => $v) {
        $c[] = "$k=$v";
    }
    return Request::fromServer(['REQUEST_URI' => $uri, 'REQUEST_METHOD' => $method, 'HTTP_HOST' => 'example.org',
        'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => $ua] + ($c ? ['HTTP_COOKIE' => implode('; ', $c)] : []));
}

/** The cookie's value from a Set-Cookie line. */
function cookieValue(array $cookies, string $name): ?string
{
    foreach ($cookies as $line) {
        if (strncmp($line, $name . '=', strlen($name) + 1) === 0) {
            return substr($line, strlen($name) + 1, strpos($line, ';') - strlen($name) - 1);
        }
    }
    return null;
}

return [
    'RSF03-02 the check page\'s preview (for a page about it): the same ring and words, no task, no cookie, three times then the smile' => function (): void {
        $live = \CjwNetwork\RequestShield\Challenge\ChallengePage::render(['algorithm' => 'SHA-256', 'challenge' => str_repeat('a', 64), 'maxnumber' => 10, 'salt' => 's', 'signature' => str_repeat('b', 64)], 'rss', false, \CjwNetwork\RequestShield\Texts::all('de'));
        $preview = \CjwNetwork\RequestShield\Challenge\ChallengePage::preview(\CjwNetwork\RequestShield\Texts::all('de'));
        $ring = static fn (string $html): string => (string) strstr((string) strstr($html, '<svg id="r"'), '</svg>', true);
        truthy($ring($live) !== '' && $ring($live) === $ring($preview), 'the same ring as the live page');
        truthy(strpos($preview, 'Einen Moment, bitte') !== false && strpos($preview, 'Ihr Browser wird geprüft') !== false, 'the same words, in the language asked for');
        truthy(strpos($preview, 'document.cookie') === false && strpos($preview, 'var RS=') === false && strpos($preview, 'signature') === false, 'no task, no cookie, no solver');
        truthy(strpos($preview, 'n<3') !== false && strpos($preview, 'prefers-reduced-motion') !== false, 'three times, then the smile; reduced motion: the smile at once');
    },
    'RSF03-02 proof of work: a solution verifies; tampering, expiry and another client do not' => function (): void {
        $pow = new ProofOfWork(SECRET);
        $c = $pow->create('203.0.113.7', 2000, 2000);
        same('SHA-256', $c['algorithm']);
        $payload = solveInPhp($c);
        truthy($pow->verify($payload, '203.0.113.7', 1000.0), 'valid');
        truthy(!$pow->verify($payload, '198.51.100.1', 1000.0), 'another client');
        truthy(!$pow->verify($payload, '203.0.113.7', 2001.0), 'expired');
        truthy(!(new ProofOfWork('another-secret-0123456789abcdef0123456789'))->verify($payload, '203.0.113.7', 1000.0), 'another secret');
        $data = json_decode(base64_decode(strtr($payload, '-_', '+/') . '=='), true);
        $wrong = $data;
        $wrong['number'] = $data['number'] + 1;
        truthy(!$pow->verify(rtrim(strtr(base64_encode(json_encode($wrong)), '+/', '-_'), '='), '203.0.113.7', 1000.0), 'wrong number');
        $wrong = $data;
        $wrong['salt'] = str_replace('expires=2000', 'expires=9999', $data['salt']);
        truthy(!$pow->verify(rtrim(strtr(base64_encode(json_encode($wrong)), '+/', '-_'), '='), '203.0.113.7', 1000.0), 'extended expiry');
        truthy(!$pow->verify('garbage', '203.0.113.7', 1000.0), 'garbage');
    },
    'RSF03-02 pass cookie: bound to client and User-Agent, expires, cannot be forged' => function (): void {
        $p = new PassCookie(SECRET);
        $v = $p->issue('203.0.113.7', 'UA', 5000);
        truthy($p->valid($v, '203.0.113.7', 'UA', 4000.0), 'valid');
        truthy(!$p->valid($v, '203.0.113.8', 'UA', 4000.0), 'other client');
        truthy(!$p->valid($v, '203.0.113.7', 'Other UA', 4000.0), 'other User-Agent');
        truthy(!$p->valid($v, '203.0.113.7', 'UA', 5001.0), 'expired');
        truthy(!$p->valid(str_replace('.' . base_convert('5000', 10, 36) . '.', '.' . base_convert('9999', 10, 36) . '.', $v), '203.0.113.7', 'UA', 4000.0), 'extended');
        truthy(preg_match('/^2\.[0-9a-z]{1,8}\.[A-Za-z0-9_-]{11}\.[A-Za-z0-9_-]{22}$/', $v) === 1, 'v2: "2.<expires base36>.<tag 11>.<mac 22>", cookie-safe characters only: ' . $v);
        same(43, strlen($p->issue('203.0.113.7', 'UA', 1790000000)), '43 bytes for a Unix time of today');
        same(5000, $p->expires($v), 'the expiry can be read back');
        same(1790000000, $p->expires($p->issue('b', 'UA', 1790000000)), 'exactly, for a real time too');
        truthy(!$p->valid('v1.5000.' . substr(hash_hmac('sha256', 'x', SECRET), 0, 16) . '.' . substr(hash_hmac('sha256', 'y', SECRET), 0, 32), '203.0.113.7', 'UA', 4000.0), 'the v1 format is not read any more');
        truthy(!$p->valid('2.' . base_convert('5000', 10, 36) . '.' . explode('.', $v)[2] . '.' . str_repeat('A', 22), '203.0.113.7', 'UA', 4000.0), 'a wrong MAC');
        truthy((new PassCookie(SECRET, false))->valid((new PassCookie(SECRET, false))->issue('b', 'UA1', 5000), 'b', 'UA2', 1.0), 'User-Agent binding can be off');
    },
    'RSF03-02 secret: made once, kept, shared' => function (): void {
        $dir = sys_get_temp_dir() . '/rshield-secret-' . getmypid() . '-' . mt_rand();
        $a = Secret::resolve(null, $dir);
        same(64, strlen($a));
        same($a, Secret::resolve(null, $dir), 'the same on the next request');
        same('0600', substr(sprintf('%o', fileperms($dir . '/secret')), -4));
        same(str_repeat('s', 40), Secret::resolve(str_repeat('s', 40), $dir), 'a configured one wins');
        exec('rm -rf ' . escapeshellarg($dir));
    },
    'RSF03-02 gate: page, then solution -> pass cookie, then pass -> through' => function (): void {
        $gate = new Gate(ChallengeSettings::from(['difficulty' => ['min' => 1000, 'max' => 3000]]), SECRET);
        $challenged = Decision::challenge('requests', 0.0);
        $base = Decision::allow();

        $r = $gate->resolve($challenged, $base, creq('/page'), 1000.0);
        same(Decision::CHALLENGE, $r['decision']->action, 'first: challenged');
        truthy(is_string($r['page']) && strpos($r['page'], 'var RS=') !== false, 'the page carries the challenge');
        preg_match('/var RS=(\{.*?\});\(function/s', $r['page'], $m);
        $rs = json_decode($m[1], true);
        same(1000, $rs['c']['maxnumber'], 'level 0: minimum difficulty');

        $r = $gate->resolve($challenged, $base, creq('/page', ['rss' => solveInPhp($rs['c'])]), 1001.0);
        same(Decision::ALLOW_UNCACHED, $r['decision']->action, 'solved: through, not cached');
        $pass = cookieValue($r['cookies'], 'rsp');
        truthy($pass !== null && $pass !== '', 'pass cookie set');
        same('', cookieValue($r['cookies'], 'rss'), 'solution cookie removed');

        $r = $gate->resolve($challenged, $base, creq('/other', ['rsp' => $pass]), 1500.0);
        same(Decision::ALLOW, $r['decision']->action, 'pass: through as the checks decided');
        same(Decision::CHALLENGE, $gate->resolve($challenged, $base, creq('/other', ['rsp' => $pass], 'GET', '198.51.100.1'), 1500.0)['decision']->action, 'the pass is for one client only');
    },
    'RSF03-02 gate: difficulty grows with the level; POST is throttled; exempt paths pass' => function (): void {
        $gate = new Gate(ChallengeSettings::from(['difficulty' => ['min' => 1000, 'max' => 5000], 'exemptPaths' => ['#^/api/#']]), SECRET);
        $r = $gate->resolve(Decision::challenge('requests', 1.0), Decision::allow(), creq('/'), 1.0);
        preg_match('/var RS=(\{.*?\});\(function/s', $r['page'], $m);
        same(5000, json_decode($m[1], true)['c']['maxnumber'], 'level 1: maximum difficulty');
        same(Decision::THROTTLE, $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/', [], 'POST'), 1.0)['decision']->action);
        same(Decision::ALLOW, $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/api/x'), 1.0)['decision']->action);
    },
    'RSF03-02 gate: a solution buys one pass, not one per replay' => function (): void {
        $gate = new Gate(ChallengeSettings::from(['difficulty' => ['min' => 1000, 'max' => 1000]]), SECRET, null, 64, new MemoryStore());
        $c = (new ProofOfWork(SECRET))->create('203.0.113.7', 1000, 2000);
        $solved = creq('/', ['rss' => solveInPhp($c)]);
        same(Decision::ALLOW_UNCACHED, $gate->resolve(Decision::challenge('requests'), Decision::allow(), $solved, 1000.0)['decision']->action, 'first use');
        same(Decision::CHALLENGE, $gate->resolve(Decision::challenge('requests'), Decision::allow(), $solved, 1010.0)['decision']->action, 'replayed');
    },
    'RSF03-02 gate: a wrong solution gets a new challenge and loses its cookie' => function (): void {
        $gate = new Gate(ChallengeSettings::from(['difficulty' => ['min' => 1000, 'max' => 1000]]), SECRET);
        $r = $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/', ['rss' => 'bogus']), 1.0);
        same(Decision::CHALLENGE, $r['decision']->action);
        same('', cookieValue($r['cookies'], 'rss'));
    },
    'RSF01-04 search engines: a verified crawler passes, a fake one does not' => function (): void {
        $cache = [];
        $engines = new SearchEngines(SearchEngines::defaults(),
            function ($k) use (&$cache) { return $cache[$k] ?? null; },
            function ($k, $v) use (&$cache) { $cache[$k] = $v; },
            fn (string $ip) => ['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com', '6.6.6.6' => 'evil.example'][$ip] ?? false,
            fn (string $host) => $host === 'crawl-66-249-66-1.googlebot.com' ? ['66.249.66.1'] : []);
        $bot = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
        truthy($engines->verified('66.249.66.1', $bot), 'real Googlebot');
        same('1', $cache['se:66.249.66.1'] ?? null, 'remembered');
        truthy(!$engines->verified('6.6.6.6', $bot), 'claims Googlebot, resolves elsewhere');
        truthy(!$engines->verified('66.249.66.1', 'curl/8'), 'no crawler claimed');
        $crawlers = \CjwNetwork\RequestShield\Challenge\Crawlers::of(\CjwNetwork\RequestShield\Settings::from(['crawlerVerify' => 'dns']), null, null, null,
            fn (string $ip) => ['66.249.66.1' => 'crawl-66-249-66-1.googlebot.com', '6.6.6.6' => 'evil.example'][$ip] ?? false,
            fn (string $host) => $host === 'crawl-66-249-66-1.googlebot.com' ? ['66.249.66.1'] : []);
        $gate = new Gate(ChallengeSettings::from([]), SECRET, $crawlers);
        same(Decision::ALLOW, $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/', [], 'GET', '66.249.66.1', $bot), 1.0)['decision']->action);
        $fake = $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/', [], 'GET', '6.6.6.6', $bot), 1.0)['decision'];
        same([Decision::CHALLENGE, 'CRAWL-GOOGLE'], [$fake->action, $fake->claimed], 'a fake one: checked, and noted');
    },
    'RSF03-01 shield: budget -> challenge -> solved -> through, cacheability kept' => function (): void {
        $dir = sys_get_temp_dir() . '/rshield-ch-' . getmypid() . '-' . mt_rand();
        $shield = new Shield(['storeDir' => $dir, 'challenge' => ['secret' => SECRET, 'searchEngines' => false, 'difficulty' => ['min' => 1000, 'max' => 2000]],
            'cacheable' => ['query' => []], 'budgets' => ['requests' => ['limit' => 100, 'window' => 60, 'challengeAt' => 3]]], new MemoryStore());
        $now = 6000.0;
        for ($i = 0; $i < 3; $i++) {
            same(Decision::ALLOW, $shield->settle($shield->decide(creq('/'), $now), creq('/'), $now)['decision']->action);
        }
        $r = $shield->settle($shield->decide(creq('/'), $now), creq('/'), $now);
        same(Decision::CHALLENGE, $r['decision']->action, '4th: challenged');
        preg_match('/var RS=(\{.*?\});\(function/s', $r['page'], $m);
        $solved = creq('/', ['rss' => solveInPhp(json_decode($m[1], true)['c'])]);
        $r = $shield->settle($shield->decide($solved, $now), $solved, $now);
        same(Decision::ALLOW_UNCACHED, $r['decision']->action);
        $withPass = creq('/?x=1', ['rsp' => cookieValue($r['cookies'], 'rsp')]);
        $r = $shield->settle($shield->decide($withPass, $now), $withPass, $now);
        same('query parameter', $r['decision']->reason, 'with a pass, the cacheable definition still counts');
        exec('rm -rf ' . escapeshellarg($dir));
    },
    'RSF03-02 the page escapes what it embeds' => function (): void {
        $page = ChallengePage::render(['algorithm' => 'SHA-256', 'challenge' => 'x', 'maxnumber' => 1, 'salt' => '</script><b>', 'signature' => 's'], 'rs', false, ['title' => '<i>T</i>']);
        truthy(strpos($page, '</script><b>') === false, 'no raw </script> from the data');
        truthy(strpos($page, '&lt;i&gt;T&lt;/i&gt;') !== false, 'texts escaped');
    },
    'RSF03-02 alwaysPaths: challenged whatever the budget says, until the client holds a pass' => function (): void {
        $dir = sys_get_temp_dir() . '/rshield-always-' . getmypid() . '-' . mt_rand();
        $shield = new Shield(['storeDir' => $dir, 'budgets' => ['requests' => ['limit' => 1000, 'window' => 60]],
            'challenge' => ['secret' => SECRET, 'searchEngines' => false, 'alwaysPaths' => ['#^/login$#'], 'difficulty' => ['min' => 1000, 'max' => 1000]]], new MemoryStore());
        same(Decision::ALLOW, $shield->settle($shield->decide(creq('/page'), 1.0), creq('/page'), 1.0)['decision']->action, 'other paths untouched');
        $r = $shield->settle($shield->decide(creq('/login'), 1.0), creq('/login'), 1.0);
        same(Decision::CHALLENGE, $r['decision']->action, 'first visit: challenged');
        same('always', $r['decision']->reason);
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $r['page'], $m);
        $solved = creq('/login', ['rss' => solveInPhp(json_decode($m[1], true)['c'])]);
        $r = $shield->settle($shield->decide($solved, 2.0), $solved, 2.0);
        same(Decision::ALLOW_UNCACHED, $r['decision']->action, 'solved');
        $withPass = creq('/login', ['rsp' => (string) cookieValue($r['cookies'], 'rsp')]);
        same(Decision::ALLOW, $shield->settle($shield->decide($withPass, 3.0), $withPass, 3.0)['decision']->action, 'with the pass: through');
        $post = $shield->settle($shield->decide(creq('/login', [], 'POST'), 4.0), creq('/login', [], 'POST'), 4.0);
        same(Decision::CHALLENGE, $post['decision']->action, 'a POST without a pass: not through');
        truthy(is_string($post['page']) && strpos($post['page'], 'then what you entered is sent') !== false, 'but checked, and the form sent again -- not a pause');
        $postWithPass = creq('/login', ['rsp' => (string) cookieValue($r['cookies'], 'rsp')], 'POST');
        same(Decision::ALLOW_UNCACHED, $shield->settle($shield->decide($postWithPass, 5.0), $postWithPass, 5.0)['decision']->action, 'a POST with the pass: through, uncached');
        exec('rm -rf ' . escapeshellarg($dir));
    },
    'RSF03-02 a background request (fetch, XMLHttpRequest) never gets the check page: with a pass through, without one the check as JSON -- a navigation keeps the page' => function (): void {
        $dir = sys_get_temp_dir() . '/rshield-bg-' . getmypid() . '-' . mt_rand();
        $shield = new Shield(['storeDir' => $dir, 'budgets' => ['requests' => ['limit' => 1000, 'window' => 60]],
            'challenge' => ['secret' => SECRET, 'searchEngines' => false, 'alwaysPaths' => ['#^/admin(/|$)#'], 'difficulty' => ['min' => 1000, 'max' => 1000]]], new MemoryStore());
        // creq() with headers.
        $with = static function (array $c, array $headers): Request {
            [$uri, $cookies, $method] = $c + [1 => [], 2 => 'GET'];
            $server = ['REQUEST_URI' => $uri, 'REQUEST_METHOD' => $method, 'HTTP_HOST' => 'example.org', 'REMOTE_ADDR' => '203.0.113.7', 'HTTP_USER_AGENT' => 'Mozilla/5.0 Test'];
            if ($cookies !== []) {
                $server['HTTP_COOKIE'] = implode('; ', array_map(static fn ($k, $v): string => "$k=$v", array_keys($cookies), $cookies));
            }
            foreach ($headers as $k => $v) {
                $server['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
            }
            return Request::fromServer($server);
        };
        $run = static fn (Request $r, float $t): array => $shield->settle($shield->decide($r, $t), $r, $t);
        $fetch = ['Sec-Fetch-Dest' => 'empty', 'Sec-Fetch-Mode' => 'cors'];
        $xhr = ['X-Requested-With' => 'XMLHttpRequest'];

        truthy(Shield::isBackground($with(['/admin/user/megamenu/setup'], $fetch)), 'fetch(): Sec-Fetch-Dest empty');
        truthy(Shield::isBackground($with(['/admin/user/megamenu/setup'], $xhr)), 'a library\'s XMLHttpRequest: X-Requested-With');
        truthy(Shield::isBackground($with(['/'], ['X-Requested-With' => 'xmlhttprequest'])), 'in any case');
        foreach ([[], ['Sec-Fetch-Dest' => 'document', 'Sec-Fetch-Mode' => 'navigate'], ['Sec-Fetch-Dest' => 'iframe'], ['Sec-Fetch-Dest' => 'image'],
            ['X-Requested-With' => 'com.example.app']] as $h) {
            truthy(!Shield::isBackground($with(['/admin/dashboard'], $h)), 'no background request: ' . json_encode($h));
        }

        // Without a pass: the task as JSON (Responder::api), no page -- the script can tell it from its fragment.
        foreach ([$fetch, $xhr] as $h) {
            $r = $run($with(['/admin/user/megamenu/setup'], $h), 1.0);
            same(Decision::CHALLENGE, $r['decision']->action, 'no pass: not through ' . json_encode($h));
            same(null, $r['page'], 'no HTML check page ' . json_encode($h));
            truthy(is_array($r['json']) && isset($r['json']['challenge'], $r['json']['signature']), 'the check as JSON ' . json_encode($h));
        }
        $post = $run($with(['/admin/content/autosave', [], 'POST'], $fetch), 1.0);
        same([null, true], [$post['page'], is_array($post['json'])], 'a background POST: JSON too, no form to send again');

        // A navigation is unchanged: the page.
        $nav = $run($with(['/admin/dashboard'], ['Sec-Fetch-Dest' => 'document', 'Sec-Fetch-Mode' => 'navigate']), 1.0);
        same(Decision::CHALLENGE, $nav['decision']->action);
        truthy(is_string($nav['page']) && strpos($nav['page'], 'var RS=') !== false && $nav['json'] === null, 'a navigation: the check page, as before');

        // With a pass: the fragment, as any request with a pass.
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $nav['page'], $m);
        $solved = creq('/admin/dashboard', ['rss' => solveInPhp(json_decode($m[1], true)['c'])]);
        $pass = (string) cookieValue($run($solved, 2.0)['cookies'], 'rsp');
        foreach ([$fetch, $xhr] as $h) {
            $r = $run($with(['/admin/user/megamenu/setup', ['rsp' => $pass]], $h), 3.0);
            same(Decision::ALLOW, $r['decision']->action, 'with a pass: through ' . json_encode($h));
        }

        // The JSON check is what the shield sends: 429, Request-Shield-Challenge, no page.
        $lines = \CjwNetwork\RequestShield\Responder::apiHeaderLines(Decision::challenge('always'), $post['json']);
        same('Content-Type: application/json; charset=utf-8', $lines[0]);
        truthy(strncmp($lines[2], 'Request-Shield-Challenge: ', 26) === 0, 'the task in a header: ' . $lines[2]);
        exec('rm -rf ' . escapeshellarg($dir));
    },
    'RSF03-02 alwaysMethods: challenge POST ** checks every form sent, not the pages that show them' => function (): void {
        $dir = sys_get_temp_dir() . '/rshield-always-m-' . getmypid() . '-' . mt_rand();
        $shield = new Shield(['storeDir' => $dir, 'budgets' => ['requests' => ['limit' => 1000, 'window' => 60]],
            'challenge' => ['secret' => SECRET, 'searchEngines' => false, 'alwaysPaths' => ['#^/#'], 'alwaysMethods' => ['#^/#' => ['POST', 'DELETE']],
                'difficulty' => ['min' => 1000, 'max' => 1000]]], new MemoryStore());
        $run = static fn (Request $r, float $t): array => $shield->settle($shield->decide($r, $t), $r, $t);
        same(Decision::ALLOW, $run(creq('/contact'), 1.0)['decision']->action, 'the form page: no check');
        truthy($run(creq('/contact', [], 'PUT'), 1.0)['decision']->action !== Decision::CHALLENGE, 'a method the rule does not name: no check (here the site\'s methods refuse PUT anyway)');
        $post = $run(creq('/contact', [], 'POST'), 2.0);
        same([Decision::CHALLENGE, 'always'], [$post['decision']->action, $post['decision']->reason], 'the form sent: checked');
        truthy(is_string($post['page']) && strpos($post['page'], 'then what you entered is sent') !== false, '... and sent again after the check');
        same(Decision::CHALLENGE, $run(creq('/api/item/7', [], 'POST'), 2.0)['decision']->action, 'every path: an endpoint sent to as well');
        same('#^/#', $shield->settings->challenge->alwaysPaths[0]);
        truthy($shield->settings->challenge->alwaysFor('#^/#', 'POST') && !$shield->settings->challenge->alwaysFor('#^/#', 'GET'), 'alwaysFor: by method');
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $post['page'], $m);
        $solved = creq('/contact', ['rss' => solveInPhp(json_decode($m[1], true)['c'])], 'POST');
        $r = $run($solved, 3.0);
        $withPass = creq('/contact', ['rsp' => (string) cookieValue($r['cookies'], 'rsp')], 'POST');
        same(Decision::ALLOW_UNCACHED, $run($withPass, 4.0)['decision']->action, 'with the pass: the form arrives');
        exec('rm -rf ' . escapeshellarg($dir));
        try {
            new Shield(['challenge' => ['alwaysPaths' => ['#^/a#'], 'alwaysMethods' => ['#^/b#' => ['POST']]]], new MemoryStore());
            throw new TestFailure('methods for a path that is not checked: accepted');
        } catch (\InvalidArgumentException $e) {
            truthy(strpos($e->getMessage(), 'alwaysMethods') !== false, $e->getMessage());
        }
    },
    'RSF03-04 gate, asked for by the application: fresh passes, exempt paths do not count, a form comes back' => function (): void {
        $c = ChallengeSettings::from(['difficulty' => ['min' => 1000, 'max' => 3000], 'exemptPaths' => ['#^/api/#'], 'passTtl' => 3600]);
        $gate = new Gate($c, SECRET);
        $app = Decision::challenge('app');
        $base = Decision::allowUncached('app');
        // A pass issued at 1000 (valid until 4600).
        $r = $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/'), 1000.0);
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $r['page'], $m);
        $pass = cookieValue($gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/', ['rss' => solveInPhp(json_decode($m[1], true)['c'])]), 1000.0)['cookies'], 'rsp');
        same(Decision::ALLOW_UNCACHED, $gate->resolve($app, $base, creq('/x', ['rsp' => $pass]), 1200.0, ['forced' => true])['decision']->action, 'a pass is enough');
        same(Decision::ALLOW_UNCACHED, $gate->resolve($app, $base, creq('/x', ['rsp' => $pass]), 1200.0, ['forced' => true, 'fresh' => 300])['decision']->action, 'issued 200 s ago: fresh enough for 300');
        same(Decision::CHALLENGE, $gate->resolve($app, $base, creq('/x', ['rsp' => $pass]), 1400.0, ['forced' => true, 'fresh' => 300])['decision']->action, 'issued 400 s ago: not for 300');
        same(Decision::ALLOW, $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/api/x'), 1.0)['decision']->action, 'exempt path, budget');
        same(Decision::CHALLENGE, $gate->resolve($app, $base, creq('/api/x'), 1.0, ['forced' => true])['decision']->action, 'exempt path, asked for by the application: checked');
        // A POST with its form: the page carries it; its solution comes by POST.
        $r = $gate->resolve($app, $base, creq('/comment', [], 'POST'), 1.0, ['forced' => true, 'resend' => ['action' => '/comment?x=1', 'fields' => [['comment', '"hi"'], ['a[b]', '1']]]]);
        same(Decision::CHALLENGE, $r['decision']->action);
        truthy(strpos((string) $r['page'], '<form id="resend" method="post" action="/comment?x=1"><input type="hidden" name="comment" value="&quot;hi&quot;"><input type="hidden" name="a[b]" value="1">') !== false, (string) $r['page']);
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $r['page'], $m);
        $sol = solveInPhp(json_decode($m[1], true)['c']);
        same(Decision::ALLOW_UNCACHED, $gate->resolve($app, $base, creq('/comment', ['rss' => $sol], 'POST'), 2.0, ['forced' => true])['decision']->action, 'the form sent again, solved');
        same(Decision::THROTTLE, $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/comment', ['rss' => $sol], 'POST'), 2.0)['decision']->action, 'not asked for: a POST is still throttled');
        $lost = $gate->resolve($app, $base, creq('/upload', [], 'POST'), 1.0, ['forced' => true, 'resend' => false]);
        truthy(strpos((string) $lost['page'], 'Please go back and send the form again') !== false && strpos((string) $lost['page'], 'id="resend"') === false, 'a form that cannot come back: asked to send it again');
    },
    'RSF03-04 the fields that come back: as PHP read them; not with files, not too large' => function (): void {
        $fields = new ReflectionMethod(\CjwNetwork\RequestShield\Shield::class, 'resendFields');
        $fields->setAccessible(true);
        $req = creq('/comment?x=1', [], 'POST');
        [$post, $files] = [$_POST, $_FILES];
        try {
            $_POST = ['comment' => 'hi', 'tags' => ['a', 'b'], 'deep' => ['x' => ['y' => 'z']]];
            $_FILES = [];
            same(['action' => '/comment?x=1', 'fields' => [['comment', 'hi'], ['tags[0]', 'a'], ['tags[1]', 'b'], ['deep[x][y]', 'z']]], $fields->invoke(null, $req));
            $_FILES = ['upload' => ['name' => 'a.pdf', 'error' => UPLOAD_ERR_OK]];
            same(false, $fields->invoke(null, $req), 'a file cannot come back');
            $_FILES = ['upload' => ['name' => '', 'error' => UPLOAD_ERR_NO_FILE]];
            truthy(is_array($fields->invoke(null, $req)), 'an empty file field is fine');
            $_POST = ['text' => str_repeat('x', 300000)];
            same(false, $fields->invoke(null, $req), 'too large');
        } finally {
            [$_POST, $_FILES] = [$post, $files];
        }
    },
    'RSF03-03 the check inside the form: the answer from a form field, the task, the setting, the placeholder' => function (): void {
        $c = ChallengeSettings::from(['difficulty' => ['min' => 1000, 'max' => 3000], 'widgetPath' => '/request-shield', 'widgetDifficulty' => 2000]);
        $gate = new Gate($c, SECRET, null, 64, new \CjwNetwork\RequestShield\Store\MemoryStore());      // a store: an answer counts once
        $task = $gate->widgetTask(creq('/request-shield/challenge'), 1.0);
        truthy(is_array($task) && $task['maxnumber'] === 2000, 'a task of the widget\'s difficulty');
        $answer = solveInPhp($task);
        // ALTCHA's own widget sends standard base64, with padding: the same answer counts.
        $std = base64_encode((string) base64_decode(strtr($answer, '-_', '+/') . str_repeat('=', (4 - strlen($answer) % 4) % 4)));
        truthy((new \CjwNetwork\RequestShield\Challenge\ProofOfWork(SECRET))->verify($std, \CjwNetwork\RequestShield\IpAddress::bucket('203.0.113.7'), 2.0), 'an answer in ALTCHA\'s encoding verifies');
        $r = $gate->resolve(Decision::challenge('always'), Decision::allow(), creq('/login', [], 'POST'), 2.0, ['solution' => $answer]);
        same(Decision::ALLOW_UNCACHED, $r['decision']->action, 'a POST with the answer in the form: through');
        $pass = cookieValue($r['cookies'], 'rsp');
        truthy($pass !== null && $pass !== '', 'with a pass');
        same(Decision::THROTTLE, $gate->resolve(Decision::challenge('always'), Decision::allow(), creq('/login', [], 'POST'), 2.0, ['solution' => $answer])['decision']->action, 'the same answer twice: no');
        same(null, $gate->widgetTask(creq('/x', ['rsp' => $pass]), 3.0), 'with a pass: no task');
        same(2 + $c->passTtl, $gate->passUntil(creq('/x', ['rsp' => $pass]), 3.0), 'until when the pass holds');
        same(0, $gate->passUntil(creq('/x'), 3.0), 'without one: 0');
        truthy(is_array($gate->widgetTask(creq('/x', ['rsp' => $pass]), 2 + $c->passTtl - 20.0)), 'a pass about to run out: a task anyway');
        foreach (['request-shield', '/a b', '/x/../y"', '/', '/x/../y', '/..'] as $bad) {
            try {
                ChallengeSettings::from(['widgetPath' => $bad]);
                throw new TestFailure("accepted $bad");
            } catch (InvalidArgumentException $e) {
                truthy(strpos($e->getMessage(), 'challenge.widgetPath') !== false, $e->getMessage());
            }
        }
        same(null, ChallengeSettings::from([])->widgetPath, 'off by default');
        $shield = new \CjwNetwork\RequestShield\Shield([], new \CjwNetwork\RequestShield\Store\MemoryStore());
        same('', $shield->widget(), 'off: no placeholder');
        $on = new \CjwNetwork\RequestShield\Shield(['challenge' => ['widgetPath' => '/rs']], new \CjwNetwork\RequestShield\Store\MemoryStore());
        same([false, true, false], [$shield->hasWidget(), $on->hasWidget(),
            (new \CjwNetwork\RequestShield\Shield(['challenge' => ['widgetPath' => '/rs'], 'mode' => 'off'], new \CjwNetwork\RequestShield\Store\MemoryStore()))->hasWidget()],
            'hasWidget(): off, on, on but the shield off');
        $first = $on->widget();       // after hasWidget(): the script still comes with the first placeholder
        $second = $on->widget('load');
        truthy(substr_count($first . $second, '<script') === 1, 'the script once per page');
        truthy(strpos($second, 'data-start="load"') !== false, 'the start option');
        $node = nodeBinary();
        if ($node !== null) {
            $f = sys_get_temp_dir() . '/rshield-widget-' . getmypid() . '.js';
            file_put_contents($f, \CjwNetwork\RequestShield\Challenge\Widget::script());
            exec(escapeshellarg($node) . ' --check ' . escapeshellarg($f) . ' 2>&1', $out, $code);
            unlink($f);
            same(0, $code, 'widget.js is valid JavaScript: ' . implode("\n", $out));
        }
    },
    'RSF03-01 a spent budget: no pass gets past it, only its own solution -- which starts the counter again, twice as hard each time' => function (): void {
        $store = new \CjwNetwork\RequestShield\Store\MemoryStore();
        $c = ChallengeSettings::from(['difficulty' => ['min' => 1000, 'max' => 5000], 'exemptPaths' => ['#^/api/#']]);
        $gate = new Gate($c, SECRET, null, 64, $store);
        $bucket = \CjwNetwork\RequestShield\IpAddress::bucket('203.0.113.7');
        $spent = Decision::spent('posts', 30);
        $earn = ['earn' => ['window' => 60]];
        // a pass from an ordinary check
        $r = $gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/'), 1.0);
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $r['page'], $m);
        $plain = solveInPhp(json_decode($m[1], true)['c']);
        $pass = cookieValue($gate->resolve(Decision::challenge('requests'), Decision::allow(), creq('/', ['rss' => $plain]), 1.0)['cookies'], 'rsp');
        same(Decision::CHALLENGE, $gate->resolve($spent, Decision::allow(), creq('/x', ['rsp' => $pass]), 2.0, $earn)['decision']->action, 'a pass does not get past a spent budget');
        same(Decision::CHALLENGE, $gate->resolve($spent, Decision::allow(), creq('/api/x'), 2.0, $earn)['decision']->action, 'nor an exempt path');
        // its own task, bound to it
        for ($i = 0; $i < 5; $i++) {
            $store->hit('posts:' . $bucket, 60, 3.0);
        }
        $r = $gate->resolve($spent, Decision::allow(), creq('/x'), 3.0, $earn);
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $r['page'], $m);
        $task = json_decode($m[1], true)['c'];
        same(1000, $task['maxnumber'], 'the first time: difficulty-min');
        truthy(strpos($task['salt'], '&b=posts') !== false, 'bound to the budget');
        $other = (new \CjwNetwork\RequestShield\Challenge\ProofOfWork(SECRET))->create($bucket, 1000, 100, 'searches');
        same(Decision::CHALLENGE, $gate->resolve($spent, Decision::allow(), creq('/x', ['rss' => solveInPhp($other)]), 3.0, $earn)['decision']->action, 'another budget\'s solution does not count');
        $plain2 = (new \CjwNetwork\RequestShield\Challenge\ProofOfWork(SECRET))->create($bucket, 1000, 100);
        same(Decision::CHALLENGE, $gate->resolve($spent, Decision::allow(), creq('/x', ['rss' => solveInPhp($plain2)]), 3.0, $earn)['decision']->action, 'nor an ordinary one');
        $r = $gate->resolve($spent, Decision::allow(), creq('/x', ['rss' => solveInPhp($task)]), 4.0, $earn);
        same(Decision::ALLOW_UNCACHED, $r['decision']->action, 'its own solution: through');
        same(0.0, $store->peek('posts:' . $bucket, 60, 4.0), 'and the counter starts again');
        // A budget written in a site block (rules per website): its own counter, "<site>@<name>".
        $siteStore = new \CjwNetwork\RequestShield\Store\MemoryStore();
        $siteGate = new Gate($c, SECRET, null, 64, $siteStore);
        for ($i = 0; $i < 5; $i++) {
            $siteStore->hit('a.de@posts:' . $bucket, 60, 3.0);
            $siteStore->hit('posts:' . $bucket, 60, 3.0);
        }
        $siteEarn = ['earn' => ['window' => 60, 'counter' => 'a.de@posts']];
        $r = $siteGate->resolve($spent, Decision::allow(), creq('/x'), 3.0, $siteEarn);
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $r['page'], $m);
        same(Decision::ALLOW_UNCACHED, $siteGate->resolve($spent, Decision::allow(), creq('/x', ['rss' => solveInPhp(json_decode($m[1], true)['c'])]), 4.0, $siteEarn)['decision']->action, 'a site\'s budget: its own solution, through');
        same([0.0, 5.0, 1.0], [$siteStore->peek('a.de@posts:' . $bucket, 60, 4.0), $siteStore->peek('posts:' . $bucket, 60, 4.0), $siteStore->peek('solved:a.de@posts:' . $bucket, 3600, 4.0)],
            'the site\'s counter starts again, the same name elsewhere untouched; its solves counted under its own name');
        $r = $gate->resolve($spent, Decision::allow(), creq('/x'), 5.0, $earn);
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $r['page'], $m);
        same(2000, json_decode($m[1], true)['c']['maxnumber'], 'the second time within the hour: twice as hard');
        for ($i = 0; $i < 5; $i++) {
            $store->hit('solved:posts:' . $bucket, 3600, 6.0);
        }
        $r = $gate->resolve($spent, Decision::allow(), creq('/x'), 6.0, $earn);
        preg_match('/var RS=(\{.*?\});\(function/s', (string) $r['page'], $m);
        same(5000, json_decode($m[1], true)['c']['maxnumber'], 'at most difficulty-max');
        // an API: the task as JSON; a POST without its form: a pause
        $api = $gate->resolve($spent, Decision::allow(), creq('/x', [], 'POST'), 7.0, $earn + ['api' => true]);
        same([null, true], [$api['page'], is_array($api['json'])], 'an API gets the task as JSON');
        same(Decision::THROTTLE, $gate->resolve($spent, Decision::allow(), creq('/x', [], 'POST'), 7.0, $earn)['decision']->action, 'a POST whose form cannot come back: a pause');
        same(30, $gate->resolve($spent, Decision::allow(), creq('/x', [], 'POST'), 7.0, $earn)['decision']->retryAfter, 'as long as the budget says');
    },
    'RSF03-01 decisions: a spent budget outranks a plain check; the budget rule gives it only when asked' => function (): void {
        same(true, Decision::challenge('requests')->stricter(Decision::spent('posts', 5))->spent);
        same(true, Decision::spent('posts', 5)->stricter(Decision::challenge('requests'))->spent);
        same(Decision::THROTTLE, Decision::spent('posts', 5)->stricter(Decision::throttle('x', 5))->action);
        $store = new \CjwNetwork\RequestShield\Store\MemoryStore();
        $pause = new \CjwNetwork\RequestShield\Rule\BudgetRule($store, 'a', 2, 60);
        $earn = new \CjwNetwork\RequestShield\Rule\BudgetRule($store, 'b', 2, 60, null, [], 64, true);
        $req = creq('/');
        for ($i = 0; $i < 2; $i++) {
            $pause->check($req, 1.0);
            $earn->check($req, 1.0);
        }
        same(Decision::THROTTLE, $pause->check($req, 1.0)->action, 'by default a pause');
        truthy($earn->check($req, 1.0)->spent, 'on-exceeded challenge: the check that frees the counter');
    },
    'RSF03-01 stores: reset forgets a key\'s count' => function (): void {
        $dir = sys_get_temp_dir() . '/rshield-reset-' . getmypid() . '-' . mt_rand();
        $stores = ['memory' => new \CjwNetwork\RequestShield\Store\MemoryStore(), 'file' => new \CjwNetwork\RequestShield\Store\FileStore($dir, 0.0)];
        if (\CjwNetwork\RequestShield\Store\ApcuStore::usable()) {
            $stores['apcu'] = new \CjwNetwork\RequestShield\Store\ApcuStore('rshield-test-' . mt_rand() . ':');
        }
        foreach ($stores as $name => $store) {
            $store->hit('k', 60, 119.0);
            $store->hit('k', 60, 121.0);
            $store->hit('other', 60, 121.0);
            $store->reset('k', 60, 121.0);
            same(0.0, $store->peek('k', 60, 121.0), "$name: this window and the one before");
            same(1.0, $store->peek('other', 60, 121.0), "$name: other keys stay");
        }
        exec('rm -rf ' . escapeshellarg($dir));
    },
    'RSF01-04 DNS lookups for search engines: at most so many a minute -- a flood of fake crawlers does not wait for DNS' => function (): void {
        $calls = 0;
        // DNS that does not answer (a DMZ): every lookup waits, then fails.
        $slow = function (string $ip) use (&$calls) { $calls++; usleep(20000); return false; };
        $cache = [];
        $get = function ($k) use (&$cache) { return $cache[$k] ?? null; };
        $set = function ($k, $v) use (&$cache) { $cache[$k] = $v; };
        $flood = function (?\Closure $guard) use ($slow, $get, $set, &$calls, &$cache): array {
            [$calls, $cache] = [0, []];
            $se = new SearchEngines(SearchEngines::defaults(), $get, $set, $slow, null, $guard);
            $t = microtime(true);
            for ($i = 1; $i <= 50; $i++) {
                truthy(!$se->verified("198.51.100.$i", 'Mozilla/5.0 (compatible; Googlebot/2.1)'), 'a fake crawler is never verified');
            }
            return [$calls, microtime(true) - $t];
        };
        [$without, $slowTime] = $flood(null);
        same(50, $without, 'without the guard: 50 fake crawlers, 50 lookups');
        $store = new \CjwNetwork\RequestShield\Store\MemoryStore();
        [$with, $fastTime] = $flood(function () use ($store): bool { return $store->hit('se-lookups', 60, 1000.0) <= 5; });
        same(5, $with, 'with it: 5 lookups, the rest refused at once');
        truthy($fastTime < $slowTime / 5, sprintf('and fast: %.2f s instead of %.2f s', $fastTime, $slowTime));
        // Past the budget nothing is remembered: a real crawler is known again later.
        $real = new SearchEngines(SearchEngines::defaults(), $get, $set,
            fn (string $ip) => 'crawl-66-249-66-1.googlebot.com', fn (string $h) => ['66.249.66.1'], fn (): bool => false);
        same(false, $real->verified('66.249.66.1', 'Googlebot/2.1'), 'no lookups left: not verified');
        same(null, $cache['se:66.249.66.1'] ?? null, 'and not remembered');
        $later = new SearchEngines(SearchEngines::defaults(), $get, $set,
            fn (string $ip) => 'crawl-66-249-66-1.googlebot.com', fn (string $h) => ['66.249.66.1'], fn (): bool => true);
        same(true, $later->verified('66.249.66.1', 'Googlebot/2.1'), 'a minute later: verified');
        same(30, ChallengeSettings::from([])->dnsLookups, 'the default: 30 a minute');
        same(0, ChallengeSettings::from(['dnsLookups' => 0])->dnsLookups, '0: none (a DMZ without DNS)');
    },
];
