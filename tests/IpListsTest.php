<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\IpTable;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Rules\Lists;
use CjwNetwork\RequestShield\Rules\RuleFile;
use CjwNetwork\RequestShield\Rules\RuleFileException;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Shield;
use CjwNetwork\RequestShield\Store\ApcuStore;
use CjwNetwork\RequestShield\Store\FileStore;
use CjwNetwork\RequestShield\Store\MemoryStore;

/** IP lists and automatic bans (proposal 0013). */

function listsDir(): string
{
    $dir = sys_get_temp_dir() . '/rs-lists-' . getmypid() . '-' . mt_rand();
    mkdir($dir, 0700, true);
    return $dir;
}

function listsSettings(string $dir, string $rules): Settings
{
    file_put_contents("$dir/site.rules", "set store-dir $dir/store\n" . $rules);
    return Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
}

function listsReq(string $uri, string $ip = '203.0.113.9', string $method = 'GET', string $ua = 'Mozilla/5.0 Firefox/136.0', string $host = 'www.example.org'): Request
{
    return Request::fromServer(['REQUEST_URI' => $uri, 'REQUEST_METHOD' => $method, 'HTTP_HOST' => $host, 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => $ua]);
}

/** decide(), settle(), and what protect() does after: the signals for the bans. */
function listsRun(Shield $shield, Request $r, float $now): Decision
{
    $d = $shield->settle($shield->decide($r, $now), $r, $now)['decision'];
    $m = new ReflectionMethod(Shield::class, 'signals');
    $m->setAccessible(true);                                    // PHP 8.0
    $m->invoke($shield, $d, $r, $now);
    return $d;
}

return [
    'RSF01-02 the store remembers until when: mark() and marked() -- memory, files, APCu' => function (): void {
        $dir = listsDir();
        try {
            $stores = ['memory' => new MemoryStore(), 'files' => new FileStore("$dir/files")];
            if (ApcuStore::usable()) {
                $stores['apcu'] = new ApcuStore('rshield-test-' . mt_rand() . ':');
            }
            foreach ($stores as $name => $store) {
                same(0, $store->marked('ban:x', 1000.0), "$name: nothing yet");
                $store->mark('ban:x', 1060, 1000.0);
                $store->mark('other:x', 1060, 1000.0);
                same(['ban:x' => 1060], $store->marks('ban:', 1000.0), "$name: listed by prefix, while marked");
                same([1060, 1060, 0], [$store->marked('ban:x', 1000.0), $store->marked('ban:x', 1059.0), $store->marked('ban:x', 1060.0)], "$name: until then, not after");
                same([], $store->marks('ban:', 1060.0), "$name: not listed after");
                $store->mark('ban:y', 2000, 1000.0);
                $store->mark('ban:y', 0, 1000.0);
                same(0, $store->marked('ban:y', 1000.0), "$name: 0 forgets at once");
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 rule files: deny [until], exempt until, ban, the list files (only list lines) -- mistakes name their line' => function (): void {
        $dir = listsDir();
        try {
            $tomorrow = date('Y-m-d', time() + 86400);
            $s = listsSettings($dir, "[SITE-D1] deny 203.0.113.7 198.51.100.0/24 until $tomorrow\n[SITE-D2] deny 2001:db8::/48\ndeny 192.0.2.66 until 2020-01-01\n"
                . "exempt 192.0.2.50 until {$tomorrow}T12:00\nexempt 192.0.2.51 until 2020-01-01\n"
                . "[SITE-BAN] ban after 20 refusals in 5m for 1h\nset ban-growth 3\nset ban-max 12h\n");
            same([['203.0.113.7', '198.51.100.0/24'], ['2001:db8::/48']], array_column($s->deny, 'ips'), 'in force; the one that ended left out');
            same(['SITE-D1', 'SITE-D2'], array_column($s->deny, 'rule'), 'with their IDs');
            truthy(in_array('192.0.2.50', $s->exemptIps, true) && !in_array('192.0.2.51', $s->exemptIps, true), 'exempt until: in force, or left out');
            same((int) mktime(12, 0, 0, (int) date('m', time() + 86400), (int) date('d', time() + 86400), (int) date('Y', time() + 86400)), $s->listsUntil, 'the next end: when the settings are built again');
            same([['after' => 20, 'signal' => 'refusals', 'in' => 300, 'for' => 3600, 'rule' => 'SITE-BAN']], $s->bans, 'a ban');
            same([3, 43200, "$dir/store/lists"], [$s->banGrowth, $s->banMax, $s->listsDir], 'its settings; the lists in store-dir');
            $cases = [
                "deny 203.0.113.7 until tomorrow\n" => 'until takes a day',
                "deny until 2030-01-01 203.0.113.7\n" => 'until and its time come last',
                "deny not-an-address\n" => 'is not an address',
                "ban after 5 refusals in 5m\n" => 'ban after <n>',
                "ban after 5 logins in 5m for 1h\n" => 'there is no budget "logins"',
                "site a.de {\n  set ban-max 1h\n}\n" => 'is about the server',
                "site a.de {\n  [X] ban after 3 refusals in 5m for 1h\n}\n" => 'ban is about the server',
            ];
            foreach ($cases as $text => $says) {
                file_put_contents("$dir/bad.rules", "set store-dir $dir/store\n" . $text);
                try {
                    Settings::from(RuleFile::read(["$dir/bad.rules"], strpos($text, 'site ') === 0 ? 'a.de' : null)['config']);
                    throw new TestFailure('accepted: ' . json_encode($text));
                } catch (RuleFileException | InvalidArgumentException $e) {
                    truthy(strpos($e->getMessage(), $says) !== false, $e->getMessage());
                }
            }
            // The list files: read after the rule files; only deny and exempt lines.
            mkdir("$dir/store/lists", 0750, true);
            file_put_contents("$dir/store/lists/deny.rules", "[LIST-D1] deny 203.0.113.99   # scraper · cli\n");
            file_put_contents("$dir/store/lists/allow.rules", "[LIST-A1] exempt 192.0.2.77 until $tomorrow\n");
            $l = listsSettings($dir, "");
            same(['LIST-D1'], array_column($l->deny, 'rule'), 'the deny list file');
            truthy(in_array('192.0.2.77', $l->exemptIps, true), 'the allow list file');
            file_put_contents("$dir/store/lists/deny.rules", "[LIST-D1] deny 203.0.113.99\nblock **/x/**\n");
            try {
                listsSettings($dir, "");
                throw new TestFailure('a list file took a rule');
            } catch (RuleFileException $e) {
                truthy(strpos($e->getMessage(), 'deny.rules:2: a list file holds only deny and exempt lines') !== false, $e->getMessage());
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 the table: ranges and single addresses, IPv4 and IPv6, edges, overlaps -- the same answers as the range check, at random' => function (): void {
        $t = IpTable::build([[['203.0.113.0/24', '192.0.2.7'], 'A'], [['2001:db8::/48'], 'B'], [['198.51.100.0/22'], 'C'], [['198.51.101.0/24'], 'D']]);
        same(['A', 'A', 'A', 'B', 'B', null, null], [IpTable::find('203.0.113.0', $t), IpTable::find('203.0.113.255', $t), IpTable::find('192.0.2.7', $t),
            IpTable::find('2001:db8::1', $t), IpTable::find('2001:db8:0:ffff:ffff:ffff:ffff:ffff', $t), IpTable::find('2001:db9::', $t), IpTable::find('nonsense', $t)], 'edges of each range');
        same([null, 'W'], [IpTable::find('192.0.2.8', $t), IpTable::find('192.0.2.8', IpTable::build([[['0.0.0.0/0'], 'W']]))], 'next to an entry: nothing; everything: the widest range');
        same('C', IpTable::find('198.51.101.9', $t), 'overlapping ranges merged: the ID of the one that starts first (C)');
        mt_srand(7);
        $entries = [];
        $ranges = [];
        for ($i = 0; $i < 3000; $i++) {
            $r = mt_rand(1, 223) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . ['', '/24', '/20', '/32'][mt_rand(0, 3)];
            $entries[] = [[$r], "R$i"];
            $ranges[] = $r;
        }
        $t = IpTable::build($entries);
        for ($i = 0; $i < 3000; $i++) {
            $ip = $i % 3 === 0 ? (string) preg_replace('#/.*#', '', $ranges[$i]) : mt_rand(1, 223) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255) . '.' . mt_rand(0, 255);
            same(\CjwNetwork\RequestShield\IpAddress::inRanges($ip, $ranges), IpTable::find($ip, $t) !== null, "$ip: as the range check says");
        }
        same(['4' => '', '6' => '', 'ids' => ''], IpTable::build([]), 'nothing');
    },
    'RSF01-02 kept out: 403 before every other check, named by its entry -- thousands of entries, about as quick' => function (): void {
        $dir = listsDir();
        try {
            $s = listsSettings($dir, "[SITE-D1] deny 203.0.113.0/24\n");
            $shield = new Shield($s, new MemoryStore());
            $r = listsReq('/', '203.0.113.9', 'TRACE');
            $d = $shield->decide($r, 1000.0);
            same(['reject', 403, 'denied', 'SITE-D1'], [$d->action, $d->status, $d->reason, $shield->explain($d, $r)], 'before the method (TRACE would be 405)');
            same('allow', $shield->decide(listsReq('/', '203.0.114.9'), 1000.0)->action, 'the next network: through');
            $many = '';
            for ($i = 0; $i < 5000; $i++) {
                $many .= 'deny 10.' . intdiv($i, 250) . '.' . ($i % 250) . ".0/24\n";
            }
            $big = new Shield(listsSettings($dir, $many), new MemoryStore());
            same(['reject', 'allow'], [$big->decide(listsReq('/', '10.19.249.7'), 1000.0)->action, $big->decide(listsReq('/', '10.20.0.7'), 1000.0)->action], '5,000 ranges: the last one, and one outside');
            $rule = new \CjwNetwork\RequestShield\Rule\DenyRule($big->settings->denyTable);
            $hit = listsReq('/', '10.19.249.7');
            $t = hrtime(true);
            for ($i = 0; $i < 2000; $i++) {
                $rule->check($hit, 1000.0);
            }
            $us = (hrtime(true) - $t) / 1e3 / 2000;
            truthy($us < 200, sprintf('a lookup in 5,000 ranges stays in microseconds: %.1f µs', $us));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 let in (exempt): never counted, never checked -- still refused for what only attackers ask for' => function (): void {
        $dir = listsDir();
        try {
            $s = listsSettings($dir, "exempt 192.0.2.50\nchallenge **/login\n");
            $shield = new Shield($s, new MemoryStore());
            same(['allow', 'challenge'], [$shield->decide(listsReq('/login', '192.0.2.50'), 1000.0)->action, $shield->decide(listsReq('/login', '192.0.2.51'), 1000.0)->action], 'the always-checked page: not for an address let in');
            same('reject', $shield->decide(listsReq('/.env', '192.0.2.50'), 1000.0)->action, 'a blocked address: refused all the same');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 bans: after the signals, nothing but 429 -- longer each time, at most ban-max; never exempt, a trusted proxy or a verified crawler' => function (): void {
        $dir = listsDir();
        try {
            $s = listsSettings($dir, "exempt 192.0.2.50\ntrust 192.0.2.1\nset ban-growth 2\nset ban-max 25m\n[SITE-SCAN] ban after 3 refusals in 5m for 10m\n");
            $store = new MemoryStore();
            $shield = new Shield($s, $store);
            $ip = '203.0.113.9';
            $now = 10000.0;
            foreach ([1, 2] as $i) {
                listsRun($shield, listsReq('/.env', $ip), $now + $i);
            }
            same('allow', listsRun($shield, listsReq('/', $ip), $now + 3)->action, 'two refusals: not yet');
            listsRun($shield, listsReq('/.git/config', $ip), $now + 4);
            $d = listsRun($shield, listsReq('/', $ip), $now + 5);
            same(['throttle', 429, 'banned', 599], [$d->action, $d->status, $d->reason, $d->retryAfter], 'the third: banned for 10 minutes, any page');
            same(0, $store->marked('ban:' . $ip, $now + 605), 'and it ends by itself');
            foreach ([1, 2, 3] as $i) {
                listsRun($shield, listsReq('/.env', $ip), $now + 700 + $i);
            }
            same(1200, $store->marked('ban:' . $ip, $now + 704) - (int) ($now + 703), 'again within a day: twice as long');
            foreach ([1, 2, 3] as $i) {
                listsRun($shield, listsReq('/.env', $ip), $now + 2000 + $i);
            }
            same(1500, $store->marked('ban:' . $ip, $now + 2004) - (int) ($now + 2003), 'at most ban-max (25 minutes)');
            foreach (['192.0.2.50' => 'an address let in', '192.0.2.1' => 'a trusted proxy'] as $never => $what) {
                foreach ([1, 2, 3, 4] as $i) {
                    listsRun($shield, listsReq('/.env', $never), $now + $i);
                }
                same(0, $store->marked('ban:' . $never, $now + 5), "never banned: $what");
            }
            $claude = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)';
            foreach ([1, 2, 3, 4] as $i) {
                listsRun($shield, listsReq('/.env', '216.73.216.5', 'GET', $claude), $now + $i);
            }
            same(0, $store->marked('ban:216.73.216.5', $now + 5), 'never banned: a verified crawler');
            foreach ([1, 2, 3] as $i) {
                listsRun($shield, listsReq('/.env', '198.51.100.20', 'GET', $claude), $now + $i);
            }
            truthy($store->marked('ban:198.51.100.20', $now + 4) > 0, 'one that only borrows a crawler\'s name: banned');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 bans: a refusal the client did not choose -- a page\'s own request, a visitor sent by another website -- is counted against ten times the number; below /.well-known/ never' => function (): void {
        $dir = listsDir();
        try {
            $s = listsSettings($dir, "include @attacks\n[SITE-SCAN] ban after 3 refusals in 5m for 10m\n");
            $store = new MemoryStore();
            $shield = new Shield($s, $store);
            $now = 20000.0;
            // Five refusals from one address with these headers; what the last one got, and whether the address is banned after.
            $five = static function (string $uri, string $ip, array $headers) use ($shield, $store, $now): array {
                $d = null;
                foreach ([1, 2, 3, 4, 5] as $i) {
                    $d = listsRun($shield, Request::fromServer($headers + ['REQUEST_URI' => $uri, 'REQUEST_METHOD' => 'GET',
                        'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/136.0']), $now + $i);
                }
                return [$d !== null ? $d->action : '', $d !== null ? $d->status : 0, $store->marked('ban:' . $ip, $now + 6) > 0];
            };
            // <img src="https://www.example.org/.env"> on another website: the visitor's browser asks, the visitor did not.
            same(['reject', 404, false], $five('/.env', '203.0.113.21', ['HTTP_SEC_FETCH_MODE' => 'no-cors', 'HTTP_SEC_FETCH_SITE' => 'cross-site', 'HTTP_SEC_FETCH_DEST' => 'image']),
                'an image a foreign page embeds: refused, the visitor not banned for five');
            same(['reject', 404, false], $five('/old/backup.zip', '203.0.113.22', ['HTTP_SEC_FETCH_MODE' => 'no-cors', 'HTTP_SEC_FETCH_SITE' => 'same-origin']),
                'a stale image link on the site\'s own page: not the visitor\'s doing either');
            same(['reject', 403, false], $five('/?q=%3Cscript%3Ealert(1)%3C/script%3E', '203.0.113.23', ['HTTP_SEC_FETCH_MODE' => 'cors', 'HTTP_SEC_FETCH_SITE' => 'cross-site']),
                'a fetch() with an attack pattern from a foreign page: refused, not counted');
            same(['reject', 404, false], $five('/.git/config', '203.0.113.24', ['HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_SEC_FETCH_SITE' => 'cross-site']),
                'a link on another website to an address refused here: whoever follows it is not banned');
            same(['reject', 404, false], $five('/.git/config', '203.0.113.25', ['HTTP_SEC_FETCH_MODE' => 'Navigate', 'HTTP_SEC_FETCH_SITE' => ' Cross-Site ']),
                'the header values in any case, with spaces');
            // Chrome's prefetch proxy, iOS, Android and password managers ask below /.well-known/ unprompted.
            same(['reject', 404, false], $five('/.well-known/traffic-advice', '203.0.113.26', []), 'below /.well-known/: refused (SCAN-CGI), not counted');
            same(['reject', 404, false], $five('//.well-known/%61pple-app-site-association', '203.0.113.27', []), '... however the path is written');
            // What a person or a tool chose to ask for counts as before.
            same(['throttle', 429, true], $five('/.env', '203.0.113.31', []), 'no Sec-Fetch headers (a scanner, an old browser): counted, banned');
            same(['throttle', 429, true], $five('/.env', '203.0.113.32', ['HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_SEC_FETCH_SITE' => 'none']),
                'typed into the address bar: counted');
            same(['throttle', 429, true], $five('/.env', '203.0.113.33', ['HTTP_SEC_FETCH_MODE' => 'navigate', 'HTTP_SEC_FETCH_SITE' => 'same-origin']),
                'a navigation within the site: counted');
            same(['throttle', 429, true], $five('/shop/.well-known/x', '203.0.113.34', []), '.well-known is the root\'s only (RFC 8615): elsewhere counted');
            same(['throttle', 429, true], $five('/.well-known.bak', '203.0.113.35', []), 'a name that only starts like it: counted');
            same(['throttle', 429, true], $five('/.well-known/security.txt?q=%3Cscript%3Ealert(1)%3C/script%3E', '203.0.113.36', []),
                'an attack pattern sent below /.well-known/: counted like anywhere else');
            same([400, false], array_slice($five('/.well-known/../.env', '203.0.113.37', []), 1), 'no way out of it with "/../": a broken request (400), not this rule\'s');
            // The uncounted ones do not add up with the counted ones.
            $ip = '203.0.113.41';
            $plain = ['REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/136.0'];
            listsRun($shield, Request::fromServer($plain + ['REQUEST_URI' => '/.env']), $now + 1);
            listsRun($shield, Request::fromServer($plain + ['REQUEST_URI' => '/.git/config']), $now + 2);
            foreach ([3, 4, 5, 6] as $i) {
                listsRun($shield, Request::fromServer($plain + ['REQUEST_URI' => '/.env', 'HTTP_SEC_FETCH_MODE' => 'no-cors']), $now + $i);
            }
            same(0, $store->marked('ban:' . $ip, $now + 7), 'two counted and four uncounted refusals: not banned');
            listsRun($shield, Request::fromServer($plain + ['REQUEST_URI' => '/backup.sql']), $now + 8);
            truthy($store->marked('ban:' . $ip, $now + 9) > 0, 'the third counted one: banned');
            // A scanner forging the headers to dodge the ban: banned all the same, after ten times as many.
            $ip = '203.0.113.51';
            $forged = ['REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/136.0',
                'REQUEST_URI' => '/.env', 'HTTP_SEC_FETCH_MODE' => 'no-cors', 'HTTP_SEC_FETCH_SITE' => 'cross-site'];
            $limit = 3 * Shield::UNASKED_REFUSALS;
            for ($i = 1; $i < $limit; $i++) {
                listsRun($shield, Request::fromServer($forged), $now + $i);
            }
            same(0, $store->marked('ban:' . $ip, $now + $limit), ($limit - 1) . ' unasked refusals: not yet banned');
            listsRun($shield, Request::fromServer($forged), $now + $limit);
            truthy($store->marked('ban:' . $ip, $now + $limit + 1) > 0, "the {$limit}th: banned");
            // Below /.well-known/ never, however many.
            $ip = '203.0.113.52';
            for ($i = 1; $i <= $limit + 5; $i++) {
                listsRun($shield, Request::fromServer(['REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => $ip,
                    'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/136.0', 'REQUEST_URI' => '/.well-known/traffic-advice']), $now + $i);
            }
            same(0, $store->marked('ban:' . $ip, $now + $limit + 6), 'below /.well-known/: never counted');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 bans: the signals -- past a limit, a check page not solved, a budget the site counts; one ban for every website' => function (): void {
        $dir = listsDir();
        try {
            $s = listsSettings($dir, "set secret " . str_repeat('k', 40) . "\n[SITE-PACE] limit requests 2/min\n[SITE-LOGINS] limit logins 2/min on-demand\n"
                . "[B-LIM] ban after 2 limits in 5m for 10m\n[B-LOGIN] ban after 2 logins in 5m for 30m\n"
                . "site a.de {\n  challenge **/login\n}\nsite b.de {\n}\n");
            $store = new MemoryStore();
            $shield = new Shield($s, $store);
            foreach ([1, 2, 3, 4] as $i) {
                listsRun($shield, listsReq('/', '203.0.113.1'), 1000.0 + $i);           // 3rd and 4th: past the limit
            }
            truthy($store->marked('ban:203.0.113.1', 1005.0) > 0, 'past a limit twice: banned');
            foreach ([1, 2, 3, 4] as $i) {
                $shield->consume('logins', listsReq('/login', '203.0.113.2'), 2000.0 + $i);
            }
            same(1800, $store->marked('ban:203.0.113.2', 2005.0) - 2004, 'a budget the site counts (failed sign-ins), past its limit twice: its ban');
            // One ban for every website: banned on a.de, refused on b.de.
            $siteA = Settings::from(RuleFile::read(["$dir/site.rules"], 'a.de')['config']);
            $siteB = Settings::from(RuleFile::read(["$dir/site.rules"], 'b.de')['config']);
            $checks = listsSettings($dir, "set secret " . str_repeat('k', 40) . "\n[B-POW] ban after 3 checks in 5m for 10m\nsite a.de {\n  challenge **/login\n}\nsite b.de {\n}\n");
            $a = new Shield(Settings::from(RuleFile::read(["$dir/site.rules"], 'a.de')['config']), $store);
            foreach ([1, 2, 3] as $i) {
                listsRun($a, listsReq('/login', '203.0.113.3', 'GET', 'Mozilla/5.0 Firefox/136.0', 'a.de'), 3000.0 + $i);
            }
            $b = new Shield(Settings::from(RuleFile::read(["$dir/site.rules"], 'b.de')['config']), $store);
            same(['throttle', 'banned'], [($d = $b->decide(listsReq('/', '203.0.113.3', 'GET', 'Mozilla/5.0 Firefox/136.0', 'b.de'), 3004.0))->action, $d->reason],
                'three check pages on a.de, never solved: banned on b.de too');
            truthy($siteA->bans !== [] && $siteB->bans !== [] && $checks->bans !== [], 'the base\'s bans in every website\'s settings');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 watched first: "monitor ban" and mode monitor ban nobody and write monitor-ban to the log' => function (): void {
        $dir = listsDir();
        try {
            foreach (["set log $dir/a.log\nset log-level all\n[W-SCAN] monitor ban after 2 refusals in 5m for 10m\n" => "$dir/a.log",
                "set log $dir/b.log\nset log-level all\nset mode monitor\n[M-SCAN] ban after 2 refusals in 5m for 10m\n" => "$dir/b.log"] as $rules => $log) {
                $store = new MemoryStore();
                $shield = new Shield(listsSettings($dir, $rules), $store);
                foreach ([1, 2, 3] as $i) {
                    listsRun($shield, listsReq('/.env', '203.0.113.4'), 1000.0 + $i);
                }
                same(0, $store->marked('ban:203.0.113.4', 1004.0), 'nobody banned');
                truthy(strpos((string) @file_get_contents($log), 'monitor-throttle 429 "banned"') !== false, 'the log says whom it would have banned: ' . @file_get_contents($log));
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 the compiled settings are built again when a list entry ends' => function (): void {
        $dir = listsDir();
        try {
            file_put_contents("$dir/site.rules", "set store-dir $dir/store\ndeny 203.0.113.7 until " . date('Y-m-d', time() + 86400) . "\n");
            Settings::load("$dir/site.rules", "$dir/cache");
            $files = glob("$dir/cache/settings-*.php") ?: [];
            same(1, count($files), 'compiled');
            $e = require $files[0];
            $e['settings']['listsUntil'] = time() - 1;                      // as if the entry had just ended
            $e['settings']['deny'] = [];
            file_put_contents($files[0], '<?php return ' . var_export($e, true) . ";\n");
            if (function_exists('opcache_invalidate')) {
                @opcache_invalidate($files[0], true);
            }
            same(1, count(Settings::load("$dir/site.rules", "$dir/cache")->deny), 'an entry ended: built again from the files (here: the entry still in force)');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 while one request rebuilds the settings, the others keep the last ones -- no stampede' => function (): void {
        $dir = listsDir();
        try {
            file_put_contents("$dir/site.rules", "set store-dir $dir/store\ndeny 203.0.113.7 until " . date('Y-m-d', time() + 86400) . "\n");
            Settings::load("$dir/site.rules", "$dir/cache");
            $file = (glob("$dir/cache/settings-*.php") ?: [])[0];
            $e = require $file;
            $e['settings']['listsUntil'] = time() - 1;                      // to be rebuilt
            $e['settings']['denyCount'] = 0;
            file_put_contents($file, '<?php return ' . var_export($e, true) . ";\n");
            if (function_exists('opcache_invalidate')) {
                @opcache_invalidate($file, true);
            }
            $lock = fopen(str_replace('.php', '.lock', $file), 'c');
            truthy($lock !== false && flock($lock, LOCK_EX | LOCK_NB), 'the test holds the lock');
            same(0, Settings::load("$dir/site.rules", "$dir/cache")->denyCount, 'being built elsewhere: the last settings');
            flock($lock, LOCK_UN);
            fclose($lock);
            same(1, Settings::load("$dir/site.rules", "$dir/cache")->denyCount, 'then built');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 a big list file: the fast path and the usual one side by side, mistakes named by their line; the compiled settings stay small' => function (): void {
        $dir = listsDir();
        try {
            mkdir("$dir/store/lists", 0750, true);
            $lines = ['# kept by the command line', '', 'deny 192.0.2.66                # written by hand, no ID', '[LIST-A1] exempt 192.0.2.50 until ' . date('Y-m-d', time() + 86400)];
            for ($i = 0; $i < 20000; $i++) {
                $lines[] = "[LIST-D$i] deny 10." . ($i >> 8) . '.' . ($i & 255) . '.0/24' . ($i % 3 === 0 ? "   # scraper · cli 2026-10-01 10:00" : '') . ($i === 5 ? '' : '');
            }
            $lines[] = '[LIST-DX] deny 198.51.100.0/24 until ' . date('Y-m-d', time() + 86400) . '   # for a while';
            file_put_contents("$dir/store/lists/deny.rules", implode("\n", $lines) . "\n");
            $s = listsSettings($dir, '');
            same([20002, Settings::DENY_SHOWN], [$s->denyCount, count($s->deny)], 'every entry counted; the first hundred kept as written');
            $shield = new Shield($s, new MemoryStore());
            foreach (['10.0.0.9' => 'LIST-D0', '10.78.31.200' => 'LIST-D19999', '192.0.2.66' => null, '198.51.100.3' => 'LIST-DX', '10.78.32.1' => false] as $ip => $id) {
                $r = listsReq('/', $ip);
                $d = $shield->decide($r, 1000.0);
                same($id === false ? 'allow' : 'reject', $d->action, $ip);
                if (is_string($id)) {
                    same($id, $shield->explain($d, $r), "$ip: its entry");
                }
            }
            truthy(in_array('192.0.2.50', $s->exemptIps, true), 'an exempt line in the same file');
            $file = (glob("$dir/cache/settings-*.php") ?: []);
            Settings::load("$dir/site.rules", "$dir/cache");
            $file = (glob("$dir/cache/settings-*.php") ?: [])[0];
            truthy(filesize($file) < 2000000, 'compiled: ' . filesize($file) . ' bytes -- a table, not an array of 20,000');
            file_put_contents("$dir/store/lists/deny.rules", "[LIST-D1] deny 10.0.0.0/24\n[LIST-D2] deny 10.0.1.300\n");
            try {
                listsSettings($dir, '');
                throw new TestFailure('accepted a wrong address');
            } catch (RuleFileException $e) {
                truthy(strpos($e->getMessage(), 'deny.rules:2: "10.0.1.300" is not an address') !== false, $e->getMessage());
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 the command line: deny, allow, unlist, lists -- with their guards; the list written whole' => function (): void {
        $dir = listsDir();
        try {
            file_put_contents("$dir/site.rules", "set store-dir $dir/store\ntrust 10.0.0.1\n");
            $bin = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli());
            $run = static function (string $args) use ($bin, $dir): array {
                exec("$bin $args 2>&1", $out, $code);
                return [$code, implode("\n", $out)];
            };
            $f = escapeshellarg("$dir/site.rules");
            [$code, $out] = $run("deny $f 203.0.113.7 --for=7d --reason=scraper");
            truthy($code === 0 && strpos($out, 'kept out 203.0.113.7 until') !== false && strpos($out, '(LIST-D1)') !== false, $out);
            truthy(preg_match('/^\[LIST-D1\] deny 203\.0\.113\.7 until \d{4}-\d{2}-\d{2}T\d{2}:\d{2}   # scraper · cli /', (string) file_get_contents("$dir/store/lists/deny.rules")) === 1, 'the line, with its reason');
            same('0600', substr(sprintf('%o', (int) fileperms("$dir/store/lists/deny.rules")), -4), 'not for everyone');
            same([1, 1, 1, 0], [$run("deny $f 10.0.0.0/24")[0], $run("deny $f 198.0.0.0/8")[0], $run("allow $f 192.0.2.50")[0], $run("deny $f 198.0.0.0/8 --force")[0]],
                'a trusted proxy never; a wide range only with --force; allow only for a while');
            [$code, $out] = $run("lists $f");
            truthy($code === 0 && strpos($out, 'kept out (deny): 2') !== false && strpos($out, 'LIST-D2') !== false, $out);
            same(['reject', 'denied'], [($d = (new Shield(Settings::load("$dir/site.rules", "$dir/cache"), new MemoryStore()))->decide(listsReq('/', '203.0.113.7'), (float) time()))->action, $d->reason], 'in force at once');
            [$code, $out] = $run("unlist $f 203.0.113.7");
            truthy($code === 0 && strpos($out, '1 entry removed') !== false, $out);
            same([['198.0.0.0/8']], array_column(Lists::read("$dir/store/lists"), 'addresses'), 'only the other one left');
            // With the file store the command line reaches the servers' bans too.
            file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\n[B] ban after 3 refusals in 5m for 1h\n");
            (new FileStore("$dir/store"))->mark('ban:203.0.113.8', time() + 3600, (float) time());
            [$code, $out] = $run("unlist $f 203.0.113.8");
            truthy($code === 0 && strpos($out, 'its ban lifted') !== false, $out);
            same(0, (new FileStore("$dir/store"))->marked('ban:203.0.113.8', (float) time()), 'lifted at once');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-02 the real path: a scanner banned after its refusals, everywhere on the site, with Retry-After' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        $dir = listsDir();
        mkdir("$dir/docroot");
        file_put_contents("$dir/docroot/index.php", '<?php echo "ok";');
        file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nexempt none\n[SITE-SECRET] block **/secret/**\n[SITE-SCAN] ban after 3 refusals in 5m for 10m\n");
        $port = freePort();
        $proc = proc_open(sprintf('REQUEST_SHIELD_CONFIG=%s exec %s -d auto_prepend_file=%s -S 127.0.0.1:%d -t %s > /dev/null 2>&1', escapeshellarg("$dir/site.rules"),
            serverPhp(), escapeshellarg(rsEntry()), $port, escapeshellarg("$dir/docroot")), [], $pipes);
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
            usleep(100000);
        }
        try {
            $get = static function (string $uri, string $headers = '') use ($port): array {
                @file_get_contents("http://127.0.0.1:$port$uri", false, stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 10, 'header' => "User-Agent: Mozilla/5.0 Firefox/136.0\r\n" . $headers]]));
                $retry = '';
                foreach ($http_response_header ?? [] as $h) {
                    if (stripos($h, 'Retry-After:') === 0) {
                        $retry = trim(substr($h, 12));
                    }
                }
                return [substr((string) ($http_response_header[0] ?? ''), 9, 3), $retry];
            };
            same('200', $get('/')[0], 'before: the page');
            // A foreign page embedding five images of refused addresses: refused, the visitor not banned.
            $embedded = "Sec-Fetch-Mode: no-cors\r\nSec-Fetch-Site: cross-site\r\nSec-Fetch-Dest: image\r\n";
            $statuses = [];
            foreach (['a', 'b', 'c', 'd', 'e'] as $name) {
                $statuses[] = $get("/secret/$name.png", $embedded)[0];
            }
            same(['404', '404', '404', '404', '404'], $statuses, 'five refusals a page asked for');
            same('200', $get('/')[0], 'not counted: the page still');
            same(['404', '404', '404'], [$get('/secret/a')[0], $get('/secret/b')[0], $get('/secret/c')[0]], 'three refusals');
            [$status, $retry] = $get('/');
            truthy($status === '429' && (int) $retry > 590 && (int) $retry <= 600, "then nothing but 429, for 10 minutes: $status, Retry-After $retry");
        } finally {
            proc_terminate($proc);
            proc_close($proc);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
];
