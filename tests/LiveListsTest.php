<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Log;
use CjwNetwork\RequestShield\Waf\ListsPage;
use CjwNetwork\RequestShield\Waf\LivePage;
use CjwNetwork\RequestShield\LogTail;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Rules\Lists;
use CjwNetwork\RequestShield\Rules\RuleFile;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Store\MemoryStore;

/** The live view and the lists in the dashboard (proposal 0026). */

function liveDir(): string
{
    $dir = sys_get_temp_dir() . '/rs-live-' . getmypid() . '-' . mt_rand();
    mkdir($dir, 0700, true);
    return $dir;
}

function liveSettings(string $dir, string $rules = ''): Settings
{
    file_put_contents("$dir/site.rules", "set store-dir $dir/store\nset log $dir/shield.log\nset log-level all\n" . $rules);
    return Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
}

function liveLine(Settings $s, string $url, Decision $d, ?string $rule, string $ip = '203.0.113.9', bool $monitor = false, string $ua = 'curl/8'): void
{
    $p = parse_url($url);
    $r = Request::fromServer(['REQUEST_URI' => ($p['path'] ?? '/') . (isset($p['query']) ? '?' . $p['query'] : ''), 'REQUEST_METHOD' => 'GET',
        'HTTP_HOST' => (string) ($p['host'] ?? 'example.org'), 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => $ua]);
    Log::write($s, $r, $d, $rule, 1790800000.0, $monitor);
}

return [
    'RSF06-02 the log tail: the end first, then only what is new -- whole lines, a rotated log from its start, a burst skipped to its newest' => function (): void {
        $dir = liveDir();
        try {
            $f = "$dir/shield.log";
            same(['rows' => [], 'cursor' => '0:0', 'skipped' => 0], LogTail::read($f, null), 'no log yet');
            $s = liveSettings($dir);
            for ($i = 0; $i < 5; $i++) {
                liveLine($s, "http://example.org/a$i", Decision::reject(404, 'blocked path'), 'SCAN-1');
            }
            $first = LogTail::read($f, null);
            same(5, count($first['rows']), 'the end of the log');
            same('http://example.org/a4', $first['rows'][4]['url']);
            same([], LogTail::read($f, $first['cursor'])['rows'], 'nothing new');
            liveLine($s, 'http://example.org/b', Decision::reject(404, 'blocked path'), 'SCAN-1');
            file_put_contents($f, '2026-10-01T10:00:00+02:00 203.0.113.0/24 reject 404 "blocked path" rule=SCAN-1 "GET http://example.org/half', FILE_APPEND);
            $next = LogTail::read($f, $first['cursor']);
            same(['http://example.org/b'], array_column($next['rows'], 'url'), 'only the new whole line; the half one waits');
            file_put_contents($f, "\" \"curl\"\n", FILE_APPEND);
            same(['http://example.org/half'], array_column(LogTail::read($f, $next['cursor'])['rows'], 'url'), 'then the rest of it');
            // Rotated: a new file (another inode) under the same name.
            rename($f, "$f.1");
            liveLine($s, 'http://example.org/new', Decision::reject(404, 'blocked path'), 'SCAN-1');
            same(['http://example.org/new'], array_column(LogTail::read($f, $next['cursor'])['rows'], 'url'), 'a rotated log: from its start');
            // A burst bigger than one read: the newest, and how much was skipped.
            $c = LogTail::read($f, null)['cursor'];
            for ($i = 0; $i < 400; $i++) {
                liveLine($s, "http://example.org/burst$i", Decision::reject(404, 'blocked path'), 'SCAN-1');
            }
            $burst = LogTail::read($f, $c, 8192);
            truthy($burst['skipped'] > 0 && count($burst['rows']) > 10 && end($burst['rows'])['url'] === 'http://example.org/burst399', 'skipped ' . $burst['skipped'] . ' bytes, newest kept');
            same('http://example.org/burst' . (400 - count($burst['rows'])), $burst['rows'][0]['url'], 'no half line at the start');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 each row: the website, what happened, why in words, where from -- list, ban, built-in, own rule, pace, crawler, basic check, watched' => function (): void {
        $dir = liveDir();
        try {
            mkdir("$dir/store/lists", 0750, true);
            file_put_contents("$dir/store/lists/deny.rules", "[LIST-D7] deny 198.51.100.0/24   # scraper, 900 a minute · cli 2026-10-01 09:00\n");
            $s = liveSettings($dir, "[SITE-ADMIN] restrict /admin/** to 192.0.2.0/24   # the office only\n[SITE-PACE] limit requests 100/min\n"
                . "site shop.example.de *.shop.example.de {\n}\n");
            liveLine($s, 'http://shop.example.de/x', Decision::reject(403, 'denied'), 'LIST-D7', '198.51.100.7');
            liveLine($s, 'http://www.example.org/', Decision::throttle('banned', 600), 'B-SCAN');
            liveLine($s, 'http://www.example.org/.env', Decision::reject(404, 'blocked path'), 'SCAN-HIDDEN');
            liveLine($s, 'http://www.example.org/admin/', Decision::reject(403, 'restricted'), 'SITE-ADMIN');
            liveLine($s, 'http://www.example.org/', Decision::throttle('requests', 30), 'SITE-PACE');
            liveLine($s, 'http://www.example.org/', Decision::reject(403, 'crawler'), 'CRAWLER-GPTBOT');
            liveLine($s, 'http://www.example.org/', Decision::reject(405, 'method'), null);
            liveLine($s, 'http://news.shop.example.de/old', Decision::reject(404, 'blocked path'), 'SITE-OLD', '203.0.113.9', true);
            $j = \CjwNetwork\RequestShield\Api\LiveRows::json($s, null, ['lang' => 'en']);
            same(['list', 'ban', 'builtin', 'own', 'pace', 'crawler', 'shield', 'own'], array_column($j['rows'], 'source'), 'where from');
            same(['refused', 'banned', 'refused', 'refused', 'paused', 'refused', 'refused', 'refused'], array_column($j['rows'], 'what'));
            $r = $j['rows'];
            same('on the deny list: scraper, 900 a minute', $r[0]['why'], 'a list entry: its comment, without who and when');
            same(['shop.example.de', 'shop.example.de'], [$r[0]['host'], $r[0]['site']], 'the website and its site block');
            same('shop.example.de', $r[7]['site'], 'a subdomain: its block (named by its first name)');
            same('the office only', $r[3]['why'], 'a rule with a description: the site\'s own words');
            same('banned for a while: it kept going past the limits', $r[1]['why'], 'otherwise the reason in words');
            same([true, 'watched: would be refused 404'], [$r[7]['watched'], $r[7]['label']], 'a watched rule says so');
            same(['198.51.100.0/24', null], [$r[0]['client'], $r[0]['keep']], 'on a list already: no "keep out"');
            same('203.0.113.0/24', $r[2]['keep'], 'a masked address: kept out as its /24');
            same(null, \CjwNetwork\RequestShield\Api\LiveRows::json($s, null, ['ip' => '203.0.113.50'])['rows'][2]['keep'], 'never offered for the range the viewer is in');
            $linked = \CjwNetwork\RequestShield\Api\LiveRows::json($s, null, ['links' => ['rules' => '/rs/rules', 'lists' => '/rs/lists']])['rows'];
            same(['/rs/lists?q=%5BLIST-D7%5D', '/rs/rules#rule-SCAN-HIDDEN', '/rs/rules#rule-SITE-ADMIN', '/rs/rules#rule-SITE-PACE', null],
                [$linked[0]['ruleHref'], $linked[2]['ruleHref'], $linked[3]['ruleHref'], $linked[4]['ruleHref'], $linked[6]['ruleHref']],
                'a rule\'s ID: where it is written (a list entry: its list); a basic check without one: no link');
            same(null, \CjwNetwork\RequestShield\Api\LiveRows::json($s, null)['rows'][3]['ruleHref'], 'without the pages\' addresses: no link');
            $de = \CjwNetwork\RequestShield\Api\LiveRows::json($s, null, ['lang' => 'de'])['rows'];
            same(['abgewiesen 403', 'Sperre', 'auf der Sperrliste: scraper, 900 a minute'], [$de[0]['label'], $de[1]['sourceLabel'], $de[0]['why']], 'in German');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 the dashboard does not show itself; the page escapes what the log holds; without a log it says how to switch it on' => function (): void {
        $dir = liveDir();
        try {
            $s = liveSettings($dir, "set dashboard-path /admin/rs\n");
            liveLine($s, 'http://example.org/site/admin/rs/waf/live?format=json&cursor=1:2', Decision::allowUncached('query parameter'), 'DEMO-Q');
            liveLine($s, 'http://example.org/admin/rs/waf/lists', Decision::reject(403, 'restricted'), 'SITE-RS');
            liveLine($s, 'http://example.org/"><script>alert(1)</script>', Decision::reject(404, 'blocked path'), 'SCAN-1', '203.0.113.9', false, '<img src=x onerror=alert(2)>');
            $j = \CjwNetwork\RequestShield\Api\LiveRows::json($s, null);
            same(['http://example.org/admin/rs/waf/lists', 'http://example.org/\'><script>alert(1)</script>'], array_map(static fn (array $r): string => 'http://' . $r['host'] . $r['request'], $j['rows']),
                'its own pages that went through are left out (below a prefix too); refused ones stay');
            $html = LivePage::render($s, ['feed' => '/admin/rs/live?format=json', 'lists' => '/admin/rs/lists', 'lang' => 'en']);
            truthy(strpos($html, '<script>alert') === false && strpos($html, '<img src=x') === false, 'nothing from the log unescaped');
            truthy(strpos($html, 'data-feed="/admin/rs/live?format=json&amp;lang=en"') !== false && strpos($html, 'noindex') !== false, 'the feed, never indexed');
            $none = Settings::from(RuleFile::read([(string) (file_put_contents("$dir/b.rules", "set store-dir $dir/store\n") !== false ? "$dir/b.rules" : '')])['config']);
            truthy(strpos(LivePage::render($none, ['feed' => '/x']), 'set log') !== false, 'no log: how to switch it on');
            same(false, \CjwNetwork\RequestShield\Api\LiveRows::json($none, null)['log']);
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 the lists page: a token per address and hour; add with a comment, change, extend, remove -- with the guards' => function (): void {
        $dir = liveDir();
        try {
            $s = liveSettings($dir, "trust 10.1.0.0/16\n");
            // The lists are written with this clock, but Settings::load() below judges them by the real
            // one (and the rule file is touched with it), so a fixed date expires the 30-day entry a month
            // later. 26:40 past the previous hour is never ahead of the real clock and keeps the token's
            // hour boundaries where a fixed time had them.
            $now = intdiv(time(), 3600) * 3600 - 2000;
            $tok = \CjwNetwork\RequestShield\Api\ListsChanges::token($s, '192.0.2.10', $now);
            same([true, true, false, false, false], [\CjwNetwork\RequestShield\Api\ListsChanges::verify($s, '192.0.2.10', $tok, $now), \CjwNetwork\RequestShield\Api\ListsChanges::verify($s, '192.0.2.10', $tok, $now + 3600),
                \CjwNetwork\RequestShield\Api\ListsChanges::verify($s, '192.0.2.10', $tok, $now + 7200), \CjwNetwork\RequestShield\Api\ListsChanges::verify($s, '192.0.2.11', $tok, $now), \CjwNetwork\RequestShield\Api\ListsChanges::verify($s, '192.0.2.10', '', $now)],
                'this hour and the next; not later, not another address, not empty');
            $o = ['ip' => '192.0.2.10', 'now' => $now, 'user' => 'editor', 'ruleFile' => "$dir/site.rules"];
            $post = static fn (array $p): array => \CjwNetwork\RequestShield\Api\ListsChanges::handle($s, $p + ['token' => $tok], $o);
            touch("$dir/site.rules", $now - 100);
            $r = $post(['do' => 'add', 'kind' => 'deny', 'address' => '203.0.113.0/24', 'for' => '7d', 'note' => 'scanner <b>#1</b> [x]']);
            same([true, 'LIST-D1: 203.0.113.0/24 added (until ' . date('Y-m-d H:i', $now + 604800) . ').'], [$r['ok'], $r['message']]);
            clearstatcache();
            truthy(filemtime("$dir/site.rules") > $now - 100, 'the rule file touched: every server reads the lists');
            $e = Lists::read("$dir/store/lists")[0];
            same([['203.0.113.0/24'], $now + 604800 - ($now + 604800) % 60, 'scanner <b> 1</b> x'], [$e['addresses'], $e['until'], Lists::split($e['note'])[0]], 'the line, the comment cleaned');
            truthy(strpos($e['note'], 'dashboard editor') !== false, 'who added it');
            $fails = [
                [['do' => 'add', 'kind' => 'deny', 'address' => '10.1.2.0/24', 'for' => '1d', 'note' => 'x'], 'trusted proxy'],
                [['do' => 'add', 'kind' => 'deny', 'address' => '192.0.2.0/24', 'for' => '1d', 'note' => 'x'], 'your own address'],
                [['do' => 'add', 'kind' => 'deny', 'address' => '198.0.0.0/8', 'for' => '1d', 'note' => 'x'], 'wide range'],
                [['do' => 'add', 'kind' => 'exempt', 'address' => '198.51.100.5', 'for' => 'good', 'note' => 'x'], 'needs an end'],
                [['do' => 'add', 'kind' => 'deny', 'address' => '198.51.100.5', 'for' => 'good', 'note' => ''], 'needs a comment'],
                [['do' => 'add', 'kind' => 'deny', 'address' => '198.51.100.5', 'for' => 'date', 'until' => '2020-01-01', 'note' => 'x'], 'in the future'],
                [['do' => 'add', 'kind' => 'deny', 'address' => 'nonsense', 'for' => '1d', 'note' => 'x'], 'is not an address'],
                [['do' => 'remove', 'id' => 'LIST-D9'], 'no entry LIST-D9'],
                [['do' => 'what'], 'Nothing to do'],
            ];
            foreach ($fails as [$p, $says]) {
                $r = $post($p);
                truthy(!$r['ok'] && strpos($r['message'], $says) !== false, $says . ': ' . $r['message']);
            }
            same(false, \CjwNetwork\RequestShield\Api\ListsChanges::handle($s, ['do' => 'add', 'kind' => 'deny', 'address' => '198.51.100.5', 'for' => '1d', 'token' => 'forged'], $o)['ok'], 'a forged token');
            same(true, \CjwNetwork\RequestShield\Api\ListsChanges::handle($s, ['do' => 'add', 'kind' => 'deny', 'address' => '198.51.100.5', 'for' => '1d'], $o + ['csrfChecked' => true])['ok'], 'a CMS that checked its own form token');
            same(true, $post(['do' => 'add', 'kind' => 'deny', 'address' => '198.0.0.0/8', 'for' => '1d', 'note' => 'x', 'confirm' => '1'])['ok'], 'a wide range, confirmed');
            same(true, $post(['do' => 'update', 'id' => 'LIST-D1', 'for' => 'good', 'note' => 'scanner, for good'])['ok'], 'for good, with a comment');
            $e = Lists::find("$dir/store/lists", '[LIST-D1]', 1)['entries'][0];
            same([null, 'scanner, for good'], [$e['until'], Lists::split($e['note'])[0]]);
            truthy(strpos($e['note'], 'changed dashboard editor') !== false, 'who changed it');
            same(true, $post(['do' => 'update', 'id' => 'LIST-D1', 'for' => '30d'])['ok'], 'an end again, the comment kept');
            $e = Lists::find("$dir/store/lists", '[LIST-D1]', 1)['entries'][0];
            same(['scanner, for good', true], [Lists::split($e['note'])[0], $e['until'] !== null]);
            same(true, $post(['do' => 'remove', 'id' => 'LIST-D2'])['ok']);
            same(['LIST-D3', 'LIST-D1'], array_column(Lists::find("$dir/store/lists", '', 10)['entries'], 'id'), 'newest first');
            same(1, Settings::load("$dir/site.rules", "$dir/cache")->deny[0]['rule'] === 'LIST-D1' ? 1 : 0, 'in force for the shield');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 the page shows the entries (escaped, searched, the rest counted) and the active bans -- lifted with one click, "for good?" after the third' => function (): void {
        $dir = liveDir();
        try {
            mkdir("$dir/store/lists", 0750, true);
            $lines = [];
            for ($i = 1; $i <= 250; $i++) {
                $lines[] = "[LIST-D$i] deny 10.9." . intdiv($i, 250) . '.' . ($i % 250) . "   # scraper $i · cli 2026-10-01 09:00";
            }
            $lines[] = '[LIST-D251] deny 198.51.100.66   # <script>alert(1)</script> · dashboard 2026-10-01 09:00';
            file_put_contents("$dir/store/lists/deny.rules", implode("\n", $lines) . "\n");
            $s = liveSettings($dir, "[B-SCAN] ban after 3 refusals in 5m for 10m\n");
            $store = new MemoryStore();
            $now = time();
            $store->mark('ban:203.0.113.9', $now + 600, (float) $now);
            for ($i = 0; $i < 3; $i++) {
                $store->hit('bans:203.0.113.9', 86400, (float) $now);
            }
            $store->mark('ban:2001:db8::/64', $now + 300, (float) $now);
            $html = ListsPage::render($s, ['action' => '/rs/lists', 'ip' => '192.0.2.10', 'store' => $store, 'lang' => 'en', 'get' => ['address' => '203.0.113.0/24', 'note' => 'from the live view', 'for' => '1d']]);
            truthy(strpos($html, '<script>alert') === false && strpos($html, '&lt;script&gt;alert(1)&lt;/script&gt;') !== false, 'the comment escaped');
            truthy(strpos($html, 'value="203.0.113.0/24"') !== false && strpos($html, 'value="from the live view"') !== false && strpos($html, '<option value="1d" selected>') !== false, 'filled from the live view');
            same(ListsPage::SHOWN, substr_count($html, 'name="do" value="remove"'), 'at most ' . ListsPage::SHOWN . ' entries');
            truthy(strpos($html, '51 more') !== false, 'the rest counted');
            truthy(strpos($html, '<td class="mono">203.0.113.9</td>') !== false && strpos($html, '2001:db8::/64') !== false, 'the active bans, IPv6 as its network');
            truthy(strpos($html, 'banned 3 times today') !== false, 'the third ban today: "keep out for good?"');
            $found = ListsPage::render($s, ['action' => '/rs/lists', 'ip' => '192.0.2.10', 'store' => $store, 'get' => ['q' => 'scraper 25']]);
            same(2, substr_count($found, 'name="do" value="remove"'), 'searched: "scraper 25" and "scraper 250"');
            $r = \CjwNetwork\RequestShield\Api\ListsChanges::handle($s, ['do' => 'lift', 'bucket' => '203.0.113.9', 'token' => \CjwNetwork\RequestShield\Api\ListsChanges::token($s, '192.0.2.10')], ['ip' => '192.0.2.10', 'store' => $store]);
            same([true, 0], [$r['ok'], $store->marked('ban:203.0.113.9', (float) time())], 'lifted');
            same(false, \CjwNetwork\RequestShield\Api\ListsChanges::handle($s, ['do' => 'lift', 'bucket' => '203.0.113.9', 'token' => \CjwNetwork\RequestShield\Api\ListsChanges::token($s, '192.0.2.10')], ['ip' => '192.0.2.10', 'store' => $store])['ok'], 'not banned any more');
            $empty = liveSettings(liveDir());
            truthy(strpos(ListsPage::render($empty, ['action' => '/x', 'ip' => '1.2.3.4']), 'No entries yet') !== false, 'an empty list');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 the live memory (set live on): the full address, only what stopped a request, the cursor, the ring, each store-dir its own' => function (): void {
        if (!\CjwNetwork\RequestShield\Live::usable()) {
            skip('no APCu in this PHP (apc.enable_cli=1)');
        }
        $dir = liveDir();
        try {
            $s = liveSettings($dir, "set live on\nset live-keep 10m\nset log-level off\n");
            same([true, 600], [$s->liveEnabled, $s->liveKeep]);
            $shield = new \CjwNetwork\RequestShield\Shield($s, new MemoryStore());
            $note = static function (string $uri, string $ip) use ($s, $shield): void {
                $r = Request::fromServer(['REQUEST_URI' => $uri, 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'shop.example.de', 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/136.0']);
                $d = $shield->decide($r, 1790800000.0);
                Log::note($s, $r, $d, $shield->explain($d, $r), 1790800000.0);
            };
            $note('/.env', '203.0.113.77');
            $note('/', '203.0.113.78');                          // passes: not kept
            $note('/?utm_source=x', '203.0.113.79');            // uncached: not kept
            $j = \CjwNetwork\RequestShield\Api\LiveRows::json($s, null, ['lang' => 'en']);
            same([true, ['203.0.113.77'], '203.0.113.77'], [$j['memory'] ?? null, array_column($j['rows'], 'client'), $j['rows'][0]['keep']], 'the full address -- and "keep out" for exactly it');
            same('shop.example.de', $j['rows'][0]['host']);
            $note('/.git/config', '2001:db8::5');
            $next = \CjwNetwork\RequestShield\Api\LiveRows::json($s, $j['cursor']);
            same(['2001:db8::5'], array_column($next['rows'], 'client'), 'with the cursor: only what is new');
            same([], \CjwNetwork\RequestShield\Api\LiveRows::json($s, $next['cursor'])['rows'], 'nothing new');
            $other = liveSettings(liveDir(), "set live on\n");
            same([], \CjwNetwork\RequestShield\Api\LiveRows::json($other, null)['rows'], 'another store-dir: its own memory');
            // The ring: once full, the oldest overwritten -- a reader never gets an overwritten slot as new.
            $p = 'rshield-live:' . hash('crc32b', $s->storeDir) . ':';
            apcu_store($p . 'n', \CjwNetwork\RequestShield\Live::SIZE + 1);
            $note('/.htpasswd', '198.51.100.1');                 // number SIZE + 2, in the slot of number 2
            $ring = \CjwNetwork\RequestShield\Live::read($s, null, 5);
            same(['198.51.100.1'], array_column($ring['rows'], 'client'), 'only entries of this round');
            same(['rows' => [], 'cursor' => 'm:' . (\CjwNetwork\RequestShield\Live::SIZE + 2), 'skipped' => 0], \CjwNetwork\RequestShield\Live::read($s, $ring['cursor']));
            $burst = \CjwNetwork\RequestShield\Live::read($s, 'm:1', 3);
            same(\CjwNetwork\RequestShield\Live::SIZE - 2, $burst['skipped'], 'a reader far behind: the newest, the rest counted');
            $html = LivePage::render($s, ['feed' => '/rs/live?format=json', 'lang' => 'en']);
            truthy(strpos($html, 'From the live memory') !== false && strpos($html, '10 minutes') !== false, 'the page says where its rows come from');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 the live memory without APCu (set store file): live.log in store-dir, the full address, the cursor, live-keep, rotation' => function (): void {
        $dir = liveDir();
        try {
            $s = liveSettings($dir, "set store file\nset live on\nset live-keep 10m\nset log-level off\n");
            same('file', \CjwNetwork\RequestShield\Live::where($s), 'the file store keeps the live view in a file');
            truthy(\CjwNetwork\RequestShield\Api\LiveRows::fromMemory($s), 'the page reads the live view, not the log');
            $shield = new \CjwNetwork\RequestShield\Shield($s, new MemoryStore());
            $note = static function (string $uri, string $ip, float $now = 0.0) use ($s, $shield): void {
                $r = Request::fromServer(['REQUEST_URI' => $uri, 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'shop.example.de', 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/136.0']);
                $now = $now > 0 ? $now : microtime(true);
                $d = $shield->decide($r, $now);
                Log::note($s, $r, $d, $shield->explain($d, $r), $now);
            };
            $note('/.env', '203.0.113.77');
            $note('/', '203.0.113.78');                          // passes: not kept
            $note('/.git/HEAD', '203.0.113.79', time() - 3600.0); // an hour old: past live-keep, not shown
            truthy(is_file("$dir/store/live.log"), 'the file in store-dir');
            same(false, is_file("$dir/shield.log"), 'the log itself was not written (log-level off)');
            $j = \CjwNetwork\RequestShield\Api\LiveRows::json($s, null, ['lang' => 'en']);
            same([true, ['203.0.113.77'], '203.0.113.77'], [$j['memory'] ?? null, array_column($j['rows'], 'client'), $j['rows'][0]['keep']], 'the full address -- and "keep out" for exactly it; the old entry left out');
            same('shop.example.de', $j['rows'][0]['host']);
            $note('/.git/config', '2001:db8::5');
            $next = \CjwNetwork\RequestShield\Api\LiveRows::json($s, $j['cursor']);
            same(['2001:db8::5'], array_column($next['rows'], 'client'), 'with the cursor: only what is new');
            same([], \CjwNetwork\RequestShield\Api\LiveRows::json($s, $next['cursor'])['rows'], 'nothing new');
            // Rotation: past FILE_MAX the file moves to .1 and a new one starts; a reader goes on from its start.
            file_put_contents("$dir/store/live.log", str_repeat(str_repeat('x', 99) . "\n", intdiv(\CjwNetwork\RequestShield\Live::FILE_MAX, 100) + 10), FILE_APPEND);
            $note('/.htpasswd', '198.51.100.1');
            truthy(is_file("$dir/store/live.log.1") && filesize("$dir/store/live.log") < 1000, 'rotated: the new file holds the newest line only');
            same(['198.51.100.1'], array_column(\CjwNetwork\RequestShield\Api\LiveRows::json($s, $next['cursor'])['rows'], 'client'), 'read on after the rotation');
            $html = LivePage::render($s, ['feed' => '/rs/live?format=json', 'lang' => 'en']);
            truthy(strpos($html, 'From the live memory') !== false && strpos($html, '10 minutes') !== false, 'the page says where its rows come from');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 set ban-keep file: a ban survives a restart of APCu, and is lifted from both' => function (): void {
        if (!\CjwNetwork\RequestShield\Live::usable()) {
            skip('no APCu in this PHP (apc.enable_cli=1)');
        }
        $dir = liveDir();
        try {
            $s = liveSettings($dir, "set ban-keep file\n[B-SCAN] ban after 2 refusals in 5m for 10m\n");
            same('file', $s->banKeep);
            $prefix = 'rshield-test-' . mt_rand() . ':';
            $store = new \CjwNetwork\RequestShield\Store\ApcuStore($prefix);
            $shield = new \CjwNetwork\RequestShield\Shield($s, $store);
            $signals = new ReflectionMethod(\CjwNetwork\RequestShield\Shield::class, 'signals');
            $signals->setAccessible(true);
            $now = microtime(true);
            foreach ([1, 2] as $i) {
                $r = Request::fromServer(['REQUEST_URI' => '/.env', 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'x', 'REMOTE_ADDR' => '203.0.113.5', 'HTTP_USER_AGENT' => 'curl']);
                $signals->invoke($shield, $shield->decide($r, $now), $r, $now);
            }
            $files = new \CjwNetwork\RequestShield\Store\FileStore("$dir/store");
            truthy($store->marked('ban:203.0.113.5', $now) > 0 && $files->marked('ban:203.0.113.5', $now) > 0, 'banned: in APCu and in its file');
            // A restart: APCu empty.
            apcu_delete($prefix . 'mark:ban:203.0.113.5');
            apcu_delete('rshield-bans-restored:' . hash('crc32b', $s->storeDir));
            same(0, $store->marked('ban:203.0.113.5', $now), 'gone from memory');
            $again = new \CjwNetwork\RequestShield\Shield($s, $store);
            $r = Request::fromServer(['REQUEST_URI' => '/', 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'x', 'REMOTE_ADDR' => '203.0.113.5', 'HTTP_USER_AGENT' => 'curl']);
            same(['throttle', 'banned'], [($d = $again->decide($r, $now))->action, $d->reason], 'the first request after the restart brought it back');
            same(true, \CjwNetwork\RequestShield\Shield::liftBan($s, $store, '203.0.113.5', $now), 'lifted');
            same([0, 0], [$store->marked('ban:203.0.113.5', $now), $files->marked('ban:203.0.113.5', $now)], 'from both');
            same(false, \CjwNetwork\RequestShield\Shield::liftBan($s, $store, '203.0.113.5', $now), 'nothing to lift');
            // Without ban-keep: no file.
            $plain = liveSettings(liveDir(), "[B-SCAN] ban after 1 refusals in 5m for 10m\n");
            same('memory', $plain->banKeep);
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 the dashboard\'s own pages, restricted to an address, do not count against the pace -- without a restrict rule they do' => function (): void {
        $dir = liveDir();
        try {
            $req = static fn (string $path, string $ip = '127.0.0.1'): Request => Request::fromServer(['REQUEST_URI' => $path, 'REQUEST_METHOD' => 'GET',
                'HTTP_HOST' => 'example.org', 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/136.0']);
            $s = liveSettings($dir, "exempt none\n[R-RS] restrict **/rs/** to 127.0.0.1 ::1\n[R-PACE] limit requests 3/min\n");
            $shield = new \CjwNetwork\RequestShield\Shield($s, new MemoryStore());
            $actions = [];
            for ($i = 0; $i < 10; $i++) {
                $actions[] = $shield->decide($req($i % 2 === 0 ? '/rs/waf/live?format=json&cursor=m:1' : '/demo/index.php/rs/stats'), 1000.0 + $i)->action;
            }
            same(array_fill(0, 10, 'allow'), $actions, 'the live view every few seconds, the statistics below a prefix: never counted');
            $page = [];
            for ($i = 0; $i < 5; $i++) {
                $page[] = $shield->decide($req('/page'), 1020.0 + $i)->action;
            }
            same(['allow', 'allow', 'allow', 'challenge', 'challenge'], array_map(static fn (string $a): string => $a === 'throttle' ? 'challenge' : $a, $page),
                'the site\'s pages still are -- and the dashboard requests before added nothing');
            same(['reject', 'restricted'], [($d = $shield->decide($req('/rs/waf/live', '198.51.100.7'), 1030.0))->action, $d->reason], 'from elsewhere: refused first');
            $other = new \CjwNetwork\RequestShield\Shield($s, new MemoryStore());
            $more = [];
            for ($i = 0; $i < 5; $i++) {
                $more[] = $other->decide($req('/rs/waf/live-and-more'), 1040.0 + $i)->action;
            }
            truthy($more[4] !== 'allow', 'not a page of the dashboard (below the restricted path all the same): counted as any: ' . implode(',', $more));
            $open = liveSettings($dir, "exempt none\n[R-PACE] limit requests 3/min\n");
            $openShield = new \CjwNetwork\RequestShield\Shield($open, new MemoryStore());
            $counted = [];
            for ($i = 0; $i < 5; $i++) {
                $counted[] = $openShield->decide($req('/rs/waf/live'), 1000.0 + $i)->action;
            }
            truthy(in_array('challenge', $counted, true) || in_array('throttle', $counted, true), 'no restrict rule: the dashboard counts, an open one keeps its flood guard: ' . implode(',', $counted));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF06-02 the list file functions: notes by ID without reading every entry, update keeps the rest, removeId, find newest first' => function (): void {
        $dir = liveDir();
        try {
            file_put_contents("$dir/deny.rules", "[LIST-D1] deny 10.0.0.1   # one · cli 2026-10-01 09:00\n[LIST-D11] deny 10.0.0.11   # eleven · cli 2026-10-01 09:00\n[LIST-D2] deny 10.0.0.2\n");
            same(['LIST-D1' => 'one', 'LIST-D11' => 'eleven', 'LIST-D2' => ''], Lists::notes($dir, ['LIST-D1', 'LIST-D11', 'LIST-D2', 'LIST-D9']), 'by ID, an ID that only begins like another not mixed up');
            same(true, Lists::update($dir, 'LIST-D11', null, 'new comment', 'dashboard'));
            same([false, false], [Lists::update($dir, 'LIST-D9', null, 'x'), Lists::removeId($dir, 'LIST-D9')], 'no such entry');
            $lines = file("$dir/deny.rules", FILE_IGNORE_NEW_LINES) ?: [];
            same('[LIST-D1] deny 10.0.0.1   # one · cli 2026-10-01 09:00', $lines[0], 'the others untouched');
            truthy(preg_match('/^\[LIST-D11\] deny 10\.0\.0\.11   # new comment · cli 2026-10-01 09:00, changed dashboard \d{4}-\d\d-\d\d \d\d:\d\d$/', $lines[1]) === 1, $lines[1]);
            same(true, Lists::removeId($dir, 'LIST-D1'));
            same(['LIST-D2', 'LIST-D11'], array_column(Lists::find($dir, '', 5)['entries'], 'id'), 'newest first; LIST-D1 gone, not LIST-D11');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
];
