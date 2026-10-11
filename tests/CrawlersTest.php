<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Challenge\Crawlers;
use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Log;
use CjwNetwork\RequestShield\LogStats;
use CjwNetwork\RequestShield\Waf\RulesPage;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Rules\CrawlerLists;
use CjwNetwork\RequestShield\Rules\RuleFile;
use CjwNetwork\RequestShield\Rules\RuleFileException;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Shield;
use CjwNetwork\RequestShield\Store\MemoryStore;

/** Known crawlers (proposal 0011): the list, verifying by address list or DNS, what a site does with them, updating the lists. */

const CLAUDEBOT = 'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)';
const GOOGLEBOT = 'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)';
const ANTHROPIC_IP = '216.73.216.5';        // in 216.73.216.0/22, rules/crawlers/anthropic.json
const GOOGLE_IP6 = '2001:4860:4801:10::1';  // in 2001:4860:4801:10::/64, rules/crawlers/google-googlebot.json

function crawlerDir(array $files): string
{
    $dir = sys_get_temp_dir() . '/rshield-crawl-' . getmypid() . '-' . mt_rand();
    foreach ($files as $name => $text) {
        @mkdir(dirname("$dir/$name"), 0700, true);
        file_put_contents("$dir/$name", $text);
    }
    return $dir;
}

function crawlerSettings(string $rules): Settings
{
    $dir = crawlerDir(['site.rules' => $rules]);
    try {
        return Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
    } finally {
        exec('rm -rf ' . escapeshellarg($dir));
    }
}

function crawlerFails(string $rules, string $at, string $part): void
{
    $dir = crawlerDir(['site.rules' => $rules]);
    try {
        RuleFile::read(["$dir/site.rules"]);
    } catch (RuleFileException $e) {
        truthy(strncmp($e->getMessage(), "$at: ", strlen($at) + 2) === 0, "starts with $at: " . $e->getMessage());
        truthy(strpos($e->getMessage(), $part) !== false, "says \"$part\": " . $e->getMessage());
        return;
    } finally {
        exec('rm -rf ' . escapeshellarg($dir));
    }
    throw new TestFailure('accepted: ' . $rules);
}

function crawlerReq(string $ip, string $ua, string $uri = '/'): Request
{
    return Request::fromServer(['REQUEST_URI' => $uri, 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'example.org', 'REMOTE_ADDR' => $ip, 'HTTP_USER_AGENT' => $ua]);
}

/** A crawler request through decide() and the gate, under a budget that checks from the first request. */
function crawlerSettle(Settings $s, string $ip, string $ua): Decision
{
    $shield = new Shield($s, new MemoryStore());
    $r = crawlerReq($ip, $ua);
    return $shield->settle($shield->decide($r, 1000.0), $r, 1000.0)['decision'];
}

return [
    'RSF01-04 the shipped list: the crawlers, their kinds and how each is verified; the generated rules/crawlers.php is current' => function (): void {
        $s = Settings::from([]);
        same(['search' => 8, 'ai-search' => 4, 'ai-user' => 3, 'ai-training' => 4], array_count_values(array_column($s->crawlers, 'kind')), 'by kind');
        foreach ($s->crawlers as $id => $x) {
            truthy($x['ranges'] !== [] || $x['dns'] !== [], "$id can be verified");
            same('allow', $x['policy'], "$id: allowed by default");
            foreach ($x['lists'] as $name => $about) {
                truthy(strncmp((string) $about['source'], 'https://', 8) === 0, "$id: $name names where it comes from");
            }
        }
        same(RuleFile::shippedCrawlersPhp(), (string) file_get_contents(dirname(__DIR__) . '/rules/crawlers.php'), 'rules/crawlers.php is current (php bin/update-crawler-lists)');
        same(array_keys(crawlerSettings('')->crawlers), array_keys($s->crawlers), 'rule files and PHP settings: the same crawlers');
        foreach (glob(dirname(__DIR__) . '/rules/crawlers/*.json') ?: [] as $f) {
            truthy(CrawlerLists::parse((string) file_get_contents($f)) !== null, basename($f) . ' is a valid list');
        }
    },
    'RSF01-04 one expression names the crawler -- and names close to each other are told apart' => function (): void {
        $c = Crawlers::of(Settings::from([]));
        $cases = [
            GOOGLEBOT => 'CRAWL-GOOGLE',
            'Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)' => 'CRAWL-GPTBOT',
            'Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot' => 'CRAWL-CHATGPT-USER',
            'Mozilla/5.0 (compatible; OAI-SearchBot/1.0; +https://openai.com/searchbot)' => 'CRAWL-OAI-SEARCH',
            CLAUDEBOT => 'CRAWL-CLAUDEBOT',
            'Claude-User/1.0' => 'CRAWL-CLAUDE-USER',
            'Mozilla/5.0 (compatible; Claude-SearchBot/1.0)' => 'CRAWL-CLAUDE-SEARCH',
            'Mozilla/5.0 (compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)' => 'CRAWL-PERPLEXITY',
            'Perplexity-User/1.0' => 'CRAWL-PERPLEXITY-USER',
            'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)' => 'CRAWL-BING',
            'CCBot/2.0 (https://commoncrawl.org/faq/)' => 'CRAWL-CCBOT',
            'Mozilla/5.0 (X11; Linux x86_64) Firefox/136.0' => null,
            '' => null,
        ];
        foreach ($cases as $ua => $id) {
            same($id, $c->claims((string) $ua), (string) $ua);
        }
    },
    'RSF01-04 verified by the address, never the name: address lists (IPv4, IPv6), DNS, crawler-verify for a DMZ' => function (): void {
        $dnsCalls = 0;
        $reverse = function (string $ip) use (&$dnsCalls) {
            $dnsCalls++;
            return $ip === '203.0.113.66' ? 'crawl-203-0-113-66.googlebot.com' : false;       // not in Google's list: only DNS knows it
        };
        $forward = fn (string $h) => $h === 'crawl-203-0-113-66.googlebot.com' ? ['203.0.113.66'] : [];
        $both = Crawlers::of(Settings::from([]), null, null, null, $reverse, $forward);
        truthy($both->verified(ANTHROPIC_IP, 'CRAWL-CLAUDEBOT'), 'Anthropic\'s list');
        truthy(!$both->verified('198.51.100.9', 'CRAWL-CLAUDEBOT'), 'not in it');
        truthy($both->verified(GOOGLE_IP6, 'CRAWL-GOOGLE'), 'IPv6, Google\'s list');
        same(0, $dnsCalls, 'found in the list: no DNS');
        truthy($both->verified('203.0.113.66', 'CRAWL-GOOGLE'), 'not in the list (here), but its DNS');
        truthy(!$both->verified(ANTHROPIC_IP, 'CRAWL-GOOGLE'), 'another crawler\'s address');
        $dnsCalls = 0;
        $ranges = Crawlers::of(Settings::from(['crawlerVerify' => 'ranges']), null, null, null, $reverse, $forward);
        truthy(!$ranges->verified('203.0.113.66', 'CRAWL-GOOGLE') && $ranges->verified(GOOGLE_IP6, 'CRAWL-GOOGLE'), 'ranges: the lists only');
        same(0, $dnsCalls, 'a DMZ: never a DNS lookup');
        $dns = Crawlers::of(Settings::from(['crawlerVerify' => 'dns']), null, null, null, $reverse, $forward);
        truthy(!$dns->verified(ANTHROPIC_IP, 'CRAWL-CLAUDEBOT'), 'dns: the lists are not used (Anthropic publishes no DNS)');
        $cache = [];
        $cached = Crawlers::of(Settings::from([]), function ($k) use (&$cache) { return $cache[$k] ?? null; }, function ($k, $v) use (&$cache) { $cache[$k] = $v; }, null, $reverse, $forward);
        $cached->verified(ANTHROPIC_IP, 'CRAWL-CLAUDEBOT');
        same([], $cache, 'the list is quicker than remembering it');
        $cached->verified('203.0.113.66', 'CRAWL-GOOGLE');
        same('1', $cache['crawler:CRAWL-GOOGLE:203.0.113.66'] ?? null, 'a DNS answer is remembered per crawler and address');
        $guarded = Crawlers::of(Settings::from([]), null, null, fn (): bool => false, $reverse, $forward);
        $dnsCalls = 0;
        truthy(!$guarded->verified('203.0.113.66', 'CRAWL-GOOGLE') && $dnsCalls === 0, 'no DNS lookups left (dns-lookups): not verified, at once');
    },
    'RSF01-04 what a site does with a verified crawler: allow (never checked), check, block (403); one that only claims the name is an ordinary visitor, noted' => function (): void {
        $pace = "set secret test-secret-0123456789abcdef0123456789abcdef\nlimit requests 100/min challenge-at 0\nchallenge /\n";
        same(Decision::ALLOW, crawlerSettle(crawlerSettings($pace), ANTHROPIC_IP, CLAUDEBOT)->action, 'allow: through where everyone is checked');
        $fake = crawlerSettle(crawlerSettings($pace), '198.51.100.9', CLAUDEBOT);
        same([Decision::CHALLENGE, 'CRAWL-CLAUDEBOT'], [$fake->action, $fake->claimed], 'a fake: checked like anyone, and noted');
        same(Decision::CHALLENGE, crawlerSettle(crawlerSettings($pace . "crawlers ai-training check\n"), ANTHROPIC_IP, CLAUDEBOT)->action, 'check: like any visitor');
        same(Decision::ALLOW, crawlerSettle(crawlerSettings($pace . "crawlers ai-training check\ncrawler CRAWL-CLAUDEBOT allow\n"), ANTHROPIC_IP, CLAUDEBOT)->action, 'one crawler differently from its kind');
        $s = crawlerSettings("crawlers ai-training block\n");
        $shield = new Shield($s, new MemoryStore());
        $r = crawlerReq(ANTHROPIC_IP, CLAUDEBOT);
        $d = $shield->decide($r, 1000.0);
        same([Decision::REJECT, 403, 'crawler'], [$d->action, $d->status, $d->reason], 'block: refused');
        same('site.rules:1', $shield->explain($d, $r), 'by the line that says so');
        same(Decision::ALLOW, $shield->decide(crawlerReq('198.51.100.9', CLAUDEBOT), 1000.0)->action, 'a fake is not refused as the crawler: an ordinary visitor');
        same(Decision::ALLOW, $shield->decide(crawlerReq(ANTHROPIC_IP, 'Mozilla/5.0 Firefox/136.0'), 1000.0)->action, 'the address alone is no crawler');
        same(Decision::CHALLENGE, crawlerSettle(crawlerSettings($pace . "set search-engines off\n"), ANTHROPIC_IP, CLAUDEBOT)->action, 'search-engines off: no crawler is recognised');
        // The spent limit still applies: a crawler gets the pause it understands.
        $spent = crawlerSettings("set secret test-secret-0123456789abcdef0123456789abcdef\nlimit requests 1/min on-exceeded challenge\n");
        $shield = new Shield($spent, new MemoryStore());
        $shield->decide(crawlerReq(ANTHROPIC_IP, CLAUDEBOT), 1000.0);
        $r = crawlerReq(ANTHROPIC_IP, CLAUDEBOT);
        same(Decision::THROTTLE, $shield->settle($shield->decide($r, 1000.0), $r, 1000.0)['decision']->action, 'past the limit: 429, never the check');
    },
    'RSF01-04 the log notes a claimed name; the rules page counts it and lists the crawlers' => function (): void {
        needsPlugins();         // the shipped plugins' pages (the WAF's, the statistics'): not in the core single file
        $dir = sys_get_temp_dir() . '/rshield-crawl-log-' . getmypid() . '-' . mt_rand();
        mkdir($dir);
        try {
            $s = Settings::from(['log' => ['file' => "$dir/shield.log"]]);
            $r = crawlerReq('198.51.100.9', CLAUDEBOT);
            Log::write($s, $r, Decision::challenge('requests')->claiming('CRAWL-CLAUDEBOT'), 'site.rules:3', (float) time());
            Log::write($s, $r, Decision::challenge('requests')->claiming('CRAWL-CLAUDEBOT'), null, (float) time());
            $line = (string) file_get_contents("$dir/shield.log");
            truthy(strpos($line, ' rule=site.rules:3 claimed=CRAWL-CLAUDEBOT "GET ') !== false, $line);
            $st = LogStats::read("$dir/shield.log", time() - 60);
            same(['CRAWL-CLAUDEBOT' => 2], $st['claims']);
            same(1, $st['rules']['site.rules:3']['count'] ?? 0, 'the rule in front of it is still read');
            $html = RulesPage::render(crawlerSettings("set log $dir/shield.log\ncrawlers ai-training block\n"));
            truthy(strpos($html, 'Known crawlers') !== false, 'a group');
            // As many ranges as the shipped list holds (bin/update-crawler-lists changes it, the words stay).
            $ranges = count(json_decode((string) file_get_contents(dirname(__DIR__) . '/rules/crawlers/anthropic.json'), true)['prefixes'] ?? []);
            truthy($ranges > 0 && strpos($html, "collects for AI training: refused (403) — verified by its published address list ($ranges ranges") !== false, "in words ($ranges ranges)");
            truthy(strpos($html, '2× only claimed in 24 h') !== false, 'how often someone only claimed to be it');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF01-04 rule files: a site\'s own crawler, its own address list; policies; the mistakes' => function (): void {
        $dir = crawlerDir(['site.rules' => "[SITE-BOT] crawler ai-search ua /MyBot/ dns .example.org ranges bots.json   # our own\n", 'bots.json' => '{"prefixes": ["192.0.2.0/24"]}']);
        try {
            $s = Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        same(['ai-search', ['.example.org'], ['192.0.2.0/24']], [$s->crawlers['SITE-BOT']['kind'], $s->crawlers['SITE-BOT']['dns'], $s->crawlers['SITE-BOT']['ranges']], 'its own');
        truthy(Crawlers::of($s)->verified('192.0.2.7', 'SITE-BOT') && Crawlers::of($s)->claims('MyBot/2') === 'SITE-BOT', 'recognised and verified');
        crawlerFails("crawler ai-search ua /MyBot/\n", 'site.rules:1', 'the name alone proves nothing');
        crawlerFails("crawler robot ua /MyBot/ dns .example.org\n", 'site.rules:1', 'kinds: search, ai-search, ai-user, ai-training');
        crawlerFails("crawler search ua /My(Bot/ dns .example.org\n", 'site.rules:1', 'not a valid regular expression');
        crawlerFails("crawler search ua /MyBot/ dns example.org\n", 'site.rules:1', 'a suffix starts with a dot');
        crawlerFails("crawler search ua /MyBot/ ranges nosuchlist\n", 'site.rules:1', 'no address list "nosuchlist"');
        crawlerFails("crawler CRAWL-NOBODY block\n", 'site.rules:1', 'no crawler has that ID');
        crawlerFails("crawlers robots block\n", 'site.rules:1', 'crawlers <kind> <policy>');
        crawlerFails("crawlers search maybe\n", 'site.rules:1', 'crawlers <kind> <policy>');
        crawlerFails("set crawler-verify sometimes\n", 'site.rules:1', 'crawler-verify is both, ranges');
        crawlerFails("match /x/** {\n  crawlers search block\n}\n", 'site.rules:2', 'does not go inside a match block');
        same('ranges', crawlerSettings("set crawler-verify ranges\n")->crawlerVerify);
        same(['ai-training' => 'block', 'CRAWL-GPTBOT' => 'check'], crawlerSettings("crawlers ai-training block\ncrawler CRAWL-GPTBOT check\n")->crawlerPolicy);
        // PHP array settings
        same([], Settings::from(['challenge' => ['searchEngines' => false]])->crawlers, 'searchEngines false: none');
        same(['searchEngines[0]'], array_keys(Settings::from(['challenge' => ['searchEngines' => ['/MyBot/i' => ['.example.org']]]])->crawlers), 'the old map: search engines by DNS');
        foreach ([['crawlers' => ['X' => ['kind' => 'robot', 'ua' => '/x/']]], ['crawlerPolicy' => ['nobody' => 'block']], ['crawlerPolicy' => ['search' => 'maybe']], ['crawlerVerify' => 'sometimes'],
            ['crawlers' => ['X' => ['kind' => 'search', 'ua' => '/x/', 'ranges' => ['not-an-address']]]]] as $bad) {
            try {
                Settings::from($bad);
                throw new TestFailure('accepted ' . json_encode($bad));
            } catch (InvalidArgumentException $e) {
                truthy(strpos($e->getMessage(), 'crawler') !== false, $e->getMessage());
            }
        }
    },
    'RSF01-04 updating the address lists: checked, a shrunken list refused, nothing written on failure; the newer list wins when compiled' => function (): void {
        same(['prefixes' => ['192.0.2.0/24', '2001:db8::/32'], 'source' => null, 'created' => '2026-09-01', 'fetched' => null],
            CrawlerLists::parse('{"creationTime": "2026-09-01", "prefixes": [{"ipv4Prefix": "192.0.2.0/24"}, {"ipv6Prefix": "2001:db8::/32"}]}'), 'the operators\' format');
        same(null, CrawlerLists::parse('{"prefixes": ["192.0.2.0/24", "999.1.1.1/8"]}'), 'one bad entry: not trusted');
        same(null, CrawlerLists::parse('{"prefixes": []}'), 'empty: not a list');
        same(null, CrawlerLists::parse('<html>'), 'not JSON');
        same(false, CrawlerLists::isRange('192.0.2.0/33'));
        $dir = crawlerDir(['shipped/a.json' => json_encode(['source' => 'https://a.example/a.json', 'creationTime' => '2026-09-01', 'prefixes' => ['192.0.2.0/24', '192.0.3.0/24']]),
            'shipped/b.json' => json_encode(['source' => 'https://b.example/b.json', 'creationTime' => '2026-09-01', 'prefixes' => ['198.51.100.0/24', '198.51.101.0/24', '198.51.102.0/24']]),
            'shipped/c.json' => json_encode(['source' => 'https://c.example/c.json', 'prefixes' => ['203.0.113.0/24']]),
            'shipped/d.json' => json_encode(['prefixes' => ['203.0.113.0/24']])]);
        try {
            $answers = [
                'https://a.example/a.json' => json_encode(['creationTime' => '2026-09-20', 'prefixes' => [['ipv4Prefix' => '192.0.2.0/24'], ['ipv4Prefix' => '192.0.9.0/24']]]),
                'https://b.example/b.json' => json_encode(['prefixes' => ['198.51.100.0/24']]),     // a third: a broken download
                'https://c.example/c.json' => 'Service Unavailable',
            ];
            $lists = ['a' => "$dir/shipped/a.json", 'b' => "$dir/shipped/b.json", 'c' => "$dir/shipped/c.json", 'd' => "$dir/shipped/d.json"];
            $report = CrawlerLists::update($lists, "$dir/store", fn (string $url) => $answers[$url] ?? false);
            truthy(strncmp($report['a'], 'updated: 2 entries (was 2), created 2026-09-20', 46) === 0, $report['a']);
            truthy(strncmp($report['b'], 'refused: https://b.example/b.json has 1 entries instead of 3', 60) === 0, $report['b']);
            truthy(strncmp($report['c'], 'failed:', 7) === 0, $report['c']);
            truthy(strncmp($report['d'], 'skipped: no https source', 24) === 0, $report['d']);
            same([false, false, false], [is_file("$dir/store/b.json"), is_file("$dir/store/c.json"), is_file("$dir/store/d.json")], 'nothing written for them');
            same(['192.0.2.0/24', '192.0.9.0/24'], CrawlerLists::read("$dir/shipped/a.json", "$dir/store/a.json")['prefixes'], 'read: the newer one');
            same('updated', CrawlerLists::read("$dir/shipped/a.json", "$dir/store/a.json")['from']);
            $before = (string) file_get_contents("$dir/store/a.json");
            $again = CrawlerLists::update(['a' => "$dir/store/a.json"], "$dir/store", fn (string $url) => $answers[$url] ?? false);
            truthy(strncmp($again['a'], 'unchanged: 2 entries', 20) === 0, $again['a']);
            same($before, (string) file_get_contents("$dir/store/a.json"), 'unchanged: not rewritten (a diff shows only real changes)');
            $forced = CrawlerLists::update(['b' => "$dir/shipped/b.json"], "$dir/store", fn (string $url) => json_encode(['prefixes' => ['198.51.100.0/24']]), true);
            truthy(strncmp($forced['b'], 'updated: 1 entries (was 3)', 26) === 0, '--force takes it: ' . $forced['b']);
            file_put_contents("$dir/store/old.json", json_encode(['creationTime' => '2020-01-01', 'prefixes' => ['192.0.2.0/24']]));
            same('shipped', CrawlerLists::read("$dir/shipped/a.json", "$dir/store/old.json")['from'], 'an older list than the shipped one (a new release) is not taken');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        // Compiled with the rules: an updated list in store-dir wins over the shipped one.
        $site = crawlerDir(['site.rules' => '']);
        try {
            $store = "$site/store";
            file_put_contents("$site/site.rules", "set store-dir $store\n");
            mkdir("$store/crawlers", 0700, true);
            file_put_contents("$store/crawlers/anthropic.json", json_encode(['source' => 'https://claude.com/crawling/bots.json', 'creationTime' => '2099-01-01', 'prefixes' => ['192.0.2.0/24']]));
            $read = RuleFile::read(["$site/site.rules"]);
            $s = Settings::from($read['config']);
            same(['192.0.2.0/24'], $s->crawlers['CRAWL-CLAUDEBOT']['ranges'], 'the updated list');
            same('updated', $s->crawlers['CRAWL-CLAUDEBOT']['lists']['anthropic']['from']);
            truthy(isset($read['seen']["$store/crawlers/anthropic.json"]) && isset($read['seen']["$store/crawlers"]), 'watched: a new update recompiles the rules');
            same(['anthropic' => '@anthropic'], array_intersect_key(RuleFile::crawlerListFiles($read['config']), ['anthropic' => 1]), 'what crawlers update fetches: the shipped list by name (Shipped::crawlerList())');
            truthy(isset($read['seen'][(string) \CjwNetwork\RequestShield\Rules\Shipped::crawlerListFile('anthropic')]), 'the shipped list watched (rules/crawlers/anthropic.json, or the single file)');
        } finally {
            exec('rm -rf ' . escapeshellarg($site));
        }
    },
    'RSF01-04 bin: crawlers lists them, update-crawler-lists --check says whether rules/crawlers.php is current' => function (): void {
        if (!function_exists('exec')) {
            skip('no exec');
        }
        $dir = crawlerDir(['site.rules' => "crawlers ai-training block\ncrawler CRAWL-GPTBOT check\n"]);
        try {
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli()) . ' crawlers ' . escapeshellarg("$dir/site.rules") . ' 2>&1', $out, $code);
            $shown = implode("\n", $out);
            same(0, $code, $shown);
            truthy(preg_match('/^CRAWL-GPTBOT\s+ai-training\s+check\s+ranges: openai-gptbot \(\d{4}-\d\d-\d\d, shipped\)$/m', $shown) === 1, $shown);
            truthy(preg_match('/^CRAWL-CLAUDEBOT\s+ai-training\s+block/m', $shown) === 1, 'the kind\'s policy');
            $out = [];
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli()) . ' trace ' . escapeshellarg("$dir/site.rules") . ' "GET /" --ip=' . ANTHROPIC_IP . ' ' . escapeshellarg('--ua=' . CLAUDEBOT) . ' 2>&1', $out, $code);
            same(4, $code, 'refused: exit 4');
            truthy(strpos(implode("\n", $out), 'Known crawlers') !== false, implode("\n", $out));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__) . '/bin/update-crawler-lists') . ' --check 2>&1', $out2, $code);
        same(0, $code, implode("\n", $out2));
    },
];
