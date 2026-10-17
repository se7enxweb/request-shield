<?php

declare(strict_types=1);

/**
 * Examples next to the rules (proposal 0029): expect lines, read and checked
 * with the rules, decided by request-shield test -- never by a request.
 */

use CjwNetwork\RequestShield\Rules\Examples;
use CjwNetwork\RequestShield\Rules\RuleFile;

/**
 * The results of a rule text's examples, as "<status> <at>: <why>" lines.
 *
 * @param array<string, string> $more further files
 * @return array{results: list<array<string, mixed>>, without: list<string>, lines: list<string>}
 */
function examplesOf(string $text, bool $asWritten = false, ?string $only = null, array $more = []): array
{
    $dir = ruleDir(['site.rules' => "set store-dir /nonexistent/never-written\n" . $text] + $more);
    try {
        $run = Examples::run(["$dir/site.rules"], $asWritten, $only);
    } finally {
        exec('rm -rf ' . escapeshellarg($dir));
    }
    $lines = [];
    foreach ($run['results'] as $r) {
        if (strncmp($r['example']['at'], 'built-in', 8) !== 0) {
            $lines[] = $r['status'] . ' ' . $r['example']['at'] . ($r['why'] !== '' ? ': ' . $r['why'] : '');
        }
    }
    return $run + ['lines' => $lines];
}

return [
    'RSF05-04 json-check: the check as JSON only (an api-path, a background request); check takes the page or JSON, json-check never the page' => function (): void {
        $run = examplesOf("[S-API] api-path /api/**\nexpect GET /api/x with pass answered\n[S-CHK] challenge /api/** /admin/**\n"
            . "expect GET /api/x json-check\nexpect GET /api/x check\nexpect GET /admin/menu header Sec-Fetch-Dest:empty json-check\n"
            . "expect GET /admin/menu header X-Requested-With:XMLHttpRequest json-check\nexpect GET /admin/menu check\nexpect GET /admin/menu json-check\n");
        same(['pass site.rules:3', 'pass site.rules:5', 'pass site.rules:6', 'pass site.rules:7', 'pass site.rules:8', 'pass site.rules:9',
            'fail site.rules:10: expected json-check by S-CHK, got check by S-CHK'], $run['lines']);
        $at = array_column(array_map(static fn (array $r): array => ['at' => $r['example']['at'], 'r' => $r], $run['results']), 'r', 'at');
        same('json-check', $at['site.rules:5']['got']);
        truthy(in_array('Content-Type: application/json; charset=utf-8', $at['site.rules:5']['headers'], true), 'its headers: JSON -- ' . implode(' | ', $at['site.rules:5']['headers']));
        same('check', $at['site.rules:9']['got'], 'a navigation: the page');
        truthy(in_array('Content-Type: text/html; charset=utf-8', $at['site.rules:9']['headers'], true), 'its headers: the page');
    },
    'RSF05-04 an example of a feed whose list is not fetched yet is skipped, not failed (0031 F.6)' => function (): void {
        $run = examplesOf("[S-F] feed spamhaus-drop deny\nexpect GET / from 203.0.113.5 403 by S-F\n");
        same(1, count(array_filter($run['lines'], static fn (string $l): bool => strncmp($l, 'skip site.rules:3', 17) === 0)), 'skipped: ' . implode(' | ', $run['lines']));
    },
    'RSF05-04 an example of a deny line is decided -- also the 101st, past the list the pages show (0031 F.6)' => function (): void {
        $lines = '';
        for ($i = 1; $i <= 101; $i++) {
            $lines .= "[S-D$i] deny 203.0.113." . $i . "\n";
        }
        $run = examplesOf($lines . "expect GET / from 203.0.113.101 403 by S-D101\nexpect GET / from 203.0.113.1 403 by S-D1\nexpect GET / from 203.0.113.200 answered\n");
        same(['pass site.rules:103', 'pass site.rules:104', 'pass site.rules:105'], $run['lines']);
    },
    'RSF05-04 demo markers: # demo: opens a group -- the comment lines below explain it, its examples carry its id; # try: rows are kept, not decided (0031 F.3)' => function (): void {
        $dir = ruleDir(['site.rules' => "# demo: RSF02-02 blocked-paths Paths only attackers ask for\n# A scanner asks for backups.\n#   Every one is 404.\n\n"
            . "[S-OLD] block /old/**\nexpect GET /old/x 404\n# not part of the explanation\nexpect GET /oldies answered\n"
            . "# try: GET /old/ the page a visitor sees\n# demo: RSF04-01\nexpect GET / answered\n", 'more.rules' => "expect GET /x answered\n"]);
        try {
            $r = RuleFile::read(["$dir/site.rules"]);
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        same([['id' => 'RSF02-02', 'slug' => 'blocked-paths', 'title' => 'Paths only attackers ask for', 'about' => ['A scanner asks for backups.', '  Every one is 404.'], 'at' => 'site.rules:1'],
            ['id' => 'RSF04-01', 'slug' => '', 'title' => '', 'about' => [], 'at' => 'site.rules:10']], $r['demos'], 'the groups, a bare marker too');
        same(['RSF02-02', 'RSF02-02', 'RSF04-01'], array_column(array_filter($r['examples'], static fn (array $x): bool => strncmp($x['at'], 'site.rules', 10) === 0), 'demo'), 'each example belongs to the group above it');
        same([['demo' => 'RSF02-02', 'method' => 'GET', 'url' => '/old/', 'text' => 'the page a visitor sees', 'at' => 'site.rules:9']], $r['tries'], 'a try row: kept, never decided');
        same(3, count(array_filter($r['examples'], static fn (array $x): bool => strncmp($x['at'], 'site.rules', 10) === 0)), 'a try row is no example');
        // A line that only looks like a marker is a comment: a rule file never fails on one.
        $dir = ruleDir(['site.rules' => "# demo: remove before launch\n# try: block /old/** if spam returns\n# demo: RSF2.2 x\n[S-1] block /a   # demo: RSF02-02 in a comment\n"]);
        try {
            $r = RuleFile::read(["$dir/site.rules"]);
            same([[], []], [$r['demos'], $r['tries']], 'no group, no row');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
        // An include does not end the group; another website's block keeps its markers to itself.
        $dir = ruleDir(['site.rules' => "# demo: RSF02-02\ninclude more.rules\nexpect GET /.env 404 by SCAN-HIDDEN\nsite b.example {\n# demo: RSF04-01\nexpect GET /x answered\n}\nexpect GET /y answered\n",
            'more.rules' => "[M-1] block /m\n"]);
        try {
            $r = RuleFile::read(["$dir/site.rules"]);
            same(['RSF02-02'], array_column($r['demos'], 'id'), 'the group in another website\'s block is not read with the base');
            same(['RSF02-02', 'RSF02-02'], array_column(array_values(array_filter($r['examples'], static fn (array $x): bool => strncmp($x['at'], 'site.rules', 10) === 0)), 'demo'), 'after the include, still the group');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-04 expect … ua "<User-Agent>" and quoted header values; the results carry the status and the headers a visitor gets (0031 F.3)' => function (): void {
        $run = examplesOf("[S-BOT] block header User-Agent regex sqlmap\nexpect GET / 403 ua \"sqlmap/1.7 (https://sqlmap.org)\"\nexpect GET / answered ua \"Mozilla/5.0 (X11; Linux x86_64)\"\n"
            . "expect GET /x answered header Accept-Language:\"de, en;q=0.8\" header X-Note:\"say \\\"hi\\\"\"\nexpect GET /.env 404 by SCAN-HIDDEN\n");
        same(['pass site.rules:3', 'pass site.rules:4', 'pass site.rules:5', 'pass site.rules:6'], $run['lines']);
        $own = array_values(array_filter($run['results'], static fn (array $r): bool => strncmp($r['example']['at'], 'site.rules', 10) === 0));
        same(['sqlmap/1.7 (https://sqlmap.org)', 'Mozilla/5.0 (X11; Linux x86_64)'], [$own[0]['example']['ua'], $own[1]['example']['ua']], 'the User-Agent, spaces and all');
        same(['accept-language' => 'de, en;q=0.8', 'x-note' => 'say "hi"'], $own[2]['example']['headers'], 'a quoted value keeps its spaces; \\" is a quote inside');
        same([403, 200, 200, 404], array_column($own, 'http'), 'the status the visitor gets');
        same([[], true], [$own[1]['headers'], in_array('Cache-Control: no-store', $own[3]['headers'], true)], 'passing: the site\'s own headers; refused: the shield\'s');
        $hash = examplesOf("expect GET / answered ua \"Bot #1 (x)\" header X-Note:\"see #3\"   # the comment\n");
        $x = array_values(array_filter($hash['results'], static fn (array $r): bool => strncmp($r['example']['at'], 'site.rules', 10) === 0))[0]['example'];
        same(['Bot #1 (x)', ['x-note' => 'see #3'], 'the comment'], [$x['ua'], $x['headers'], $x['text']], 'a # inside quotes is part of the value; the comment after them is the comment');
        try {
            rulesFrom("expect GET / answered ua \"never closed\n");
            throw new TestFailure('accepted an open quote');
        } catch (\CjwNetwork\RequestShield\Rules\RuleFileException $e) {
            truthy(strpos($e->getMessage(), 'a quote is not closed') !== false, $e->getMessage());
        }
    },
    'RSF05-04 expect lines: read with the rules, any order after the address -- never part of the settings' => function (): void {
        $plain = "[S-OLD] block /old/**\nmatch /admin/** {\n  [S-ADM] challenge\n}\n";
        $with = "[S-OLD] block /old/**   # old pages\nexpect GET /old/x 404\nexpect GET /oldies answered   # a near miss\n"
            . "match /admin/** {\n  [S-ADM] challenge\n  expect GET /admin/x with pass answered\n  expect GET /admin/x check\n}\nexpect POST /old/y times 3 from 192.0.2.10 404 by S-OLD\n";
        $a = ruleDir(['site.rules' => $plain]);
        $b = ruleDir(['site.rules' => $with]);
        try {
            $ra = RuleFile::read(["$a/site.rules"]);
            $rb = RuleFile::read(["$b/site.rules"]);
            $strip = static function (array $c): array {
                unset($c['origins']['text'], $c['origins']['at']);      // descriptions, and line numbers (the examples move the lines below them)
                unset($c['storeDir'], $c['listsDir']);                  // the store's default is next to each file: two directories here
                return $c;
            };
            same($strip($ra['config']), $strip($rb['config']), 'the same settings with and without examples');
            $own = static fn (array $xs): array => array_values(array_filter($xs, static fn (array $x): bool => strncmp($x['at'], 'built-in', 8) !== 0));
            same([], $own($ra['examples']), 'no examples of its own (the built-in files bring theirs)');
            $x = $own($rb['examples']);
            same(5, count($x), 'five examples');
            same(['GET', '/old/x', '404', null, 'S-OLD', '198.51.100.7', false, 1, null, 'site.rules:2', null],
                array_values(array_intersect_key($x[0], array_flip(['method', 'url', 'outcome', 'by', 'rule', 'from', 'pass', 'times', 'text', 'at', 'site']))),
                'the first: about the rule above it, from a documentation address');
            same(['answered', 'a near miss'], [$x[1]['outcome'], $x[1]['text']], 'the comment is its description');
            same([true, 'answered', 'S-ADM'], [$x[2]['pass'], $x[2]['outcome'], $x[2]['rule']], 'inside a match block: with pass, any order');
            same(['POST', 3, '192.0.2.10', 'S-OLD', 'S-ADM'], [$x[4]['method'], $x[4]['times'], $x[4]['from'], $x[4]['by'], $x[4]['rule']], 'times, from, by');
        } finally {
            exec('rm -rf ' . escapeshellarg($a) . ' ' . escapeshellarg($b));
        }
    },

    'RSF05-04 expect lines: mistakes are errors with file and line' => function (): void {
        rulesFail(['site.rules' => "expect get /x 404\n"], 'site.rules:1', 'is no method');
        rulesFail(['site.rules' => "expect GET x 404\n"], 'site.rules:1', 'a path (/news?page=2)');
        rulesFail(['site.rules' => "expect GET /x 200\n"], 'site.rules:1', '"200"');
        rulesFail(['site.rules' => "expect GET /x by S-1\n"], 'site.rules:1', 'what should happen?');
        rulesFail(['site.rules' => "expect GET /x 404 404\n"], 'site.rules:1', '"404"');
        rulesFail(['site.rules' => "expect GET /x 404 from somewhere\n"], 'site.rules:1', 'one address');
        rulesFail(['site.rules' => "expect GET /x 404 times 0\n"], 'site.rules:1', '"times"');
        rulesFail(['site.rules' => "[S-1] expect GET /x 404\n"], 'site.rules:1', 'an example has no ID');
        rulesFail(['site.rules' => "expect GET /x 404 by S-NONE\n"], 'site.rules:1', 'no rule has that ID');
        rulesFail(['site.rules' => "expect GET /x\n"], 'site.rules:1', 'expect <METHOD> <address>');
    },

    'RSF05-04 decided: refused, checked, passes or uncached -- by the rule above or the one named' => function (): void {
        $run = examplesOf("cache-query page\n[S-OLD] block /old/**\nexpect GET /old/a 404\nexpect GET /old/b 404 by S-OLD\nexpect GET /oldies passes\nexpect GET /x?q=1 uncached\nexpect GET /x?q=1 answered\n"
            . "expect GET /x?page=2 passes\n[S-LOGIN] challenge /login\nexpect GET /login check\nexpect GET /login with pass answered\nexpect GET /old/c 403\nexpect GET /login 404\n[S-OTHER] block /other\nexpect GET /old/d 404\n");
        same(['pass site.rules:4', 'pass site.rules:5', 'pass site.rules:6', 'pass site.rules:7', 'pass site.rules:8', 'pass site.rules:9',
            'pass site.rules:11', 'pass site.rules:12',
            'fail site.rules:13: expected 403 by S-LOGIN, got 404 by S-OLD',
            'fail site.rules:14: expected 404 by S-LOGIN, got check by S-LOGIN',
            'fail site.rules:16: expected 404 by S-OTHER, got 404 by S-OLD'], $run['lines'], 'each with what was expected and what came');
    },

    'RSF05-04 budgets with times, an address with from, a site block\'s host -- each example on a fresh store' => function (): void {
        $run = examplesOf("exempt none\n[S-PACE] limit requests 5/min\nexpect GET /a times 5 passes\nexpect GET /a times 6 429\nexpect GET /a times 5 passes   # a fresh store: not the sixth\n"
            . "[S-INTRA] restrict /intra/** to 192.0.2.0/24\nexpect GET /intra/x 403\nexpect GET /intra/x from 192.0.2.10 passes\n"
            . "site shop.example {\n  [S-SHOP] block /cart/old\n  expect GET /cart/old 404   # the block's host: shop.example\n}\n");
        same(['pass site.rules:4', 'pass site.rules:5', 'pass site.rules:6', 'pass site.rules:8', 'pass site.rules:9', 'pass site.rules:12'], array_slice($run['lines'], 0, 6), 'budgets, addresses, the site block\'s own example');
        same('shop.example', $run['results'][count($run['results']) - 1]['example']['site'], 'decided with the shop\'s settings, its host');
        rulesFail(['site.rules' => "site shop.example {\n  [S-SHOP] block /x\n}\nexpect GET /x 404 by S-SHOP\n"], 'site.rules:4', 'no rule has that ID');
    },

    'RSF05-04 monitor rules: tested switched on; --as-written skips them; a rule taken back: skipped' => function (): void {
        $text = "[S-OLD] monitor block /old/**\nexpect GET /old/a 404\nset mode monitor\n";
        same(['pass site.rules:3'], examplesOf($text)['lines'], 'switched on: monitor enforced, mode monitor as enforce');
        same(['skip site.rules:3: S-OLD is only watched (monitor) -- test without --as-written'], examplesOf($text, true)['lines'], 'as written');
        $taken = examplesOf("unblock [SCAN-BACKUP]\nexpect GET /backup.zip 404 by SCAN-BACKUP\n");
        same(['skip site.rules:3: SCAN-BACKUP is not in effect here (taken back or replaced)'], $taken['lines'], 'taken back');
        truthy(!in_array('fail', array_column($taken['results'], 'status'), true), 'and the built-in examples of SCAN-BACKUP: skipped, not failed');
    },

    'RSF05-04 rules without an example: listed (the site\'s, not the built-in ones); --only' => function (): void {
        $run = examplesOf("[S-A] block /a\nexpect GET /a 404\n[S-B] block /b\n[S-C] challenge /c\nstats-group \"Customer A\" a.example\n");
        same(['S-B', 'S-C'], $run['without'], 'S-B and S-C have none');
        same(['pass site.rules:3'], examplesOf("[S-A] block /a\nexpect GET /a 404\n[S-B] block /b\nexpect GET /b 404\n", false, 'S-A')['lines'], '--only S-A');
    },

    'RSF05-04 the built-in rule files: their examples pass on a plain site, with WordPress and the marketing tags' => function (): void {
        $run = examplesOf("include @wordpress\ninclude @tracking\nquery strict\n");
        $built = array_filter($run['results'], static fn (array $r): bool => strncmp($r['example']['at'], 'built-in', 8) === 0);
        truthy(count($built) >= 20, 'the shipped examples: ' . count($built));
        same([], array_values(array_map(static fn (array $r): string => $r['example']['at'] . ': ' . $r['why'], array_filter($built, static fn (array $r): bool => $r['status'] !== 'pass'))), 'all pass');
        same([], $run['without'], 'built-in rules are never listed as without');
    },

    'RSF05-04 request-shield test: the output, exit 0, 1 and 2, --junit' => function (): void {
        $dir = ruleDir(['ok.rules' => "set store-dir /nonexistent\n[S-A] block /a   # old\nexpect GET /a 404\nexpect GET /ab answered   # a near miss\n",
            'bad.rules' => "set store-dir /nonexistent\n[S-A] block /a\nexpect GET /a passes   # wrong on purpose\n",
            'broken.rules' => "expect GET /a nothing\n"]);
        $bin = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli());
        try {
            exec("$bin test " . escapeshellarg("$dir/ok.rules") . ' --junit=' . escapeshellarg("$dir/r.xml") . ' 2>&1', $out, $code);
            same(0, $code, implode("\n", $out));
            truthy(preg_match('/^S-A\s+✓ GET \/a\s+404 by S-A$/m', implode("\n", $out)) === 1, 'a line per example, the rule once: ' . implode("\n", $out));
            truthy(strpos(implode("\n", $out), 'examples: ') !== false && strpos(implode("\n", $out), ' pass.') !== false, 'the summary');
            $xml = (string) file_get_contents("$dir/r.xml");
            truthy(strpos($xml, '<testsuite name="ok.rules"') !== false && strpos($xml, 'failures="0"') !== false && substr_count($xml, '<testcase') >= 2, 'JUnit for CI');
            $out = [];
            exec("$bin test " . escapeshellarg("$dir/bad.rules") . ' 2>&1', $out, $code);
            same(1, $code, 'one fails: exit 1');
            truthy(strpos(implode("\n", $out), 'expected passes, got 404 by S-A') !== false && strpos(implode("\n", $out), 'wrong on purpose   (bad.rules:3)') !== false, 'what and where: ' . implode("\n", $out));
            $out = [];
            exec("$bin test " . escapeshellarg("$dir/broken.rules") . ' 2>&1', $out, $code);
            same(2, $code, 'a mistake in the files: exit 2');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
];
