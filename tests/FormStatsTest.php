<?php

declare(strict_types=1);

/**
 * Forms counted (proposal 0028, phase 2): each form, from which page, how it
 * ended; the editors' area (backend <paths>) apart -- never what was typed.
 */

use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Stats\Report\StatsReport;
use CjwNetwork\RequestShield\Stats\Report\VisitorsPage;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Rules\RuleFile;
use CjwNetwork\RequestShield\Seen;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Shield;
use CjwNetwork\RequestShield\Stats\StatsPlugin;
use CjwNetwork\RequestShield\Store\MemoryStore;

const FORMS_T0 = 1790856000;    // 2026-10-02 12:00 UTC

/** Settings with statistics in files, and the rule text. */
function formSettings(string $dir, string $rules): Settings
{
    file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nset stats on\nhost www.example.org example.org\nexempt none\n" . $rules);
    return Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
}

/**
 * One request through the shield and the statistics: decided, and -- when the
 * site answers it -- ended with $status.
 *
 * @param array<string, string> $headers
 */
function formSend(Settings $s, string $method, string $path, array $headers = [], int $status = 303, string $body = ''): Decision
{
    $server = ['REQUEST_METHOD' => $method, 'REQUEST_URI' => $path, 'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => '203.0.113.9',
        'HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64) Firefox/136.0'];
    foreach ($headers as $k => $v) {
        $server['HTTP_' . strtoupper(str_replace('-', '_', $k))] = $v;
    }
    $shield = new Shield($s, new MemoryStore());
    $r = Request::fromServer($server);
    $d = $shield->decide($r, (float) FORMS_T0);
    $plugin = new StatsPlugin($s);
    $seen = new Seen($r, $shield);
    $plugin->decided($r, $d, $shield->explain($d, $r), $seen, (float) FORMS_T0, $d->passes());
    if ($d->passes()) {
        $plugin->ended($r, $status, ['Content-Type: text/html'], $seen, (float) FORMS_T0);
    }
    unset($body);       // what was typed never reaches the statistics: there is nothing to pass
    return $d;
}

return [
    'RSF06-03 each form: sent, from which page of the website, how it ended -- another website only by its host' => function (): void {
        $dir = sitesStatsDir();
        try {
            $s = formSettings($dir, "[F-ORIGIN] post-origin same\n");
            formSend($s, 'POST', '/kontakt', ['Origin' => 'https://www.example.org', 'Referer' => 'https://www.example.org/kontakt?ref=nav']);
            formSend($s, 'POST', '/kontakt', ['Origin' => 'https://www.example.org', 'Referer' => 'https://www.example.org/kontakt']);
            formSend($s, 'POST', '/kontakt', ['Origin' => 'https://example.org', 'Referer' => 'https://example.org/produkt/x']);
            formSend($s, 'POST', '/kontakt', ['Origin' => 'https://www.example.org'], 500);                      // an error after sending
            same('reject', formSend($s, 'POST', '/kontakt', ['Origin' => 'https://evil.example', 'Referer' => 'https://evil.example/trap?u=1'])->action, 'from another website: refused');
            same('challenge', formSend($s, 'POST', '/kontakt')->action, 'neither header: checked');
            formSend($s, 'GET', '/kontakt', [], 200);                                                             // a page, not a form
            $r = StatsReport::build($s, null, 1, FORMS_T0);
            same(['/kontakt'], array_keys($r['forms']), 'one form');
            $f = $r['forms']['/kontakt'];
            same([6, 3, 1, 1, 1, 2], [$f['sent'], $f['saved'], $f['error'], $f['cross-site'], $f['checked'], $f['stopped']], 'sent, saved, errors, stopped (another site, checked)');
            $from = $f['from'];
            ksort($from);
            same(['-' => 1, '/kontakt' => 2, '/produkt/x' => 1, '=' => 1, '@evil.example' => 1], $from, 'from: the page (no query), this website without a page, none, another website by its host only');
            same([], $r['backend'], 'no editors\' area named');
            $html = VisitorsPage::render($r, [], [], ['lang' => 'en', 'live' => static fn (string $p): string => '/rs/waf/live?q=' . rawurlencode($p)]);
            truthy(strpos($html, '<h2>Forms <a class="rs-help"') !== false && strpos($html, 'Visitors&#039; forms') !== false, 'the card "Forms"');
            truthy(strpos($html, '3 saved · 1 errors · 2 stopped (1 from another website)') !== false, 'each form in words: ' . $html);
            truthy(strpos($html, 'this website (page not said) 1') !== false && strpos($html, 'another website evil.example 1') !== false && strpos($html, 'no page given 1') !== false, 'where from, in words');
            truthy(strpos($html, 'href="/rs/waf/live?q=%2Fkontakt"') !== false, 'stopped: a link to the live view');
            truthy(strpos(VisitorsPage::render($r, [], [], ['lang' => 'de']), 'Formulare der Besucher') !== false, 'in German');
            $other = sitesStatsDir();
            try {
                $plain = formSettings($other, "set stats requests pages\n");
                formSend($plain, 'POST', '/kontakt', ['Origin' => 'https://www.example.org']);
                same([], StatsReport::build($plain, null, 1, FORMS_T0)['forms'], 'stats without the part "forms": not counted');
            } finally {
                exec('rm -rf ' . escapeshellarg($other));
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },

    'RSF06-03 the editors\' area (backend <paths>): one entry per area, not per address; the API and plain pages are no forms' => function (): void {
        $dir = sitesStatsDir();
        try {
            $s = formSettings($dir, "api-path /api/**\n[F-BACKEND] backend /admin/**\nmatch /redaktion/** {\n  backend\n}\n");
            same(['#^/admin(?:/.*)?$#i', '#^/redaktion(?:/.*)?$#i'], $s->backend, 'the areas, in a block too');
            formSend($s, 'POST', '/admin/content/edit/87/1/ger-DE', ['Origin' => 'https://www.example.org']);
            formSend($s, 'POST', '/admin/content/edit/88/1/ger-DE', ['Origin' => 'https://www.example.org']);
            formSend($s, 'PUT', '/admin/ezjscore/autosave', [], 200);
            formSend($s, 'POST', '/admin/class/edit/1', [], 422);
            formSend($s, 'POST', '/redaktion/x', [], 200);
            formSend($s, 'POST', '/api/orders', [], 201);
            formSend($s, 'POST', '/kontakt', ['Origin' => 'https://www.example.org']);
            $r = StatsReport::build($s, null, 1, FORMS_T0);
            same(['/kontakt'], array_keys($r['forms']), 'the visitors\' forms: no admin address, no API');
            same(['/admin/**' => [4, 2, 1], '/redaktion/**' => [1, 1, 0]], array_map(static fn (array $b): array => [$b['sent'], $b['saved'], $b['error']], $r['backend']),
                'the editors\' area: per area, as written -- saving, autosave and errors together');
            truthy(strpos(VisitorsPage::render($r, [], [], ['lang' => 'en']), 'Editors (backend)') !== false, 'its own tab');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },

    'RSF06-03 several websites read together: each form with its website in front' => function (): void {
        $dir = sitesStatsDir();
        try {
            file_put_contents("$dir/site.rules", "set store file\nset store-dir $dir/store\nset stats on\nset stats-hosts a.de b.de\nexempt none\n");
            $s = Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
            foreach (['a.de', 'b.de'] as $host) {
                $shield = new Shield($s, new MemoryStore());
                $r = Request::fromServer(['REQUEST_METHOD' => 'POST', 'REQUEST_URI' => '/kontakt', 'HTTP_HOST' => $host, 'REMOTE_ADDR' => '203.0.113.9', 'HTTP_REFERER' => "https://$host/kontakt"]);
                $d = $shield->decide($r, (float) FORMS_T0);
                $p = new StatsPlugin($s);
                $seen = new Seen($r, $shield);
                $p->decided($r, $d, null, $seen, (float) FORMS_T0, true);
                $p->ended($r, 303, [], $seen, (float) FORMS_T0);
            }
            same(['a.de/kontakt', 'b.de/kontakt'], array_keys(StatsReport::build($s, null, 1, FORMS_T0)['forms']), 'all websites: with the website');
            same(['/kontakt'], array_keys(StatsReport::build($s, null, 1, FORMS_T0, ['site' => 'a.de'])['forms']), 'one website: the path');
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },

    'RSF06-03 backend in a rule file: in a match block without paths; mistakes name the line' => function (): void {
        rulesFail(['site.rules' => "match /a/** {\n  backend /b\n}\n"], 'site.rules:2', 'backend takes no paths');
        rulesFail(['site.rules' => "backend regex (\n"], 'site.rules:1', 'not a valid regular expression');
        same([], Settings::from([])->backend, 'none by default');
        same(['#^/admin/#'], Settings::from(['backend' => ['#^/admin/#']])->backend, 'PHP settings');
        foreach ([1, 12] as $i) {                                      // 12: past the end of "backend"
            $list = array_fill(0, $i, '#^/admin/#');
            $list[] = '(';
            try {
                Settings::from(['backend' => $list]);
                $msg = 'taken';
            } catch (InvalidArgumentException $e) {
                $msg = $e->getMessage();
            }
            same("request-shield: 'backend[$i]' must be a path pattern (stats-skip **/osm-proxy/** in a rule file)", $msg, "PHP settings: the wrong pattern named by its place ($i)");
        }
    },
];
