<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Tests\RsTestExtension;

/**
 * The shield serves the dashboard's pages itself (0031 B.6): a route below
 * dashboard-path is answered before the application, behind Access::gate()
 * and the route's role, with no-store and noindex -- a site wires nothing.
 * End to end on PHP's built-in server, like RobustnessTest; the test
 * extension's /rs-test/ping is the smallest page.
 */

/**
 * A site behind the shield, the shield started by a prepend file that also
 * loads the test extension and the test plugins (tests/support/*.php; the
 * statistics, the API and the test extension named in REQUEST_SHIELD_EXTENSIONS before the bootstrap defines
 * the shipped list). "__DIR__" in the rules is the test's directory.
 *
 * @param callable(callable(string, string=, array<string, string>=, ?string=): array{status: int, body: string, headers: list<string>}, string): void $body
 */
function withDashboard(string $rules, callable $body): void
{
    $dir = sys_get_temp_dir() . '/rs-dash-' . getmypid() . '-' . mt_rand();
    mkdir("$dir/docroot", 0700, true);
    file_put_contents("$dir/docroot/index.php", '<?php echo "site " . ($_SERVER["REQUEST_SHIELD"] ?? "-") . " " . $_SERVER["REQUEST_URI"];');
    file_put_contents("$dir/site.rules", "set recheck 0\nset store file\nset store-dir $dir/store\n" . str_replace('__DIR__', $dir, $rules));
    file_put_contents("$dir/prepend.php", '<?php define("REQUEST_SHIELD_EXTENSIONS", ["CjwNetwork\\\\RequestShield\\\\Stats\\\\StatsExtension", "CjwNetwork\\\\RequestShield\\\\Api\\\\ApiExtension", "CjwNetwork\\\\RequestShield\\\\Waf\\\\WafExtension", "CjwNetwork\\\\RequestShield\\\\Tests\\\\RsTestExtension"]);'
        . 'require ' . var_export(rsEntry(), true) . '; foreach (glob(' . var_export(__DIR__ . '/support/*.php', true) . ') as $f) { require $f; }' . "\n"
        . '\CjwNetwork\RequestShield\Shield::protectFile(' . var_export("$dir/site.rules", true) . ', null, ' . var_export("$dir/cache", true) . ');');
    $port = freePort();
    $proc = proc_open(sprintf('REQUEST_SHIELD_CONFIG=/nonexistent exec %s -d auto_prepend_file=%s -S 127.0.0.1:%d -t %s > /dev/null 2>&1',
        serverPhp(), escapeshellarg("$dir/prepend.php"), $port, escapeshellarg("$dir/docroot")), [], $pipes);
    for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
        usleep(100000);
    }
    try {
        $body(static function (string $uri, string $method = 'GET', array $headers = [], ?string $post = null) use ($port): array {
            $h = '';
            foreach ($headers as $k => $v) {
                $h .= "$k: $v\r\n";
            }
            if ($post !== null) {
                $h .= "Content-Type: application/x-www-form-urlencoded\r\n";
            }
            $ctx = stream_context_create(['http' => ['method' => $method, 'header' => $h, 'content' => $post ?? '', 'ignore_errors' => true, 'timeout' => 10]]);
            $body = (string) @file_get_contents("http://127.0.0.1:$port$uri", false, $ctx);
            $lines = $http_response_header ?? [];
            $status = preg_match('#^HTTP/\S+ (\d+)#', $lines[0] ?? '', $m) ? (int) $m[1] : 0;
            return ['status' => $status, 'body' => $body, 'headers' => array_slice($lines, 1)];
        }, $dir);
    } finally {
        proc_terminate($proc);
        proc_close($proc);
        exec('rm -rf ' . escapeshellarg($dir));
    }
}

/** The header lines of one name, lower-cased values joined. */
function dashHeader(array $lines, string $name): string
{
    $found = [];
    foreach ($lines as $l) {
        if (stripos($l, $name . ':') === 0) {
            $found[] = strtolower(trim(substr($l, strlen($name) + 1)));
        }
    }
    return implode(' | ', $found);
}

return [
    'RSF06-01 behind a restrict rule: the shield answers the pages itself, with no-store and noindex; the site never sees them; an unknown page below dashboard-path is the site\'s' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withDashboard("set dashboard-path /rs\n[T-ADMIN] restrict **/rs/** to 127.0.0.1 ::1\n", function (callable $get): void {     // **/rs/**: behind a front controller too (/index.php/rs/...)
            $r = $get('/rs/waf/live?lang=en');
            same(200, $r['status'], 'the live view');
            truthy(strpos($r['body'], 'class="tab on"') !== false && strpos($r['body'], '/rs/waf/lists?lang=en') !== false, 'the core\'s frame with the tabs: ' . substr($r['body'], 0, 200));
            truthy(strpos($r['body'], 'site allow') === false, 'nothing of the site');
            same('private, no-store', dashHeader($r['headers'], 'Cache-Control'), 'never kept');
            same('noindex, nofollow', dashHeader($r['headers'], 'X-Robots-Tag'), 'never indexed');
            truthy(stripos(dashHeader($r['headers'], 'Content-Type'), 'text/html') === 0, 'HTML');
            $json = json_decode($get('/rs/api/v1/live')['body'], true);
            truthy(is_array($json) && array_key_exists('rows', (array) ($json['data'] ?? null)), 'the live rows as JSON, from the API: ' . substr((string) json_encode($json), 0, 300));
            same(200, $get('/rs/waf')['status'], 'the start alias');
            same(200, $get('/rs/waf/lists')['status'], 'the lists');
            same(200, $get('/rs/waf/rules?lang=de')['status'], 'rules and setup');
            truthy(strpos($get('/rs/waf/rules?lang=de')['body'], 'Der Weg einer Anfrage') !== false, 'the way, in German');
            // The test extension's page: who reads, and nothing stood before the route.
            $ping = json_decode($get('/rs/rs-test/ping')['body'], true);
            same(['pong' => true, 'who' => '*', 'prefix' => '', 'key' => 'ping', 'method' => 'GET'], $ping, 'an extension\'s route, served');
            // Behind a front controller: the prefix is what stood before the route.
            $ping = json_decode($get('/index.php/rs/rs-test/ping')['body'], true);
            same('/index.php', $ping['prefix'] ?? null, 'the prefix: links are built with it');
            // Not a route: the site's, as always.
            $r = $get('/rs/nothing-here');
            same(200, $r['status']);
            truthy(strncmp($r['body'], 'site allow', 10) === 0, 'the site answers');
            // A change to the lists needs the page\'s token (CSRF).
            $r = $get('/rs/waf/lists', 'POST', [], 'do=remove&id=LIST-D1');
            truthy(strpos($r['body'], 'too old or not from this page') !== false, 'without the token: refused');
        });
    },
    'RSF06-01 the statistics on a path of their own, outside dashboard-path: the shield serves them there too' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withDashboard("set dashboard-path /rs\nset stats on\nset stats-path /admin/statistics\n[T-ADMIN] restrict **/rs/** **/admin/statistics** to 127.0.0.1 ::1\n", function (callable $get): void {
            $r = $get('/admin/statistics/overview?lang=en');
            same(200, $r['status'], 'the overview: ' . substr($r['body'], 0, 200));
            truthy(strncmp($r['body'], 'site ', 5) !== 0, 'answered by the shield, not the site');
            same('private, no-store', dashHeader($r['headers'], 'Cache-Control'), 'never kept');
            same(200, $get('/rs/waf/live')['status'], 'the core\'s pages stay below dashboard-path');
            truthy(strncmp($get('/admin/other')['body'], 'site ', 5) === 0, 'the site\'s own admin pages are the site\'s');
        });
    },
    'RSF06-01 nobody guards the pages: the shield refuses them and check says what to do' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withDashboard("set dashboard-path /rs\n", function (callable $get, string $dir): void {
            $r = $get('/rs/waf/live');
            same(403, $r['status'], 'refused: no restrict rule covers it, no login is set up');
            truthy(strpos($r['body'], 'restrict') !== false, 'and says so: ' . $r['body']);
            same('private, no-store', dashHeader($r['headers'], 'Cache-Control'));
            same(403, $get('/rs/rs-test/ping')['status'], 'an extension\'s page too');
            if (!function_exists('exec')) {
                skip('no exec');
            }
            exec(sprintf('%s %s check %s 2>&1', PHP_BINARY, escapeshellarg(rsCli()), escapeshellarg("$dir/site.rules")), $out, $exit);
            $text = implode("\n", $out);
            truthy(strpos($text, "warning: the dashboard's pages are open to everyone (") !== false && strpos($text, 'restrict /rs/** to') !== false && substr_count($text, 'open to everyone') === 1, 'check warns once, naming the fix: ' . $text);
        });
    },
    'RSF06-01 mode monitor: the restrict rule refuses nobody, but the shield\'s own pages still hold it' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withDashboard("set mode monitor\nset dashboard-path /rs\ntrust 127.0.0.1\n[T-ADMIN] restrict /rs/** to 192.0.2.0/24\n", function (callable $get): void {
            $r = $get('/rs/waf/live', 'GET', ['X-Forwarded-For' => '203.0.113.9']);
            same(403, $r['status'], 'another address: refused by the page, although the rule only watched');
            truthy(strpos($r['body'], 'only for certain addresses') !== false, 'and says why: ' . $r['body']);
            same(403, $get('/rs/rs-test/ping', 'GET', ['X-Forwarded-For' => '203.0.113.9'])['status'], 'an extension\'s page too');
            $r = $get('/rs/rs-test/ping', 'GET', ['X-Forwarded-For' => '192.0.2.7']);
            same(200, $r['status'], 'the office: through, and the page');
        });
    },
    'RSF06-01 a route from an address the restrict rule keeps out is refused by the rule, before any page' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        withDashboard("set dashboard-path /rs\ntrust 127.0.0.1\n[T-ADMIN] restrict /rs/** to 192.0.2.0/24\n", function (callable $get): void {
            same(403, $get('/rs/waf/live', 'GET', ['X-Forwarded-For' => '203.0.113.9'])['status'], 'another address: the restrict rule');
            $r = $get('/rs/rs-test/ping', 'GET', ['X-Forwarded-For' => '192.0.2.7']);
            same(200, $r['status'], 'the office: through, and the page');
            same('*', json_decode($r['body'], true)['who'] ?? null, 'the administrator');
        });
    },
];
