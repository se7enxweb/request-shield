<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Shield;

/**
 * The single file (proposal 0002, 0031 E.2): build/single-file.php makes one
 * PHP file per edition. Built into a scratch directory once per run; the
 * cases load it in a fresh PHP, run it as the command line and put a request
 * through it on PHP's built-in server.
 */

/** The built file of an edition (--build=test), made once per run; removed at the end. */
function singleFile(string $edition = 'mini'): string
{
    static $dir = null;
    static $built = [];
    if (!function_exists('exec')) {
        skip('no exec');
    }
    if ($dir === null) {
        $dir = sys_get_temp_dir() . '/rs-single-' . getmypid() . '-' . mt_rand();
        mkdir($dir, 0700, true);
        $remove = $dir;
        register_shutdown_function(static function () use ($remove): void {
            exec('rm -rf ' . escapeshellarg($remove));
        });
    }
    if (!isset($built[$edition])) {
        $file = "$dir/" . ($edition === 'mini' ? 'request-shield.php' : "request-shield-$edition.php");
        [$out, $code] = singleBuild("--edition=$edition --out=" . escapeshellarg($file) . ' --build=test');
        if ($code !== 0) {
            throw new TestFailure("the $edition build failed: " . implode(' | ', $out));
        }
        $built[$edition] = $file;
    }
    return $built[$edition];
}

/** @return array{0: list<string>, 1: int} the build's output and exit code */
function singleBuild(string $args): array
{
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(dirname(__DIR__) . '/build/single-file.php') . " $args 2>&1", $out, $code);
    return [$out, $code];
}

/** @return array{0: list<string>, 1: int} what a PHP snippet printed, and its exit code */
function singlePhp(string $code, string $flags = ''): array
{
    // error_log empty: PHP's own default on the command line, stderr -- the tests read the
    // shield's one-line messages there, also where php.ini sends the log to a file.
    exec(escapeshellarg(PHP_BINARY) . " -d error_log= $flags -r " . escapeshellarg($code) . ' 2>&1', $out, $exit);
    return [$out, $exit];
}

return [
    'RSF05-07 the suite runs on what REQUEST_SHIELD_ENTRY names: the built file, or else the source tree (0031 E.3)' => function (): void {
        $from = (string) (new ReflectionClass(Shield::class))->getFileName();
        same(rsSingle() ?? realpath(dirname(__DIR__) . '/src/Shield.php'), $from, 'where Shield comes from in this run');
        if (rsSingle() !== null) {
            truthy(class_exists(\CjwNetwork\RequestShield\Stats\StatsPlugin::class, false) && (string) (new ReflectionClass(\CjwNetwork\RequestShield\Stats\StatsPlugin::class))->getFileName() === dirname(rsSingle()) . '/request-shield-stats.php',
                'the statistics from the file beside it');
            same(['entry', 'cli'], [basename(rsEntry(), '.php') === 'rs-test-entry' ? 'entry' : rsEntry(), basename(rsCli(), '.php') === 'rs-test-cli' ? 'cli' : rsCli()], 'servers and the command line use it too');
        }
    },
    'RSF05-07 the build: one file that php -l accepts, one declare, nothing read relative to the sources, the version and the build named, byte-identical twice' => function (): void {
        $file = singleFile();
        exec(escapeshellarg(PHP_BINARY) . ' -l ' . escapeshellarg($file) . ' 2>&1', $out, $code);
        same(0, $code, implode(' | ', $out));
        $text = (string) file_get_contents($file);
        same(1, count(array_filter(token_get_all($text), static fn ($t): bool => is_array($t) && $t[0] === T_DECLARE)), 'exactly one declare');
        same(false, strpos($text, "__DIR__ . '/.."), 'nothing relative to the source tree');
        truthy(strpos($text, "public const VERSION = '" . Shield::VERSION . "';") !== false && strpos($text, "public const BUILD = 'test';") !== false, 'the version as the source has it, the build as given');
        truthy(strpos($text, ' * Install (PHP 8.0 or newer') !== false, 'the install guide is the header');
        $again = dirname($file) . '/again.php';
        singleBuild('--out=' . escapeshellarg($again) . ' --build=test');
        same(sha1($text), sha1((string) file_get_contents($again)), 'the same sources, the same bytes');
        unlink($again);
    },
    'RSF05-07 loaded twice, with and without OPcache; the statistics after it, and before it without harm; every class of src/ is there' => function (): void {
        $file = singleFile();
        $stats = singleFile('stats');
        $api = singleFile('api');
        $cache = singleFile('cache');
        $waf = singleFile('waf');
        $classes = [];
        foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator(dirname(__DIR__) . '/src', FilesystemIterator::SKIP_DOTS)) as $f) {
            if ($f instanceof SplFileInfo && $f->getExtension() === 'php' && preg_match('/^namespace ([^;]+);.*?^(?:final |abstract )?(?:class|interface|trait) (\w+)/ms', (string) file_get_contents($f->getPathname()), $m) === 1) {
                $classes[] = $m[1] . '\\' . $m[2];
            }
        }
        truthy(count($classes) > 80, 'found the classes: ' . count($classes));
        foreach (['-d opcache.enable_cli=0', '-d opcache.enable_cli=1'] as $flags) {
            [$out, $code] = singlePhp('require ' . var_export($stats, true) . '; require ' . var_export($file, true) . '; require ' . var_export($file, true) . '; require ' . var_export($stats, true) . '; require ' . var_export($stats, true) . '; require ' . var_export($api, true) . '; require ' . var_export($api, true) . '; require ' . var_export($cache, true) . '; require ' . var_export($waf, true) . ';'
                . '$missing = array_values(array_filter(' . var_export($classes, true) . ', static fn (string $c): bool => !class_exists($c, false) && !interface_exists($c, false) && !trait_exists($c, false)));'
                . 'echo json_encode(["missing" => $missing, "stats" => class_exists("CjwNetwork\\\\RequestShield\\\\Stats\\\\StatsPlugin", false), "api" => class_exists("CjwNetwork\\\\RequestShield\\\\Api\\\\ApiExtension", false), "cache" => class_exists("CjwNetwork\\\\RequestShield\\\\Cache\\\\CachePlugin", false), "waf" => class_exists("CjwNetwork\\\\RequestShield\\\\Waf\\\\SetupPage", false), "done" => defined("REQUEST_SHIELD_DONE")]);', $flags);
            $got = json_decode((string) end($out), true);
            truthy($code === 0 && is_array($got), "$flags: " . implode(' | ', $out));
            same(['missing' => [], 'stats' => true, 'api' => true, 'cache' => true, 'waf' => true, 'done' => false], $got, "$flags: every class, the statistics, the API, the cache, the WAF's pages; required by a script on the command line, nothing protected");
            truthy(strpos(implode("\n", $out), 'needs request-shield.php loaded first') !== false, 'the statistics before the core: one line in the error log, nothing declared');
        }
    },
    'RSF05-07 the file is the command line: version names the build, check comes to what bin/request-shield comes to' => function (): void {
        $file = singleFile();
        $dir = dirname($file) . '/cli';
        @mkdir($dir);
        file_put_contents("$dir/site.rules", "host a.example\ninclude @wordpress\n[OWN-1] block /secret/**\n");
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($file) . ' version 2>&1', $out, $code);
        same(0, $code, implode(' | ', $out));
        same('request-shield ' . Shield::VERSION . ' (test)', $out[0] ?? '');
        truthy(preg_match('/^shipped rule sets: @attacks \d{4}\.\d{2}\.\d+ · @crawlers /', $out[2] ?? '') === 1, 'the embedded sets with their versions: ' . ($out[2] ?? ''));
        $check = static function (string $tool) use ($dir): array {
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg($tool) . ' check ' . escapeshellarg("$dir/site.rules") . ' 2>&1', $out, $code);
            return [$code, array_values(preg_grep('/^ok:/', $out) ?: [])];
        };
        [$binCode, $binOk] = $check(dirname(__DIR__) . '/bin/request-shield');
        [$miniCode, $miniOk] = $check($file);
        same($binOk, $miniOk, 'the same verdict');
        same([3, 0], [$binCode, $miniCode], 'the repository warns that its pages are unguarded (3); the mini file has no pages, so nothing to guard (0)');
    },
    'RSF05-07 a request through the file (auto_prepend_file): the rules found next to it, a scanner refused, a page let through' => function (): void {
        if (!function_exists('proc_open')) {
            skip('no proc_open');
        }
        $file = singleFile();
        $dir = dirname($file) . '/site';
        @mkdir("$dir/docroot", 0700, true);
        copy($file, "$dir/request-shield.php");
        file_put_contents("$dir/request-shield.rules", "host 127.0.0.1\nset recheck 0\ninclude @wordpress\n");
        file_put_contents("$dir/docroot/index.php", '<?php echo "site " . ($_SERVER["REQUEST_SHIELD"] ?? "-");');
        $port = freePort();
        $proc = proc_open(sprintf('exec env -u REQUEST_SHIELD_CONFIG %s -d auto_prepend_file=%s -S 127.0.0.1:%d -t %s > /dev/null 2>&1',
            serverPhp(), escapeshellarg("$dir/request-shield.php"), $port, escapeshellarg("$dir/docroot")), [], $pipes);
        for ($i = 0; $i < 50 && !@fsockopen('127.0.0.1', $port); $i++) {
            usleep(100000);
        }
        try {
            $get = static function (string $path) use ($port): array {
                $body = (string) @file_get_contents("http://127.0.0.1:$port$path", false, stream_context_create(['http' => ['ignore_errors' => true, 'timeout' => 10]]));
                return [preg_match('#^HTTP/\S+ (\d+)#', $http_response_header[0] ?? '', $m) === 1 ? (int) $m[1] : 0, $body];
            };
            [$status, $body] = $get('/');
            same([200, 'site allow'], [$status, $body], 'a page: the site, told the shield let it through');
            [$status, $body] = $get('/wp-login.php');
            truthy($status >= 400 && strpos($body, 'site ') !== 0, "@wordpress from the embedded set: $status");
            [$status] = $get('/.env');
            truthy($status >= 400, "a hidden file (built-in scanners.rules): $status");
            truthy(is_dir("$dir/.request-shield"), 'the store next to the rules, as from the source tree');
        } finally {
            proc_terminate($proc);
            proc_close($proc);
        }
    },
    'RSF05-07 the visitors\' scripts lose indentation and comment lines only, and stay JavaScript' => function (): void {
        $file = singleFile();
        $read = 'require ' . var_export($file, true) . '; echo json_encode([\\CjwNetwork\\RequestShield\\Challenge\\ChallengePage::SCRIPT, (new ReflectionClassConstant(\\CjwNetwork\\RequestShield\\Challenge\\Widget::class, "BOX"))->getValue()]);';
        [$out] = singlePhp($read);
        $built = json_decode(implode("\n", $out), true);
        truthy(is_array($built) && count($built) === 2, implode(' | ', $out));
        // The scripts as the sources have them (this process may run on the single file itself).
        [$src] = singlePhp(str_replace('require ' . var_export($file, true), 'require ' . var_export(dirname(__DIR__) . '/bootstrap.php', true), $read));
        $source = json_decode(implode("\n", $src), true);
        truthy(is_array($source) && count($source) === 2, implode(' | ', $src));
        $node = nodeBinary();
        foreach ($source as $i => $js) {
            $lines = array_values(array_filter(array_map('trim', explode("\n", (string) $js)), static fn (string $l): bool => $l !== '' && strncmp($l, '//', 2) !== 0));
            same(implode("\n", $lines), $built[$i], 'each line as written, without its indentation');
            truthy(strlen($built[$i]) < strlen((string) $js), 'shorter: ' . strlen($built[$i]) . ' < ' . strlen((string) $js));
            if ($node !== null) {
                $tmp = sys_get_temp_dir() . '/rs-single-js-' . getmypid() . ".js";
                file_put_contents($tmp, $built[$i]);
                exec(escapeshellarg($node) . ' --check ' . escapeshellarg($tmp) . ' 2>&1', $nout, $ncode);
                unlink($tmp);
                same(0, $ncode, 'node --check: ' . implode(' | ', $nout));
            }
        }
        if ($node === null) {
            skip('node not installed: the scripts are compared line by line, not parsed');
        }
    },
    'RSF05-07 the mini file has no page of the dashboard (0031 G.3: they are the WAF edition\'s); an unknown edition is refused' => function (): void {
        $mini = (string) file_get_contents(singleFile());
        truthy(strpos($mini, 'namespace CjwNetwork\\RequestShield\\Waf') === false && strpos($mini, 'class SetupPage') === false, 'no Waf\\ class in the mini file');
        truthy(strpos((string) file_get_contents(singleFile('waf')), 'final class SetupPage') !== false, 'the WAF edition has them');
        [$out, $code] = singleBuild('--edition=full');
        truthy($code === 1 && strpos(implode("\n", $out), 'no edition "full"') !== false, implode(' | ', $out));
    },
];
