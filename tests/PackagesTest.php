<?php
/**
 * This file is part of cjw-network/request-shield.
 *
 * @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
 * @license MIT, see LICENSE
 */

declare(strict_types=1);

/*
 * The subpackages (0031 H.1): every plugin directory and testkit/ is a
 * Composer package of its own, mirrored read-only from H.2 on. Checked here:
 * its papers, its autoload against the core's, the plugins it uses against
 * what it requires -- and an install from path repositories against a core
 * without the plugins (a path repository links the directory: what its archive
 * leaves out is checked by the .gitattributes test above it).
 */

/** The subpackages: directory => [package, namespace below CjwNetwork\RequestShield\, or null]. */
function rsPackages(): array
{
    return [
        'plugins/api' => ['cjw-network/request-shield-api', 'Api'],
        'plugins/waf' => ['cjw-network/request-shield-waf', 'Waf'],
        'plugins/stats' => ['cjw-network/request-shield-stats', 'Stats'],
        'plugins/cache' => ['cjw-network/request-shield-cache', 'Cache'],
        'testkit' => ['cjw-network/request-shield-testkit', null],
    ];
}

/** A package's composer.json, decoded. */
function rsPackageJson(string $dir): array
{
    $json = json_decode((string) file_get_contents(dirname(__DIR__) . "/$dir/composer.json"), true);
    if (!is_array($json)) {
        throw new TestFailure("$dir/composer.json: no JSON");
    }
    return $json;
}

/** Composer 2, or null. */
function rsComposer(): ?string
{
    foreach ([(string) getenv('COMPOSER_BINARY'), 'composer', '/usr/local/bin/composer'] as $c) {
        if ($c !== '' && preg_match('/Composer (?:version )?2\./', (string) shell_exec(escapeshellarg($c) . ' --version 2>/dev/null')) === 1) {
            return $c;
        }
    }
    return null;
}

return [
    'Packages: every subpackage has its papers -- composer.json with its name, MIT, the core ^1.0; LICENSE as the core\'s; README, CHANGELOG with an Unreleased section, SECURITY.md; a .gitattributes that leaves only its tests out' => function (): void {
        $root = dirname(__DIR__);
        foreach (rsPackages() as $dir => [$name, $ns]) {
            $json = rsPackageJson($dir);
            same([$name, 'library', 'MIT', '>=8.0'], [$json['name'] ?? null, $json['type'] ?? null, $json['license'] ?? null, $json['require']['php'] ?? null], "$dir: name, type, license, PHP");
            if ($ns !== null) {
                same('^1.0', $json['require']['cjw-network/request-shield'] ?? null, "$dir requires the core");
            }
            same(file_get_contents("$root/LICENSE"), @file_get_contents("$root/$dir/LICENSE"), "$dir/LICENSE");
            foreach (['README.md', 'SECURITY.md'] as $paper) {
                truthy(is_file("$root/$dir/$paper"), "$dir/$paper");
            }
            truthy(str_contains((string) @file_get_contents("$root/$dir/CHANGELOG.md"), "\n## Unreleased\n"), "$dir/CHANGELOG.md has an Unreleased section");
            // In the monorepo a nested .gitattributes applies to its directory: leaving out more than the tests would thin the core's archive too.
            $ignored = [];
            foreach (file("$root/$dir/.gitattributes") ?: [] as $line) {
                if (preg_match('/^(\S+)\s+export-ignore\b/', $line, $m) === 1) {
                    $ignored[] = $m[1];
                }
            }
            same(['/tests', '/.gitattributes'], $ignored, "$dir/.gitattributes leaves out");
        }
    },

    'Packages: a README links into the monorepo with absolute addresses (a mirror has no docs/) and to its own papers' => function (): void {
        $root = dirname(__DIR__);
        foreach (array_keys(rsPackages()) as $dir) {
            preg_match_all('/\]\(([^)\s]+)\)/', (string) file_get_contents("$root/$dir/README.md"), $m);
            foreach ($m[1] as $link) {
                if (str_starts_with($link, 'https://github.com/cjw-network/request-shield/blob/main/')) {
                    $path = substr($link, strlen('https://github.com/cjw-network/request-shield/blob/main/'));
                    truthy(is_file("$root/" . explode('#', $path)[0]), "$dir/README.md: $link -- no such file in the monorepo");
                } elseif (!str_starts_with($link, 'https://')) {
                    truthy(is_file("$root/$dir/$link"), "$dir/README.md: $link is relative and not one of its own papers");
                }
            }
        }
    },

    'Packages: a plugin autoloads its src/ under the namespace the core\'s composer.json and bootstrap.php give it, and the core names its extension' => function (): void {
        needsPlugins();                 // the core single file names no extension
        $root = dirname(__DIR__);
        $core = rsPackageJson('.')['autoload']['psr-4'] ?? [];
        $boot = (string) file_get_contents("$root/bootstrap.php");
        foreach (rsPackages() as $dir => [, $ns]) {
            if ($ns === null) {
                continue;
            }
            $prefix = "CjwNetwork\\RequestShield\\$ns\\";
            same([$prefix => 'src/'], rsPackageJson($dir)['autoload']['psr-4'] ?? null, "$dir: its autoload");
            same("$dir/src/", $core[$prefix] ?? null, "the core's autoload of $prefix");
            truthy(str_contains($boot, "'$ns\\\\' => '/$dir/src/'"), "bootstrap.php loads $prefix from $dir/src/");
            truthy(in_array($prefix . $ns . 'Extension', (array) REQUEST_SHIELD_EXTENSIONS, true), "REQUEST_SHIELD_EXTENSIONS names {$ns}Extension");
        }
    },

    'Packages: a plugin uses another plugin only if it requires it, or suggests it and checks class_exists() in that file first' => function (): void {
        $root = dirname(__DIR__);
        $byNs = [];
        foreach (rsPackages() as [$name, $ns]) {
            if ($ns !== null) {
                $byNs[$ns] = $name;
            }
        }
        foreach (rsPackages() as $dir => [$name, $ns]) {
            if ($ns === null) {
                continue;
            }
            $json = rsPackageJson($dir);
            foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator("$root/$dir/src", FilesystemIterator::SKIP_DOTS)) as $file) {
                $code = (string) file_get_contents((string) $file);
                // A grouped use (use CjwNetwork\RequestShield\{Api\A, Stats\B};) written out: each name in full.
                $code = (string) preg_replace_callback('/(CjwNetwork\\\\RequestShield\\\\)\{([^}]*)\}/', static fn (array $g): string
                    => implode(', ', array_map(static fn (string $n): string => $g[1] . trim($n), explode(',', $g[2]))), $code);
                // A name as code writes it (one backslash), in a string ('\\\\') or in a grouped use (RequestShield\{Api\X}).
                $sep = '(?:\\\\\\\\|\\\\)';
                preg_match_all('/CjwNetwork' . $sep . 'RequestShield' . $sep . '\\{?\\s*(' . implode('|', array_keys($byNs)) . ')' . $sep . '/', $code, $m, PREG_OFFSET_CAPTURE);
                $uses = [];
                foreach ($m[1] as [$other, $at]) {
                    $uses[$other][] = $at;
                }
                foreach ($uses as $other => $offsets) {
                    if ($other === $ns) {
                        continue;
                    }
                    $pkg = $byNs[$other];
                    $where = substr((string) $file, strlen($root) + 1);
                    if (isset($json['require'][$pkg])) {
                        continue;
                    }
                    truthy(isset($json['suggest'][$pkg]), "$where uses $other\\ -- $name neither requires nor suggests $pkg");
                    // Every use after a class_exists() of that plugin, on its line or at most 20 lines above (in the same method, as written now).
                    foreach ($offsets as $at) {
                        $end = strpos($code, "\n", $at);
                        $above = implode("\n", array_slice(explode("\n", substr($code, 0, $end === false ? null : $end)), -21));
                        truthy(preg_match('/class_exists\(\\\\?CjwNetwork' . $sep . 'RequestShield' . $sep . $other . $sep . '/', $above) === 1,
                            "$where:" . (substr_count($code, "\n", 0, $at) + 1) . " uses $other\\ (suggested only) without a class_exists() of it just before");
                    }
                }
            }
        }
    },

    'Packages: composer validate --strict passes for every subpackage' => function (): void {
        $composer = rsComposer();
        if ($composer === null) {
            skip('no Composer 2');
        }
        foreach (array_keys(rsPackages()) as $dir) {
            $out = [];
            exec(escapeshellarg($composer) . ' validate --strict --no-check-publish --no-interaction -d ' . escapeshellarg(dirname(__DIR__) . "/$dir") . ' 2>&1', $out, $code);
            same(0, $code, "$dir: " . implode("\n", $out));
        }
    },

    'Packages: each plugin installs from a path repository next to a core without plugins -- with what it requires, without the rest; its words are known, the others\' are not' => function (): void {
        $composer = rsComposer();
        if ($composer === null || !function_exists('exec')) {
            skip('no Composer 2');
        }
        $root = dirname(__DIR__);
        $tmp = sys_get_temp_dir() . '/rs-pkg-' . getmypid() . '-' . mt_rand();
        try {
            // The core as a mirror of the root will be once the plugins are packages (0031 H.2): its code, no plugin directories.
            mkdir("$tmp/core/plugins", 0777, true);
            foreach (['src', 'bin', 'rules', 'bootstrap.php'] as $part) {
                symlink("$root/$part", "$tmp/core/$part");
            }
            symlink("$root/plugins/shipped.php", "$tmp/core/plugins/shipped.php");
            $core = rsPackageJson('.');
            unset($core['require-dev'], $core['scripts']);
            $core['autoload']['psr-4'] = ['CjwNetwork\\RequestShield\\' => 'src/'];
            file_put_contents("$tmp/core/composer.json", json_encode($core, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
            // The core's own name (a fork renames it and replaces cjw-network/request-shield, which the plugins require).
            $coreName = (string) $core['name'];
            $versions = [$coreName => '1.0.0'];
            // Composer finds a package that replaces another only when it is required itself: under another name the
            // core is required next to the plugin, as a project using the renamed core does.
            $coreRequire = $coreName === 'cjw-network/request-shield' ? [] : [$coreName => '^1.0'];
            foreach (rsPackages() as [$name]) {
                $versions[$name] = '1.0.0';
            }
            $repos = [['type' => 'path', 'url' => "$tmp/core", 'options' => ['versions' => $versions]]];
            foreach (array_keys(rsPackages()) as $dir) {
                $repos[] = ['type' => 'path', 'url' => "$root/$dir", 'options' => ['versions' => $versions]];
            }
            $repos[] = ['packagist.org' => false];
            $words = ['Api' => "set api-write on\n", 'Stats' => "set stats on\n", 'Cache' => "set http-cache on\nset http-cache-hosts www.example.org\n", 'Waf' => ''];
            $expect = ['Api' => [], 'Waf' => ['Api'], 'Stats' => [], 'Cache' => []];
            foreach (rsPackages() as $dir => [$name, $ns]) {
                if ($ns === null) {
                    continue;
                }
                $project = "$tmp/p-$ns";
                mkdir($project);
                file_put_contents("$project/composer.json", json_encode(['repositories' => $repos, 'require' => $coreRequire + [$name => '^1.0']], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES));
                $out = [];
                exec('COMPOSER_HOME=' . escapeshellarg("$tmp/home") . ' ' . escapeshellarg($composer) . ' install --no-dev --no-interaction --no-progress --no-plugins -d ' . escapeshellarg($project) . ' 2>&1', $out, $code);
                same(0, $code, "$name installs: " . implode("\n", array_slice($out, -15)));
                $installed = json_decode((string) file_get_contents("$project/vendor/composer/installed.json"), true);
                $got = array_map(static fn (array $p): string => (string) $p['name'], (array) ($installed['packages'] ?? []));
                sort($got);
                $want = array_merge([$coreName, $name], array_map(static fn (string $n): string => rsPackages()['plugins/' . strtolower($n)][0], $expect[$ns]));
                sort($want);
                same($want, $got, "$name brings exactly what it requires");
                // Every class of the plugin loads (its interfaces and parents from the core and what it requires); its words are known.
                $rules = "$project/site.rules";
                file_put_contents($rules, $words[$ns]);
                $others = array_diff_key($words, [$ns => true], array_flip($expect[$ns]));
                $probe = '<?php require ' . var_export("$project/vendor/autoload.php", true) . ";\n"
                    . '$dir = ' . var_export("$project/vendor/$name/src", true) . ";\n"
                    . 'foreach (new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir, FilesystemIterator::SKIP_DOTS)) as $f) {'
                    . ' $c = ' . var_export("CjwNetwork\\RequestShield\\$ns\\", true) . ' . str_replace("/", "\\\\", substr((string) $f, strlen($dir) + 1, -4));'
                    . ' if (!class_exists($c) && !interface_exists($c)) { echo "missing $c\n"; } }' . "\n"
                    . 'try { \CjwNetwork\RequestShield\Rules\RuleFile::read([' . var_export($rules, true) . ']); echo "own: known\n"; } catch (Throwable $e) { echo "own: ", $e->getMessage(), "\n"; }' . "\n"
                    . 'foreach (' . var_export(array_values(array_filter($others)), true) . ' as $w) { $f = tempnam(sys_get_temp_dir(), "rs"); file_put_contents($f, $w);'
                    . ' try { \CjwNetwork\RequestShield\Rules\RuleFile::read([$f]); echo "other: known ", trim($w), "\n"; } catch (Throwable $e) { } unlink($f); }' . "\n";
                file_put_contents("$project/probe.php", $probe);
                $res = trim((string) shell_exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg("$project/probe.php") . ' 2>&1'));
                same('own: known', $res, "$name: its classes load, its words are known, no other plugin's");
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($tmp));
        }
    },
];
