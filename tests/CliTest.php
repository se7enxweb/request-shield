<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Shield;

/** @return array{0: list<string>, 1: int} the CLI's output lines and exit code */
function cli(string $args): array
{
    exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli()) . ' ' . $args . ' 2>&1', $out, $code);
    return [$out, $code];
}

return [
    'RSF05-02 the version is one literal, in the shape of a release (or the next one, -dev)' => function (): void {
        truthy(preg_match('/^\d+\.\d+\.\d+(-dev)?$/', Shield::VERSION) === 1, 'Shield::VERSION is a version: ' . Shield::VERSION);
        if (rsSingle() === null) {
            same('source', Shield::BUILD, 'the repository is the source build');
        } else {
            truthy(Shield::BUILD !== 'source' && Shield::BUILD !== '', 'the built file names its build: ' . Shield::BUILD);
        }
        // Between releases (-dev): ahead of the last release in the changelog, the next version, not an old one.
        // A release itself: that last release -- the commit that is tagged (build/release-check.php).
        $log = (string) file_get_contents(dirname(__DIR__) . '/CHANGELOG.md');
        truthy(preg_match('/^## \[(\d+\.\d+\.\d+)\]/m', $log, $m) === 1, 'the changelog names the last release');
        if (substr(Shield::VERSION, -4) === '-dev') {
            truthy(version_compare((string) strtok(Shield::VERSION, '-'), $m[1], '>'), 'VERSION ' . Shield::VERSION . ' is ahead of the last release ' . $m[1]);
        } else {
            same($m[1], Shield::VERSION, 'a release: the changelog\'s last section is its own');
        }
    },
    'RSF05-02 request-shield version: what is installed, without a rule file' => function (): void {
        foreach (['version', '--version'] as $word) {
            [$out, $code] = cli($word);
            same(0, $code, "$word exits 0: " . implode(' | ', $out));
            same('request-shield ' . Shield::VERSION . ' (' . Shield::BUILD . ')', $out[0] ?? '', 'the first line');
            truthy(strpos($out[1] ?? '', 'PHP ' . PHP_VERSION) === 0, 'PHP and APCu on the second line: ' . ($out[1] ?? ''));
            truthy(preg_match('/^shipped rule sets: @attacks \d{4}\.\d{2}\.\d+ · @crawlers /', $out[2] ?? '') === 1, 'the shipped sets with their versions: ' . ($out[2] ?? ''));
            same(3, count($out), 'nothing more without a rule file');
        }
    },
    'RSF05-01 the tool is the class Cli: Cli::main($argv) runs it without the script, as the single file will (0031 E.2)' => function (): void {
        if (!function_exists('exec')) {
            skip('no exec');
        }
        $code = 'require ' . var_export(rsEntry(), true) . '; exit(\\CjwNetwork\\RequestShield\\Cli::main(["request-shield", "version"]));';
        exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg($code) . ' 2>&1', $out, $exit);
        same(0, $exit, implode(' | ', $out));
        same('request-shield ' . Shield::VERSION . ' (' . Shield::BUILD . ')', $out[0] ?? '', 'the same first line as the script');
        exec(escapeshellarg(PHP_BINARY) . ' -r ' . escapeshellarg(str_replace('"version"', '"nothing"', $code)) . ' 2>&1', $out2, $exit2);
        same(2, $exit2, 'a wrong command: the usage, exit 2');
        truthy(strpos(implode("\n", $out2), 'usage: request-shield') === 0, implode(' | ', $out2));
    },
    'RSF05-02 request-shield version site.rules: the store in use, the mode, the versions of the site\'s files' => function (): void {
        $dir = sys_get_temp_dir() . '/rs-cli-' . getmypid() . '-' . mt_rand();
        mkdir($dir, 0700, true);
        try {
            file_put_contents("$dir/site.rules", "version 2026.10.3\nset store file\nset store-dir $dir/store\nset mode monitor\ninclude @scanners\n");
            [$out, $code] = cli('version ' . escapeshellarg("$dir/site.rules"));
            same(0, $code, 'exits 0: ' . implode(' | ', $out));
            $text = implode("\n", $out);
            truthy(strpos($text, "rules: $dir/site.rules, mode monitor") !== false, 'the file and the mode: ' . $text);
            truthy(strpos($text, "store: file (set store file), $dir/store") !== false, 'the store in use: ' . $text);
            truthy(strpos($text, '2026.10.3') !== false, 'the site file\'s own version: ' . $text);
            [$out, $code] = cli('version ' . escapeshellarg("$dir/site.php"));
            same(2, $code, 'not a rule file: exit 2');
            file_put_contents("$dir/bad.rules", "set mode sideways\n");
            [$out, $code] = cli('version ' . escapeshellarg("$dir/bad.rules"));
            same(1, $code, 'a wrong rule file: exit 1 with the error, ' . implode(' | ', $out));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-01 the extensions\' commands (0031 D.1): the statistics\' stats is one, run from the table; the usage lists it with the plugin\'s own line' => function (): void {
        $commands = \CjwNetwork\RequestShield\Stats\StatsExtension::commands();
        same(['stats'], array_keys($commands));
        truthy(is_subclass_of($commands['stats'], \CjwNetwork\RequestShield\Cli\Command::class), 'a Cli\\Command');
        truthy(strncmp($commands['stats']::usage(), 'request-shield stats <main.rules>', 33) === 0, 'its usage line: ' . $commands['stats']::usage());
        same([], \CjwNetwork\RequestShield\Tests\RsTestExtension::commands(), 'an extension without commands: none');
        if (!function_exists('exec')) {
            skip('no exec');
        }
        exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli()) . ' 2>&1', $out, $code);
        same(2, $code, 'no command: the usage, exit 2');
        $usage = implode("\n", $out);
        truthy(strpos($usage, '       ' . $commands['stats']::usage()) !== false, 'the usage prints the plugin\'s line from the table: ' . $usage);
        truthy(strpos($usage, 'request-shield check|show|reload') !== false, 'and the core\'s');
    },
];
