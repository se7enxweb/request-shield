<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Cli;
use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Files;
use CjwNetwork\RequestShield\Log;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Rules\RuleFile;
use CjwNetwork\RequestShield\Rules\RuleFileException;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Store\FileStore;

function filesDir(): string
{
    $dir = sys_get_temp_dir() . '/rs-files-' . getmypid() . '-' . mt_rand();
    mkdir($dir, 0700, true);
    return $dir;
}

function modeOf(string $path): string
{
    clearstatcache(true, $path);
    return sprintf('0%03o', (int) fileperms($path) & 07777);
}

/** Runs $test with the umask set and the default modes restored after. */
function withUmask(int $umask, callable $test): void
{
    $old = umask($umask);
    try {
        $test();
    } finally {
        umask($old);
        Files::modes(0600, 0700);
    }
}

return [
    'RSF05-02 file-mode and dir-mode: what may be set -- never writable for everyone, never one that keeps PHP out; octal as written' => function (): void {
        same([0640, 0640, 02770, null, null, null], [Files::parseMode('0640'), Files::parseMode('640'), Files::parseMode('02770'), Files::parseMode('rw-r-----'), Files::parseMode('0890'), Files::parseMode('006400')]);
        same([true, true, true, true], [Files::fileModeOk(0600), Files::fileModeOk(0640), Files::fileModeOk(0660), Files::fileModeOk(0644)]);
        same([false, false, false, false], [Files::fileModeOk(0646), Files::fileModeOk(0400), Files::fileModeOk(0700), Files::fileModeOk(04600)], 'everyone writes; PHP cannot write; x bit; setuid');
        same([true, true, true, true], [Files::dirModeOk(0700), Files::dirModeOk(0750), Files::dirModeOk(02770), Files::dirModeOk(0755)]);
        same([false, false, false], [Files::dirModeOk(0777), Files::dirModeOk(0500), Files::dirModeOk(04700)], 'everyone writes; PHP cannot write; setuid');
        $s = Settings::from([]);
        same([0600, 0700], [$s->fileMode, $s->dirMode], 'by default only the user PHP runs as');
        same([0640, 02750], [Settings::from(['fileMode' => '0640', 'dirMode' => 02750])->fileMode, Settings::from(['dirMode' => '02750'])->dirMode]);
        foreach ([['fileMode' => 0666], ['dirMode' => 0777], ['fileMode' => 'rw'], ['dirMode' => 0600]] as $wrong) {
            try {
                Settings::from($wrong);
                throw new TestFailure('accepted ' . json_encode($wrong));
            } catch (InvalidArgumentException $e) {
                truthy(strpos($e->getMessage(), (string) array_key_first($wrong)) !== false, $e->getMessage());
            }
        }
        Files::modes(0600, 0700);
        $dir = filesDir();
        try {
            file_put_contents("$dir/site.rules", "set file-mode 0640\nset dir-mode 02770\n");
            $s = Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
            same([0640, 02770], [$s->fileMode, $s->dirMode], 'the rule words');
            same([0640, 02770], [Files::fileMode(), Files::dirMode()], 'taken when the settings are made');
            foreach (["set file-mode 0666\n" => 'file-mode is a mode such as', "set dir-mode 0777\n" => 'dir-mode is a mode such as', "set file-mode rw-r-----\n" => 'not "rw-r-----"'] as $text => $part) {
                file_put_contents("$dir/site.rules", $text);
                try {
                    RuleFile::read(["$dir/site.rules"]);
                    throw new TestFailure("accepted $text");
                } catch (RuleFileException $e) {
                    truthy(strpos($e->getMessage(), 'site.rules:1: ') === 0 && strpos($e->getMessage(), $part) !== false, $e->getMessage());
                }
            }
        } finally {
            Files::modes(0600, 0700);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-02 the modes are set exactly: the umask takes nothing away and adds nothing; each new parent too; setgid kept' => function (): void {
        $dir = filesDir();
        try {
            withUmask(0077, static function () use ($dir): void {
                Files::modes(0640, 02750);
                truthy(Files::dir("$dir/a/b/c"), 'made');
                same(['02750', '02750', '02750'], [modeOf("$dir/a"), modeOf("$dir/a/b"), modeOf("$dir/a/b/c")],
                    'the new levels in dir-mode, the umask 0077 notwithstanding');
                same('0700', modeOf($dir), 'what was there keeps its mode');
                truthy(Files::write("$dir/a/w.json", '{}'), 'written');
                same('0640', modeOf("$dir/a/w.json"));
                truthy(Files::append("$dir/a/log", "1\n") && Files::append("$dir/a/log", "2\n"), 'appended');
                same(0077, umask(), 'the umask as it was after appending');
                same(['0640', "1\n2\n"], [modeOf("$dir/a/log"), file_get_contents("$dir/a/log")]);
                same([], glob("$dir/a/w.json.*") ?: [], 'no temporary file left');
            });
            withUmask(0, static function () use ($dir): void {
                Files::modes(0640, 02770);
                \CjwNetwork\RequestShield\Challenge\Secret::resolve(null, "$dir/keyed");
                same(['02770', '0600'], [modeOf("$dir/keyed"), modeOf("$dir/keyed/secret")], 'store-dir made for the secret in dir-mode; the secret 0600 whatever is set');
                Files::modes(0600, 0700);
                Files::dir("$dir/open/x");
                $h = Files::create("$dir/open/x/new", 0640);
                truthy($h !== false, 'made');
                same('0640', modeOf("$dir/open/x/new"), 'in its mode the moment it exists (umask 0): no handle opened in between could read what follows');
                fclose($h);
                same(false, @Files::create("$dir/open/x/new", 0640), 'exclusive');
                same(0, umask(), 'the umask as it was after create()');
                Files::append("$dir/open/x/log", "1\n");
                Files::write("$dir/open/x/w", '1');
                same(['0700', '0700', '0600', '0600'], [modeOf("$dir/open"), modeOf("$dir/open/x"), modeOf("$dir/open/x/log"), modeOf("$dir/open/x/w")], 'umask 0: nothing more for others');
                chmod("$dir/open/x/log", 0644);
                Files::append("$dir/open/x/log", "2\n");
                same('0644', modeOf("$dir/open/x/log"), 'a file that is there keeps its mode');
                unlink("$dir/open/x/log");
                truthy(Files::append("$dir/open/x/log", "3\n"), 'the file removed: made anew');
                same(["3\n", '0600'], [file_get_contents("$dir/open/x/log"), modeOf("$dir/open/x/log")]);
                exec('rm -rf ' . escapeshellarg("$dir/open"));
                truthy(Files::append("$dir/open/x/log", "4\n"), 'its folder removed: made anew');
                same(["4\n", '0600', '0700'], [file_get_contents("$dir/open/x/log"), modeOf("$dir/open/x/log"), modeOf("$dir/open/x")]);
                touch("$dir/open/x/empty");
                Files::append("$dir/open/x/empty", "5\n");
                same('0666', modeOf("$dir/open/x/empty"), 'a file that is there keeps its mode, also an empty one');
                $threads = new ReflectionProperty(Files::class, 'threads');
                $threads->setAccessible(true);                            // PHP 8.0
                $threads->setValue(null, true);
                try {
                    Files::append("$dir/open/x/zts", "6\n");
                    touch("$dir/open/x/empty2");
                    Files::append("$dir/open/x/empty2", "7\n");
                    same(['0600', "6\n", '0600', "7\n"], [modeOf("$dir/open/x/zts"), file_get_contents("$dir/open/x/zts"), modeOf("$dir/open/x/empty2"), file_get_contents("$dir/open/x/empty2")],
                        'with threads (no umask): made, then file-mode while still empty (made by a parallel request too), then the line');
                    $h = Files::create("$dir/open/x/zts-new", 0640);
                    truthy($h !== false && fclose($h), 'made with threads');
                    truthy(Files::write("$dir/open/x/zts-w", 'w'), 'written with threads');
                    same(['0640', '0600', 0], [modeOf("$dir/open/x/zts-new"), modeOf("$dir/open/x/zts-w"), umask()], 'with threads: chmod after making (the umask left alone)');
                    exec('rm -rf ' . escapeshellarg("$dir/open/y"));
                    truthy(Files::append("$dir/open/y/z", "8\n") && modeOf("$dir/open/y/z") === '0600', 'with threads: the folder made');
                } finally {
                    $threads->setValue(null, null);
                }
                file_put_contents("$dir/open/x/nginx.conf", 'old');
                chmod("$dir/open/x/nginx.conf", 0644);
                truthy(Files::write("$dir/open/x/nginx.conf", 'new', '', true), 'written');
                same(['0644', 'new'], [modeOf("$dir/open/x/nginx.conf"), file_get_contents("$dir/open/x/nginx.conf")], 'keep: a file named by the user keeps its mode');
                Files::write("$dir/open/x/nginx.conf", 'newer');
                same('0600', modeOf("$dir/open/x/nginx.conf"), 'written whole otherwise: a new file, file-mode');
            });
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-02 a folder removed while PHP still remembers it (stat cache): append() makes it anew, with and without threads' => function (): void {
        $dir = filesDir();
        $threads = new ReflectionProperty(Files::class, 'threads');
        $threads->setAccessible(true);                                    // PHP 8.0
        try {
            foreach (['without threads' => false, 'with threads' => true] as $how => $zts) {
                $threads->setValue(null, $zts);
                $sub = "$dir/" . ($zts ? 'zts' : 'nts');
                truthy(Files::append("$sub/x/log", "1\n"), "$how: written");
                truthy(is_dir("$sub/x"), "$how: PHP has looked at the folder");
                exec('rm -rf ' . escapeshellarg($sub));                  // logrotate, a clean-up -- PHP is not told
                truthy(Files::append("$sub/x/log", "2\n"), "$how: its folder removed, PHP's stat cache still has it: made anew");
                clearstatcache();
                same(["2\n", '0600', '0700'], [@file_get_contents("$sub/x/log"), modeOf("$sub/x/log"), modeOf("$sub/x")], "$how: the line, in file-mode, in a folder in dir-mode");
            }
        } finally {
            $threads->setValue(null, null);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-02 what the shield writes gets the modes: the log, a mark in store-dir, a list by the command line (set file-mode, set dir-mode)' => function (): void {
        $dir = filesDir();
        try {
            withUmask(0022, static function () use ($dir): void {
                $s = Settings::from(['storeDir' => "$dir/store", 'fileMode' => 0640, 'dirMode' => 0750, 'log' => ['file' => "$dir/logs/shield.log"]]);
                Log::write($s, Request::fromServer(['REQUEST_URI' => '/x', 'REMOTE_ADDR' => '198.51.100.7']), Decision::reject(404, 'x'), null);
                same(['0750', '0640'], [modeOf("$dir/logs"), modeOf("$dir/logs/shield.log")], 'the log and its folder');
                chmod("$dir/logs/shield.log", 0600);
                Log::append("$dir/logs/shield.log", "y\n", 1);
                same(['0640', "y\n", '0600'], [modeOf("$dir/logs/shield.log"), file_get_contents("$dir/logs/shield.log"), modeOf("$dir/logs/shield.log.1")], 'rotated: the new file in file-mode, the old one keeps its mode');
                $mon = Settings::from(['mode' => 'monitor', 'fileMode' => 0660, 'dirMode' => 02770, 'monitorRules' => ['storeDir' => "$dir/store"]]);
                same([0660, 02770, 0660], [$mon->fileMode, $mon->dirMode, Files::fileMode()], 'a whole site in monitor mode keeps the modes');
                Files::modes($s->fileMode, $s->dirMode);
                (new FileStore("$dir/store"))->mark('ban:198.51.100.7', time() + 60, (float) time());
                $marks = array_values(array_filter(explode("\n", (string) shell_exec('find ' . escapeshellarg("$dir/store") . ' -type f'))));
                truthy($marks !== [], 'a mark');
                same(['0640'], array_values(array_unique(array_map('modeOf', $marks))), 'a mark holds an address: file-mode');
                same(['0750'], array_values(array_unique(array_map('modeOf', array_filter(explode("\n", (string) shell_exec('find ' . escapeshellarg("$dir/store") . ' -type d')))))), 'store-dir\'s folders');
            });
            if (!function_exists('exec')) {
                skip('no exec');
            }
            file_put_contents("$dir/site.rules", "set store-dir $dir/cli\nset file-mode 0660\nset dir-mode 02770\n");
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli()) . ' deny ' . escapeshellarg("$dir/site.rules") . ' 203.0.113.7 --for=1d 2>&1', $out, $code);
            same(0, $code, implode("\n", $out));
            same(['02770', '0660'], [modeOf("$dir/cli/lists"), modeOf("$dir/cli/lists/deny.rules")], 'the command line takes the rule words');
            file_put_contents("$dir/site.rules", "site www.example.org {\n  set dir-mode 0750\n}\n");
            exec(escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli()) . ' check ' . escapeshellarg("$dir/site.rules") . ' 2>&1', $out2, $code);
            truthy($code !== 0 && strpos(implode("\n", $out2), 'site.rules:2: set dir-mode is about the server') !== false, 'one folder for all sites: above the site blocks ' . implode("\n", $out2));
        } finally {
            Files::modes(0600, 0700);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF05-02 check warns about modes: one everyone may read, and files in store-dir or the log everyone may read already' => function (): void {
        $dir = filesDir();
        try {
            mkdir("$dir/store", 0700);
            file_put_contents("$dir/store/learned.jsonl", "{}\n");
            chmod("$dir/store/learned.jsonl", 0600);
            mkdir("$dir/store/ab", 0700);
            file_put_contents("$dir/store/ab/60-1-abc.c", "\n\n");
            chmod("$dir/store/ab/60-1-abc.c", 0644);                    // a counter: its size counts, nothing in it
            $m = new ReflectionMethod(Cli::class, 'modeWarnings');
            $m->setAccessible(true);                                  // PHP 8.0
            $warn = static fn (Settings $s): string => implode("\n", $m->invoke(null, $s));
            same('', $warn(Settings::from(['storeDir' => "$dir/store"])), 'nothing to say (a counter everyone may read holds nothing)');
            same('', $warn(Settings::from(['storeDir' => "$dir/store", 'dirMode' => 0711])), 'x alone for others lists nothing');
            truthy(strpos($warn(Settings::from(['storeDir' => "$dir/store", 'fileMode' => 0644])), 'file-mode 0644 / dir-mode 0700: everyone on this machine may read') === 0, 'a mode for everyone');
            chmod("$dir/store/learned.jsonl", 0644);
            file_put_contents("$dir/shield.log", "line\n");
            chmod("$dir/shield.log", 0604);
            file_put_contents("$dir/store/ab/f00.m", "1\nban:198.51.100.7");
            chmod("$dir/store/ab/f00.m", 0644);                         // a ban kept by an older version, a folder down
            $w = $warn(Settings::from(['storeDir' => "$dir/store", 'log' => ['file' => "$dir/shield.log"]]));
            truthy(strpos($w, "$dir/store/learned.jsonl (0644)") !== false && strpos($w, "$dir/store/ab/f00.m (0644)") !== false && strpos($w, "$dir/shield.log (0604)") !== false
                && strpos($w, 'chmod o-rwx') !== false && strpos($w, '.c (') === false, $w);
            symlink("$dir/store", "$dir/linked");
            $w = $warn(Settings::from(['storeDir' => "$dir/linked", 'listsDir' => "$dir/linked/ab"]));
            truthy(strpos($w, "$dir/linked/ab/f00.m (0644)") !== false && substr_count($w, 'f00.m') === 1, "store-dir a link (/var/lib/...): looked into; lists-dir inside it once: $w");
            $w = $warn(Settings::from(['storeDir' => "$dir/store", 'fileMode' => 0644, 'log' => ['file' => "$dir/shield.log"]]));
            truthy(strpos($w, 'everyone on this machine may read what') !== false && strpos($w, 'made before') === false, "set so on purpose: no second warning about the files: $w");
        } finally {
            Files::modes(0600, 0700);
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
];
