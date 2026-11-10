<?php

declare(strict_types=1);

/**
 * The shield under OPcache's JIT, as setup-php switches it on (opcache.jit=1235: the
 * function JIT on hot code). PHP 8.0's JIT crashed calling a \Closure::fromCallable()
 * of a method -- the lookup FeedRule was handed until it held the shield -- every few CI runs, always in
 * FeedsTest. The crash comes on only some runs, so the child runs several times.
 */

return [
    'RSF01-03 under the JIT (opcache.jit=1235): a site with feeds decides thousands of requests, the listed address refused each time -- PHP does not crash' => function (): void {
        $dir = sys_get_temp_dir() . '/rs-jit-' . getmypid() . '-' . mt_rand();
        mkdir("$dir/store/feeds", 0700, true);
        try {
            // FeedsTest's lists and rules: a deny list, a check list, one at <paths>, one that signals.
            foreach (['spamhaus-drop' => ['45.10.0.0/16'], 'blocklist-de' => ['45.20.1.1', '66.249.66.1'], 'tor-exits' => ['45.30.1.1'], 'et-compromised' => ['45.40.1.1']] as $name => $ranges) {
                file_put_contents("$dir/store/feeds/$name.txt", implode("\n", $ranges) . "\n");
                file_put_contents("$dir/store/feeds/$name.json", json_encode(['checked' => time(), 'count' => count($ranges)]));
            }
            file_put_contents("$dir/site.rules", "set store-dir $dir/store\nexempt 45.10.9.9\ntrust 45.10.8.8\n[F-DROP] feed spamhaus-drop deny\n[F-F2B] feed blocklist-de check\n"
                . "[F-TOR] feed tor-exits check at /login/**\n[F-ET] feed et-compromised ban-signal 3\n[B-SCAN] ban after 3 refusals in 5m for 10m\n");
            $entry = var_export(rsEntry(), true);
            $rules = var_export("$dir/site.rules", true);
            file_put_contents("$dir/child.php", <<<PHP
                <?php
                declare(strict_types=1);
                require $entry;
                use CjwNetwork\\RequestShield\\{Request, Settings, Shield};
                use CjwNetwork\\RequestShield\\Rules\\RuleFile;
                use CjwNetwork\\RequestShield\\Store\\MemoryStore;
                \$status = function_exists('opcache_get_status') ? opcache_get_status(false) : false;
                if (!is_array(\$status) || empty(\$status['jit']['on'])) {
                    echo "no jit\\n";
                    exit(0);
                }
                \$shield = new Shield(Settings::from(RuleFile::read([$rules])['config']), new MemoryStore());
                \$refused = 0;
                for (\$i = 0; \$i < 2000; \$i++) {
                    foreach (['203.0.113.5', '45.10.1.2', '45.20.1.1', '45.30.1.1', '66.249.66.1'] as \$ip) {
                        \$d = \$shield->decide(Request::fromServer(['REQUEST_URI' => \$i % 2 === 1 ? '/.env' : '/x', 'REQUEST_METHOD' => 'GET', 'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => \$ip, 'HTTP_USER_AGENT' => 'Mozilla/5.0 Firefox/136.0']), 1000.0);
                        \$refused += \$d->reason === 'feed' && \$d->status === 403 ? 1 : 0;
                    }
                }
                echo "refused \$refused\\n";
                PHP);
            $cmd = escapeshellarg(PHP_BINARY) . ' -d opcache.enable_cli=1 -d opcache.jit=1235 -d opcache.jit_buffer_size=64M -d opcache.jit_hot_func=2 '
                . escapeshellarg("$dir/child.php") . ' 2>&1';
            for ($run = 1; $run <= 8; $run++) {
                $out = [];
                exec($cmd, $out, $code);
                if ($out === ['no jit']) {
                    skip('OPcache\'s JIT is not available to this PHP');
                }
                same([0, ['refused 2000']], [$code, $out], "run $run" . ($code === 139 ? ' (a segfault)' : ''));
            }
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
];
