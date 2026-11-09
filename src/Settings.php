<?php
/**
 * This file is part of cjw-network/request-shield.
 *
 * @copyright Copyright (C) 2026 JAC Systeme GmbH, CJW Network
 * @license MIT, see LICENSE
 */

declare(strict_types=1);

namespace CjwNetwork\RequestShield;

/**
 * The configuration array, checked once and turned into typed values. A
 * value of the wrong type is an error at once -- with the key named -- not
 * a check that quietly does something else on a live site.
 */
final class Settings
{
    /**
     * @param list<string> $trustedProxies
     * @param list<string> $methods
     * @param list<string> $hosts
     * @param list<string> $blockedPaths
     * @param list<string>|null $cacheablePaths
     * @param list<string>|null $cacheableQuery
     * @param array<string, Budget> $budgets
     * @param list<string> $exemptIps
     * @param array<string, array<string, string>> $origins setting => pattern or budget => where it was set (rule files)
     * @param list<array{paths: list<string>, ips: list<string>}> $restricted
     * @param array<string, list<string>> $methodPaths
     * @param list<array{paths: list<string>, patterns: list<string>|null, ips: list<string>}> $blockExceptions
     * @param list<array{target: string, patterns: list<string>}> $contentRules
     * @param array<string, string> $contentIndex
     * @param array<string, list<string>> $contentHints
     */
    private function __construct(
        /** @readonly */
        public array $trustedProxies,
        /** @readonly */
        public bool $stripUntrustedForwarded,
        /** @readonly */
        public array $methods,
        /** @readonly */
        public array $hosts,
        /** @readonly */
        public int $maxUri,
        /** @readonly */
        public int $maxQueryParameters,
        /** @readonly */
        public int $maxHeaderBytes,
        /** @readonly */
        public array $blockedPaths,
        /** @readonly */
        public ?array $cacheablePaths,
        /** @readonly */
        public ?array $cacheableQuery,
        /** @readonly */
        public array $budgets,
        /** @readonly */
        public array $exemptIps,
        /** @readonly */
        public int $ipv6Prefix,
        /** @readonly */
        public string $store,
        /** @readonly */
        public string $storeDir,
        /** @readonly */
        public bool $debugHeader,
        /** @readonly */
        public ChallengeSettings $challenge,
        /** @readonly */
        public array $origins = [],
        /** @readonly */
        public array $restricted = [],
        /** @readonly */
        public array $methodPaths = [],
        /** @readonly */
        public ?string $logFile = null,
        /** @readonly */
        public string $logLevel = 'stop',
        /** @readonly */
        public string $logIp = 'masked',
        /** @readonly */
        public int $logMaxSize = 10485760,
        /** @readonly */
        public array $blockExceptions = [],
        /** @readonly */
        public bool $appChallenge = false,
        /** @readonly */
        public array $contentRules = [],
        /** @readonly target => all of its patterns in one expression */
        public array $contentIndex = [],
        /** @readonly all blocked paths in one expression; '' when they cannot be combined */
        public string $blockedIndex = '',
        /**
         * @readonly target => texts one of which every pattern needs; a target without is always matched
         * @var array<string, list<string>>
         */
        public array $contentHints = [],
        /**
         * @readonly the known query parameters (QueryRule)
         * @var list<array{paths: list<string>|null, exact: array<string, string>, globs: array<string, string>}>
         */
        public array $queryParams = [],
        /** @readonly anything but a known parameter of its type: 404 */
        public bool $queryStrict = false,
        /**
         * @readonly where an unknown parameter, or one not of its type, is dropped instead (query drop):
         *   path patterns; the request goes on without it (QueryRule, Shield::queryForCaches())
         * @var list<string>
         */
        public array $queryDrop = [],
        /**
         * @readonly queryParams as one lookup (QueryRule::index()), built once
         * @var array{exact: array<string, string>, globs: array<string, string>, local: list<array{paths: list<string>, exact: array<string, string>, globs: array<string, string>}>}
         */
        public array $queryIndex = ['exact' => [], 'globs' => [], 'local' => []],
        /** @readonly off, monitor, enforce or strict */
        public string $mode = 'enforce',
        /** @readonly how often a request a cache must not keep counts against the budgets (strict: 2) */
        public int $uncachedWeight = 1,
        /** @readonly the rules with those marked "monitor": decided alongside, only logged; null: none */
        public ?Settings $monitor = null,
        /**
         * @readonly the known crawlers, each with what the site does with it (policy)
         * @var array<string, array{kind: string, ua: string, dns: list<string>, ranges: list<string>, lists: array<string, array<string, ?string>>, policy: string, nets: array<string, list<array{0: string, 1: int}>>}>
         */
        public array $crawlers = [],
        /** @readonly every crawler's User-Agent pattern in one expression, (*MARK:<n>) naming it; '' for none */
        public string $crawlerIndex = '',
        /** @var list<string> @readonly crawler IDs in the order of the MARKs */
        public array $crawlerIds = [],
        /** @readonly both, ranges or dns */
        public string $crawlerVerify = 'both',
        /** @var array<string, string> @readonly the policies as written: kind or crawler ID => allow, check, block */
        public array $crawlerPolicy = [],
        /** @readonly where the statistics pages live: <path>/dashboard, /stats, /shield */
        public string $dashboardPath = '/rs',
        /** @var list<class-string> @readonly the plugins the rules name, and those the extensions add at compile time (Extension::plugins(): the statistics with "set stats on") */
        public array $plugins = [],
        /** @var array<class-string, string> @readonly plugin class => the file that holds it (plugin … from <file>), loaded only when the shield makes its plugins (0031 D.2) */
        public array $pluginFiles = [],
        /** @var array<string, string> @readonly website name (a.de, *.b.de, default) => its site block (the block's first name); [] without site blocks */
        public array $sites = [],
        /** @readonly the site block these settings are (null: the base, for every website) */
        public ?string $site = null,
        /** @readonly which name picks the site: server-name (the web server's, the default) or host (the Host header) */
        public string $siteFrom = 'server-name',
        /** @var list<array{ips: list<string>, until: ?int, rule: string}> @readonly addresses kept out (deny), the ones in force -- the first DENY_SHOWN, for the pages */
        public array $deny = [],
        /** @var array{4: string, 6: string, ids: string, dir?: string}|array{} @readonly all of them, as a sorted table (IpTable); [] none */
        public array $denyTable = [],
        /** @readonly how many entries are in force */
        public int $denyCount = 0,
        /** @readonly when the next list entry ends (a Unix time; 0: none) -- the settings are built again then */
        public int $listsUntil = 0,
        /** @readonly where the list files are (allow.rules, deny.rules); null: none */
        public ?string $listsDir = null,
        /** @var list<array{after: int, signal: string, in: int, for: int, rule: string}> @readonly automatic, temporary bans */
        public array $bans = [],
        /** @readonly a ban within a day of the last lasts this many times longer */
        public int $banGrowth = 2,
        /** @readonly the longest ban, in seconds */
        public int $banMax = 86400,
        /** @readonly the live view's memory (APCu): the last requests stopped, with the full address */
        public bool $liveEnabled = false,
        /** @readonly how long an entry stays in it, in seconds */
        public int $liveKeep = 3600,
        /** @readonly where a ban is kept: memory (the store), or file (also a file in store-dir: it survives a restart of APCu) */
        public string $banKeep = 'memory',
        /** @var list<array{name: string, title: string, action: string, weight: int, paths: list<string>, rule: string, terms: string, urls: list<string>, format: string, every: int, wideOk: bool, count: int, fetched: int, state: string, file: ?string}> @readonly the public blocklists named, as the pages show them */
        public array $feeds = [],
        /** @var array<string, array{4: string, 6: string, ids: string, dir?: string}> @readonly per action (deny, check, signal): the feeds without "at", as one table */
        public array $feedTables = [],
        /** @var list<array{action: string, table: array{4: string, 6: string, ids: string, dir?: string}, paths: list<string>}> @readonly the feeds with "at <paths>", each its own table */
        public array $feedsAt = [],
        /** @var array<string, int> @readonly ban-signal: rule => how many signals a request from its list counts as */
        public array $feedWeights = [],
        /** @readonly a fetched list older than this is no longer used, in seconds */
        public int $feedsMaxAge = 259200,
        /** @var list<array{who: string, hash: string, until: ?int, rule: string}> @readonly dashboard-access: who may open the dashboard's pages -- '*' (everything) or an opaque principal (customer-a; what it may see is the pages' business) -- by a token's SHA-256, in force */
        public array $dashboardAccess = [],
        /** @readonly how long a login to the dashboard lasts, in seconds (set dashboard-session; 8 hours) */
        public int $dashboardSession = 28800,
        /** @var array{missing: string, except: list<string>}|null @readonly post-origin same: forms only from the website's own pages; null: off */
        public ?array $postOrigin = null,
        /** @var list<string> @readonly the editors' area (backend <paths>): its forms counted apart, per area; as patterns */
        public array $backend = [],
        /** @var array<string, array<string, mixed>> @readonly the extensions' checked settings by extension id (ext.<id>.*; Extension::compile() fills it, 0031 B.2) -- plugins read their own, the core never does */
        public array $ext = [],
        /** @var array<string, list<class-string>> @readonly which plugins provide which capability (hook name => classes), recorded at compile time by instanceof (Settings::HOOKS), so a request costs one array access to know; ruleCounts (0031 B.8), sink (B.9), pages (B.10), ruleProvider (C.3), handler (C.4) */
        public array $hooks = [],
        /** @var array<string, array{key: string, ext: ?string, tab: ?array{0: string, 1: string}, role: string, order: int}> @readonly the dashboard's pages, full path => entry (Routes; the core's, the extensions', in the tabs' order), compiled by compiledExt() -- served by the shield from 0031 B.6 */
        public array $routes = [],
        /** @var list<string> @readonly the prefixes the routes lie below (Routes::bases()): dashboard-path, and the path of a page outside it (set stats-path /admin/statistics) -- the request path's pre-filter, one stripos each */
        public array $routeBases = [],
        /** @readonly where the pages' "?" links point (set docs-url, Help): the docs' folder; "" with the links off */
        public string $docsUrl = Help::DOCS,
        /** @var array<int|string, array<string, string>> @readonly the site's own error pages (set error-page): status or 4xx => language ("" for all) => HTML, read when the rules were compiled (0030) */
        public array $errorPages = [],
        /** @var array{until: int, token: string, from: list<string>}|null @readonly a learning run (0016: request-shield learn … start), read from <store-dir>/learn.json when compiled; null: none */
        public ?array $learn = null,
        /** @readonly the mode of a new file the shield writes (set file-mode; Files) */
        public int $fileMode = 0600,
        /** @readonly the mode of a new folder the shield makes (set dir-mode; Files) */
        public int $dirMode = 0700,
        /** @var list<string> @readonly cache-ignore (0048): parameter names (globs, as PHP names them) no cache key holds -- taken out before a cache and the application run */
        public array $cacheableIgnore = [],
        /** @readonly set cache-unknown-query (0048): "uncached" (a parameter not in cache-query: never kept) or "hit-only" (answered from the key without it, never kept) */
        public string $cacheableUnknown = 'uncached',
    ) {
        // The modes for everything written from here on: every request and every command makes its
        // settings first. Files is loaded only for modes not its defaults, or when it is loaded already.
        if ($fileMode !== 0600 || $dirMode !== 0700 || class_exists(Files::class, false)) {
            Files::modes($fileMode, $dirMode);
        }
    }

    /**
     * @param array<mixed> $config see Config::defaults()
     * @throws \InvalidArgumentException naming the key that is wrong
     */
    public static function from(array $config): self
    {
        $c = Config::merge($config);
        $verify = self::string($c, 'crawlerVerify', 'crawlerVerify', 'both');
        if (!in_array($verify, ['both', 'ranges', 'dns'], true)) {
            throw self::wrong('crawlerVerify', 'both, ranges or dns');
        }
        $mode = self::string($c, 'mode', 'mode', 'enforce');
        if (!in_array($mode, self::MODES, true)) {
            throw self::wrong('mode', implode(', ', self::MODES));
        }
        $monitorRules = $c['monitorRules'] ?? null;
        if ($monitorRules !== null && !is_array($monitorRules)) {
            throw self::wrong('monitorRules', 'null or the settings with the monitored rules');
        }
        if ($mode === 'monitor' && $monitorRules !== null) {
            // Everything is only logged anyway: the monitored rules count like the others.
            return self::from(['mode' => 'monitor', 'monitorRules' => null] + array_intersect_key($c, ['fileMode' => 1, 'dirMode' => 1]) + $monitorRules);
        }
        if ($monitorRules !== null && is_array($monitorRules['feeds'] ?? null)) {
            // The watched rules' settings: only the watched lists (feed … count, monitor feed …);
            // the others are enforced already, and a big list is read once.
            $monitorRules['feeds'] = array_values(array_filter($monitorRules['feeds'], static fn ($f): bool => is_array($f) && ($f['watched'] ?? false) === true));
        }
        $strict = $mode === 'strict';
        $limits = self::map($c, 'limits');
        $cacheable = self::map($c, 'cacheable');
        $exempt = self::map($c, 'exempt');
        $log = self::map($c, 'log');

        $restricted = [];
        foreach (self::map($c, 'restricted') as $i => $r) {
            if (!is_array($r)) {
                throw self::wrong("restricted.$i", "an array of 'paths' and 'ips'");
            }
            $restricted[] = ['paths' => self::strings($r, 'paths', "restricted.$i.paths"), 'ips' => self::strings($r, 'ips', "restricted.$i.ips")];
        }
        $exceptions = [];
        foreach (self::map($c, 'blockExceptions') as $i => $x) {
            if (!is_array($x)) {
                throw self::wrong("blockExceptions.$i", "an array of 'paths', 'patterns' and 'ips'");
            }
            $exceptions[] = ['paths' => self::strings($x, 'paths', "blockExceptions.$i.paths"),
                'patterns' => self::stringsOrNull($x, 'patterns', "blockExceptions.$i.patterns"), 'ips' => self::strings($x, 'ips', "blockExceptions.$i.ips")];
        }
        [$contentRules, $contentIndex] = self::contentRules(self::map($c, 'contentRules'));
        $blocked = self::strings($c, 'blockedPaths');
        $methodPaths = [];
        foreach (self::map($c, 'methodPaths') as $method => $paths) {
            $methodPaths[strtoupper((string) $method)] = self::strings(['p' => $paths], 'p', "methodPaths.$method");
        }
        $level = self::string($log, 'level', 'log.level', 'stop');
        if (!in_array($level, Log::LEVELS, true)) {
            throw self::wrong('log.level', implode(', ', Log::LEVELS));
        }
        $ip = self::string($log, 'ip', 'log.ip', 'masked');
        if ($ip !== 'masked' && $ip !== 'full') {
            throw self::wrong('log.ip', 'masked or full');
        }
        $logFile = $log['file'] ?? null;
        if ($logFile !== null && (!is_string($logFile) || $logFile === '')) {
            throw self::wrong('log.file', 'null or a path');
        }

        $budgets = [];
        foreach (self::map($c, 'budgets') as $name => $budget) {
            if (!is_array($budget)) {
                throw self::wrong("budgets.$name", 'an array');
            }
            $b = Budget::from((string) $name, $budget, $strict);
            if ($b !== null) {
                $budgets[(string) $name] = $b;
            }
        }

        return self::compiledExt(new self(
            self::strings($c, 'trustedProxies'),
            self::bool($c, 'stripUntrustedForwarded'),
            array_map(static fn (string $m): string => strtoupper($m), self::strings($c, 'methods')),
            array_map(static fn (string $h): string => strtolower($h), self::strings($c, 'hosts')),
            self::int($limits, 'uri', 'limits.uri'),
            self::int($limits, 'queryParameters', 'limits.queryParameters'),
            self::int($limits, 'headerBytes', 'limits.headerBytes'),
            $blocked,
            self::stringsOrNull($cacheable, 'paths', 'cacheable.paths'),
            self::stringsOrNull($cacheable, 'query', 'cacheable.query'),
            $budgets,
            array_values(array_unique(array_merge(self::strings($exempt, 'ips', 'exempt.ips'), self::exemptForNow($c)))),
            max(0, min(128, self::int($c, 'ipv6Prefix'))),
            self::string($c, 'store'),
            self::string($c, 'storeDir'),
            self::bool($c, 'debugHeader'),
            ChallengeSettings::from(self::map($c, 'challenge'), $strict),
            self::origins(self::map($c, 'origins')),
            $restricted,
            $methodPaths,
            $level === 'off' ? null : $logFile,
            $level,
            $ip,
            max(4096, self::int($log, 'maxSize', 'log.maxSize', 10485760)),
            $exceptions,
            self::bool($c, 'appChallenge'),
            $contentRules,
            $contentIndex,
            self::combine($blocked),
            self::hints($contentRules),
            $query = self::queryParams(self::map($c, 'queryParams')),
            self::bool($c, 'queryStrict'),
            self::patternList(self::listOf($c, 'queryDrop'), 'queryDrop'),
            \CjwNetwork\RequestShield\Rule\QueryRule::index($query),
            $mode,
            $strict ? 2 : 1,
            $monitorRules === null ? null : self::from(['mode' => $mode, 'monitorRules' => null] + $monitorRules),
            ...self::knownCrawlers($c, $verify),
            ...[self::dashboardPath($c), self::plugins($c), self::pluginFiles($c)],
            ...self::sites($c),
            ...self::withFeeds(self::lists($c, $budgets), $feeds = self::feeds($c), self::accessNext($c)),
            ...self::live($c),
            ...array_slice($feeds, 0, 5),
            ...self::dashboardAccess($c),
            ...[self::postOrigin($c), self::patternList($c['backend'] ?? [], 'backend')],
            ...[self::ext($c), self::hooks($c), self::routes($c), [], self::docsUrl($c), self::errorPages($c), self::learn($c)],
            ...self::modesOf($c),
            ...self::queryClasses($cacheable),
        ));
    }

    /**
     * The query parameters a cache leaves out of its key (0048): cache-ignore's
     * names, and what a parameter cache-query does not name is.
     *
     * @param array<mixed> $cacheable
     * @return array{0: list<string>, 1: string}
     */
    private static function queryClasses(array $cacheable): array
    {
        $ignore = self::strings($cacheable, 'ignore', 'cacheable.ignore');
        foreach ($ignore as $name) {
            if (preg_match('/^[A-Za-z0-9_*\[\]-]{1,128}$/', $name) !== 1) {
                throw self::wrong('cacheable.ignore', 'parameter names as PHP names them, * for any characters (utm_* gclid)');
            }
        }
        $unknown = $cacheable['unknown'] ?? 'uncached';
        if ($unknown !== 'uncached' && $unknown !== 'hit-only') {
            throw self::wrong('cacheable.unknown', 'uncached or hit-only');
        }
        return [$ignore, $unknown];
    }

    /**
     * The modes of new files and folders (set file-mode, set dir-mode): a
     * server's rules set exactly -- never writable for everyone, never one that
     * keeps PHP from writing (Files).
     *
     * @param array<mixed> $c
     * @return array{0: int, 1: int}
     */
    private static function modesOf(array $c): array
    {
        $out = [];
        foreach (['fileMode' => [0600, 'file-mode: the owner reads and writes, nobody else writes, no x bit (0600, 0640, 0660, 0644)'],
            'dirMode' => [0700, 'dir-mode: the owner rwx, nobody else writes (0700, 0750, 0770, 02770, 0755)']] as $key => [$default, $what]) {
            $v = $c[$key] ?? $default;
            $mode = is_int($v) ? $v : (is_string($v) ? Files::parseMode($v) : null);
            if ($mode === null || !($key === 'fileMode' ? Files::fileModeOk($mode) : Files::dirModeOk($mode))) {
                throw self::wrong($key, $what);
            }
            $out[] = $mode;
        }
        return [$out[0], $out[1]];
    }

    /**
     * The extensions check what the rules wrote into their slot, with the
     * whole base settings in hand (Extension::compile(), ADR 0008): an id no
     * offered extension owns keeps its values as they are -- nothing reads
     * them. A wrong value is an InvalidArgumentException like any other
     * setting's: on the request path the last good compiled settings stay.
     * The plugins an extension runs per request (Extension::plugins(), 0031
     * B.4) join the list the rules named, once each, so a request reads one
     * list and never the slots. The pages (Extension::routes(), 0031 B.5)
     * join the core's in one table, Routes::compile(): the settings array's
     * own routes, the core's below dashboard-path, every offered extension's
     * from its compiled slot.
     */
    private static function compiledExt(self $s): self
    {
        $checked = $s->ext;
        $plugins = $s->plugins;
        $routes = [];
        // Every offered extension compiles -- with an empty slot when the rules said nothing
        // of it: its defaults, its routes and its plugins apply all the same (0031 B.6).
        foreach (\CjwNetwork\RequestShield\Rules\Vocabulary::extensions() as $id => $class) {
            $checked[$id] = $class::compile($s->ext[$id] ?? [], $s);
            foreach ($class::plugins($checked[$id]) as $plugin) {
                if (!in_array($plugin, $plugins, true)) {
                    $plugins[] = $plugin;
                }
            }
            $routes[$id] = $class::routes($checked[$id]);
        }
        // The plugins' capabilities (0031 B.8): which class has which hook, recorded here
        // by instanceof, so a request -- or a page -- asks one array and never a plugin.
        $hooks = $s->hooks;
        foreach ($plugins as $class) {
            if (!class_exists($class) && isset($s->pluginFiles[$class]) && is_file($s->pluginFiles[$class])) {
                try {
                    require_once $s->pluginFiles[$class];   // plugin … from <file>: so its capabilities can be recorded
                } catch (\Throwable $e) {
                    Shield::failed('plugins', "$class could not be loaded from {$s->pluginFiles[$class]}, left out: " . $e->getMessage());
                    continue;
                }
            }
            if (!class_exists($class)) {
                continue;
            }
            foreach (self::HOOKS as $hook => $interface) {
                if (is_subclass_of($class, $interface) && !in_array($class, $hooks[$hook] ?? [], true)) {
                    $hooks[$hook][] = $class;
                }
            }
        }
        // The same settings with the slots, the plugins and the pages filled in:
        // the value objects (budgets, challenge, monitor) are immutable and shared,
        // so no export()/import() round trip. Positional, in declaration order
        // (as import()): unpacking string keys into named arguments needs PHP 8.1.
        /** @var array<string, mixed> $e */
        $e = get_object_vars($s);
        $e['ext'] = $checked;
        $e['plugins'] = $plugins;
        $e['routes'] = Routes::compile($s->routes, $s->dashboardPath, $routes);
        $e['routeBases'] = Routes::bases($e['routes'], $s->dashboardPath);
        $e['hooks'] = $hooks;
        /** @phpstan-ignore argument.type */
        return new self(...array_values($e));
    }

    /**
     * The known crawlers with the site's policies, their expression and IDs,
     * crawler-verify and the policies as written. The shipped list comes
     * ready (Shipped::crawlers()): settings from a PHP array only apply the
     * site's policies to it.
     *
     * @param array<mixed> $c
     * @return array{0: array<string, array{kind: string, ua: string, dns: list<string>, ranges: list<string>, lists: array<string, array<string, ?string>>, policy: string, nets: array<string, list<array{0: string, 1: int}>>}>, 1: string, 2: list<string>, 3: string, 4: array<string, string>}
     */
    private static function knownCrawlers(array $c, string $verify): array
    {
        $policies = self::crawlerPolicy($c);
        $engines = is_array($c['challenge'] ?? null) ? ($c['challenge']['searchEngines'] ?? true) : true;
        if ($engines === true && ($c['crawlers'] ?? null) === null) {
            $ready = Rules\Shipped::crawlers();
            $crawlers = $ready['crawlers'];
            foreach ($policies as $key => $policy) {
                if (!in_array($policy, Rules\RuleFile::POLICIES, true) || (!isset($crawlers[$key]) && !in_array($key, Rules\RuleFile::KINDS, true))) {
                    throw self::wrong("crawlerPolicy.$key", 'allow, check or block, for a kind (' . implode(', ', Rules\RuleFile::KINDS) . ') or a crawler\'s ID');
                }
            }
            if ($policies !== []) {
                foreach ($crawlers as $id => $x) {
                    $crawlers[$id]['policy'] = $policies[$id] ?? $policies[$x['kind']] ?? 'allow';
                }
            }
            return [$crawlers, $ready['index'], $ready['ids'], $verify, $policies];
        }
        $crawlers = self::crawlers($c);
        return [$crawlers, ...self::crawlerIndex($crawlers), ...[$verify, $policies]];
    }

    /**
     * The known crawlers: the shipped list, a site's own, the old
     * challenge.searchEngines map (pattern => DNS suffixes), or none.
     *
     * @param array<mixed> $c
     * @return array<string, array{kind: string, ua: string, dns: list<string>, ranges: list<string>, lists: array<string, array<string, ?string>>, policy: string, nets: array<string, list<array{0: string, 1: int}>>}>
     */
    private static function crawlers(array $c): array
    {
        $engines = is_array($c['challenge'] ?? null) ? ($c['challenge']['searchEngines'] ?? true) : true;
        if ($engines === false) {
            return [];
        }
        if (is_array($engines)) {
            $list = [];
            $i = 0;
            foreach ($engines as $pattern => $suffixes) {
                $list['searchEngines[' . $i++ . ']'] = ['kind' => 'search', 'ua' => (string) $pattern, 'dns' => $suffixes, 'ranges' => []];
            }
        } else {
            $list = $c['crawlers'] ?? [];
        }
        if (!is_array($list)) {
            throw self::wrong('crawlers', 'null or an array of ID => crawler');
        }
        $policies = self::map($c, 'crawlerPolicy');
        $out = [];
        foreach ($list as $id => $x) {
            $id = (string) $id;
            if (!is_array($x) || !in_array($x['kind'] ?? null, Rules\RuleFile::KINDS, true)
                || !is_string($x['ua'] ?? null) || @preg_match($x['ua'], '') === false) {
                throw self::wrong("crawlers.$id", "an array of 'kind' (" . implode(', ', Rules\RuleFile::KINDS) . "), 'ua' (a regex), 'dns' and 'ranges'");
            }
            $ranges = self::strings($x, 'ranges', "crawlers.$id.ranges");
            foreach ($ranges as $r) {
                if (!Rules\CrawlerLists::isRange($r)) {
                    throw self::wrong("crawlers.$id.ranges", 'addresses or ranges (192.0.2.0/24)');
                }
            }
            $policy = $policies[$id] ?? $policies[$x['kind']] ?? 'allow';
            if (!in_array($policy, Rules\RuleFile::POLICIES, true)) {
                throw self::wrong("crawlerPolicy.$id", implode(', ', Rules\RuleFile::POLICIES));
            }
            /** @var array<string, array<string, ?string>> $lists */
            $lists = is_array($x['lists'] ?? null) ? $x['lists'] : [];
            // The ranges as a lookup, built once (compiled with the settings).
            $nets = IpAddress::index($ranges);
            $out[$id] = ['kind' => $x['kind'], 'ua' => $x['ua'], 'dns' => self::strings($x, 'dns', "crawlers.$id.dns"), 'ranges' => $ranges, 'lists' => $lists, 'policy' => (string) $policy, 'nets' => $nets];
        }
        foreach ($policies as $key => $policy) {
            if (!isset($out[$key]) && !in_array($key, Rules\RuleFile::KINDS, true)) {
                throw self::wrong("crawlerPolicy.$key", 'a kind (' . implode(', ', Rules\RuleFile::KINDS) . ') or a crawler\'s ID');
            }
        }
        return $out;
    }

    /**
     * plugin … from <file>: plugin class => the file that holds it, as given
     * (absolute by the time the rules are compiled).
     *
     * @param array<mixed> $c
     * @return array<class-string, string>
     */
    private static function pluginFiles(array $c): array
    {
        $out = [];
        foreach (self::map($c, 'pluginFiles') as $class => $file) {
            if (!is_string($class) || !preg_match('/^[A-Za-z_][A-Za-z0-9_]*(\\\\[A-Za-z_][A-Za-z0-9_]*)*$/', $class) || !is_string($file) || $file === '') {
                throw self::wrong('pluginFiles', 'a map of plugin class names to the files that hold them');
            }
            /** @var class-string $class */
            $out[$class] = $file;
        }
        return $out;
    }

    /**
     * Plugins by their class names (Vendor\Package\MyPlugin): checked for their
     * form here; whether the class is there and a Plugin, when the shield makes
     * them (and by "check").
     *
     * @param array<mixed> $c
     * @return list<class-string>
     */
    private static function plugins(array $c): array
    {
        $out = [];
        foreach ((array) ($c['plugins'] ?? []) as $class) {
            if (!is_string($class) || !preg_match('/^\\\\?[A-Za-z_][A-Za-z0-9_]*(\\\\[A-Za-z_][A-Za-z0-9_]*)*$/', $class)) {
                throw self::wrong('plugins', 'class names such as Vendor\\Package\\MyPlugin');
            }
            /** @var class-string $name */
            $name = ltrim($class, '\\');
            $out[] = $name;
        }
        return array_values(array_unique($out));
    }

    /**
     * The extensions' settings: extension id => its checked values. Nothing
     * here is read by the core; an extension's compile() (0031 B.2) writes
     * what its plugin reads at request time.
     *
     * @param array<mixed> $c
     * @return array<string, array<string, mixed>>
     */
    private static function ext(array $c): array
    {
        $out = [];
        foreach (self::map($c, 'ext') as $id => $values) {
            if (!is_string($id) || !preg_match('/^[a-z][a-z0-9-]{0,31}$/', $id) || !is_array($values)) {
                throw self::wrong('ext', 'a map of extension ids (letters, digits, "-") to their settings');
            }
            /** @var array<string, mixed> $values */
            $out[$id] = $values;
        }
        return $out;
    }

    /**
     * Which plugins provide which capability: hook name => the classes, as the
     * compiler recorded them (instanceof at compile time, 0031 B.2), so a
     * request asks one array instead of every plugin.
     *
     * @param array<mixed> $c
     * @return array<string, list<class-string>>
     */
    private static function hooks(array $c): array
    {
        $out = [];
        foreach (self::map($c, 'hooks') as $hook => $classes) {
            if (!is_string($hook) || !preg_match('/^[a-z][a-zA-Z0-9]{0,31}$/', $hook) || !is_array($classes)) {
                throw self::wrong('hooks', 'a map of hook names to lists of plugin classes');
            }
            $out[$hook] = self::plugins(['plugins' => $classes]);
        }
        return $out;
    }

    /**
     * Pages given in the settings array (for tests and a site's own): path
     * => entry as Routes has them (key, tab, role, order; ext optional).
     * compiledExt() adds the core's and the extensions' pages to them.
     *
     * @param array<mixed> $c
     * @return array<string, array{key: string, ext: ?string, tab: ?array{0: string, 1: string}, role: string, order: int}>
     */
    private static function routes(array $c): array
    {
        $out = [];
        foreach (self::map($c, 'routes') as $path => $route) {
            if (!is_string($path) || $path === '' || $path[0] !== '/' || !is_array($route)) {
                throw self::wrong('routes', 'a map of paths (starting with "/") to what each page is');
            }
            $out[$path] = Routes::entry($route, 'routes', $path);
        }
        return $out;
    }

    /**
     * The addresses let in for a while (exempt … until), those still in force.
     *
     * @param array<mixed> $c
     * @return list<string>
     */
    private static function exemptForNow(array $c): array
    {
        $out = [];
        $now = time();
        foreach ((array) ($c['exemptUntil'] ?? []) as $e) {
            if (is_array($e) && (!is_int($e['until'] ?? null) || $e['until'] > $now)) {
                foreach ((array) ($e['ips'] ?? []) as $ip) {
                    if (is_string($ip)) {
                        $out[] = $ip;
                    }
                }
            }
        }
        return $out;
    }

    /**
     * The deny list (the entries in force, and as a lookup), when the next
     * entry ends (exempt … until included), the list files' directory, and
     * the automatic bans.
     *
     * @param array<mixed> $c
     * @param array<string, Budget> $budgets
     * @return array{0: list<array{ips: list<string>, until: ?int, rule: string}>, 1: array{4: string, 6: string, ids: string, dir?: string}|array{}, 2: int, 3: int, 4: ?string, 5: list<array{after: int, signal: string, in: int, for: int, rule: string}>, 6: int, 7: int}
     */
    private static function lists(array $c, array $budgets): array
    {
        $now = time();
        $next = 0;
        $deny = [];
        $entries = [];
        foreach ((array) ($c['deny'] ?? []) as $i => $e) {
            if (!is_array($e) || !is_array($e['ips'] ?? null)) {
                throw self::wrong("deny[$i]", "['ips' => [addresses], 'until' => a Unix time or null]");
            }
            $until = is_int($e['until'] ?? null) ? $e['until'] : null;
            if ($until !== null && $until <= $now) {
                continue;                       // over: left out
            }
            $list = [];
            foreach ($e['ips'] as $ip) {
                $slash = is_string($ip) ? strpos($ip, '/') : false;
                if (!is_string($ip) || @inet_pton($slash === false ? $ip : substr($ip, 0, $slash)) === false) {
                    throw self::wrong("deny[$i].ips", 'addresses or ranges (203.0.113.7, 198.51.100.0/24, 2001:db8::/32)');
                }
                $list[] = $ip;
            }
            $rule = is_string($e['rule'] ?? null) ? $e['rule'] : "deny[$i]";
            $entries[] = [$list, $rule];
            if (count($deny) < self::DENY_SHOWN) {
                $deny[] = ['ips' => $list, 'until' => $until, 'rule' => $rule];
            }
            if ($until !== null && ($next === 0 || $until < $next)) {
                $next = $until;
            }
        }
        foreach ((array) ($c['exemptUntil'] ?? []) as $e) {
            $until = is_array($e) && is_int($e['until'] ?? null) ? $e['until'] : 0;
            if ($until > $now && ($next === 0 || $until < $next)) {
                $next = $until;
            }
        }
        $bans = [];
        foreach ((array) ($c['bans'] ?? []) as $i => $b) {
            if (!is_array($b) || !is_int($b['after'] ?? null) || !is_string($b['signal'] ?? null) || !is_int($b['in'] ?? null) || !is_int($b['for'] ?? null)
                || $b['after'] < 1 || $b['in'] < 1 || $b['for'] < 1) {
                throw self::wrong("bans[$i]", "['after' => n, 'signal' => limits|refusals|checks|<budget>, 'in' => seconds, 'for' => seconds]");
            }
            if (!in_array($b['signal'], ['limits', 'refusals', 'checks'], true) && !isset($budgets[$b['signal']])) {
                throw self::wrong("bans[$i].signal", "limits, refusals, checks or a budget's name -- there is no budget \"{$b['signal']}\"");
            }
            $bans[] = ['after' => $b['after'], 'signal' => $b['signal'], 'in' => $b['in'], 'for' => $b['for'], 'rule' => is_string($b['rule'] ?? null) ? $b['rule'] : "bans[$i]"];
        }
        $growth = $c['banGrowth'] ?? 2;
        $max = $c['banMax'] ?? 86400;
        if (!is_int($growth) || $growth < 1 || !is_int($max) || $max < 1) {
            throw self::wrong('banGrowth/banMax', 'a whole number of at least 1');
        }
        $dir = $c['listsDir'] ?? null;
        return [$deny, $entries === [] ? [] : IpTable::build($entries), count($entries), $next, is_string($dir) && $dir !== '' ? $dir : null, $bans, $growth, $max];
    }

    /**
     * post-origin same: what to do without Origin and Referer, and the paths it never applies to.
     *
     * @param array<mixed> $c
     * @return array{missing: string, except: list<string>}|null
     */
    private static function postOrigin(array $c): ?array
    {
        $p = $c['postOrigin'] ?? null;
        if ($p === null) {
            return null;
        }
        if (!is_array($p)) {
            throw self::wrong('postOrigin', "null or ['missing' => 'check', 'except' => [path patterns]]");
        }
        if (($p['same'] ?? true) !== true) {
            return null;                        // a rule file's "post-origin except" without "post-origin same": off
        }
        $missing = self::string($p, 'missing', 'postOrigin.missing', 'check');
        if (!in_array($missing, ['check', 'allow', 'refuse'], true)) {
            throw self::wrong('postOrigin.missing', 'check (the browser check, the default), allow or refuse');
        }
        return ['missing' => $missing, 'except' => self::patternList($p['except'] ?? [], 'postOrigin.except')];
    }

    /**
     * A setting that must be a list: missing is empty, anything else but an array a mistake (said, not ignored).
     *
     * @param array<mixed> $c
     */
    private static function listOf(array $c, string $key): mixed
    {
        if (!isset($c[$key])) {
            return [];
        }
        if (!is_array($c[$key])) {
            throw self::wrong($key, 'a list of path patterns');
        }
        return $c[$key];
    }

    /**
     * A list of path patterns (regular expressions, as the rule files compile them), each checked.
     *
     * @return list<string>
     */
    private static function patternList(mixed $list, string $key): array
    {
        $out = [];
        foreach (is_array($list) ? $list : [] as $i => $p) {
            if (!is_string($p) || @preg_match($p, '') === false) {
                throw self::wrong("{$key}[$i]", 'a path pattern (stats-skip **/osm-proxy/** in a rule file)');
            }
            $out[] = $p;
        }
        return $out;
    }

    /**
     * The lists with the feeds' next end: the settings are built again when a
     * fetched list grows too old (as when a list entry ends).
     *
     * @param array{0: list<array{ips: list<string>, until: ?int, rule: string}>, 1: array{4: string, 6: string, ids: string, dir?: string}|array{}, 2: int, 3: int, 4: ?string, 5: list<array{after: int, signal: string, in: int, for: int, rule: string}>, 6: int, 7: int} $lists
     * @param array{0: list<mixed>, 1: array<string, mixed>, 2: list<mixed>, 3: array<string, int>, 4: int, 5: int} $feeds
     * @return array{0: list<array{ips: list<string>, until: ?int, rule: string}>, 1: array{4: string, 6: string, ids: string, dir?: string}|array{}, 2: int, 3: int, 4: ?string, 5: list<array{after: int, signal: string, in: int, for: int, rule: string}>, 6: int, 7: int}
     */
    private static function withFeeds(array $lists, array $feeds, int $more = 0): array
    {
        foreach ([$feeds[5], $more] as $next) {
            if ($next > 0 && ($lists[3] === 0 || $next < $lists[3])) {
                $lists[3] = $next;
            }
        }
        return $lists;
    }

    /**
     * When the next dashboard-access entry ends: the settings are built again then.
     *
     * @param array<mixed> $c
     */
    private static function accessNext(array $c): int
    {
        $next = 0;
        foreach ((array) ($c['dashboardAccess'] ?? []) as $a) {
            $until = is_array($a) && is_int($a['until'] ?? null) ? $a['until'] : 0;
            if ($until > time() && ($next === 0 || $until < $next)) {
                $next = $until;
            }
        }
        return $next;
    }

    /**
     * The public blocklists (feed …, proposal 0025): each fetched list read
     * from <store-dir>/feeds, unless it is older than feeds-max-age (then left
     * out, and said so); per action one table of the lists without "at", each
     * list with "at" its own. Returns [feeds, tables, at, weights, max age,
     * when the next list grows too old].
     *
     * @param array<mixed> $c
     * @return array{0: list<array{name: string, title: string, action: string, weight: int, paths: list<string>, rule: string, terms: string, urls: list<string>, format: string, every: int, wideOk: bool, count: int, fetched: int, state: string, file: ?string}>, 1: array<string, array{4: string, 6: string, ids: string, dir?: string}>, 2: list<array{action: string, table: array{4: string, 6: string, ids: string, dir?: string}, paths: list<string>}>, 3: array<string, int>, 4: int, 5: int}
     */
    private static function feeds(array $c): array
    {
        $maxAge = $c['feedsMaxAge'] ?? 259200;
        if (!is_int($maxAge) || $maxAge < 3600) {
            throw self::wrong('feedsMaxAge', 'seconds, at least an hour');
        }
        $dir = is_string($c['storeDir'] ?? null) && $c['storeDir'] !== '' ? $c['storeDir'] . '/feeds' : null;
        $now = time();
        $feeds = [];
        $entries = [];
        $at = [];
        $weights = [];
        $next = 0;
        foreach ((array) ($c['feeds'] ?? []) as $i => $f) {
            if (!is_array($f) || !is_string($f['name'] ?? null) || preg_match('/^[a-z0-9][a-z0-9-]{0,40}$/', $f['name']) !== 1
                || !in_array($f['action'] ?? null, ['deny', 'check', 'signal'], true)) {
                throw self::wrong("feeds[$i]", "['name' => a name, 'action' => deny|check|signal, …] (feed <name> <action> in a rule file)");
            }
            $name = $f['name'];
            $rule = is_string($f['rule'] ?? null) ? $f['rule'] : "feeds[$i]";
            $paths = array_values(array_filter((array) ($f['paths'] ?? []), 'is_string'));
            $file = is_string($f['file'] ?? null) ? $f['file'] : null;
            if ($file !== null) {
                // feed … from <file>: the site's own list, as current as the rules (no fetch, no age).
                $body = @file_get_contents($file);
                $ranges = $body === false ? [] : \CjwNetwork\RequestShield\Rules\Feeds::clean(\CjwNetwork\RequestShield\Rules\Feeds::parse($body,
                    is_string($f['format'] ?? null) ? $f['format'] : 'plain'), (bool) ($f['wideOk'] ?? false))['ranges'];
                $meta = ['checked' => (int) @filemtime($file), 'count' => count($ranges)];
                $state = $body === false ? 'not fetched' : 'in force';
            } else {
                $meta = $dir === null ? ['checked' => 0, 'count' => 0] : \CjwNetwork\RequestShield\Rules\Feeds::meta($dir, $name);
                $text = $dir === null ? false : @file_get_contents("$dir/$name.txt");
                $state = 'in force';
                if ($text === false) {
                    $state = 'not fetched';
                } elseif ($now - $meta['checked'] > $maxAge) {
                    $state = 'too old';
                }
                $ranges = $state === 'in force' ? array_values(array_filter(explode("\n", (string) $text), static fn (string $l): bool => $l !== '')) : [];
            }
            if ($state === 'in force') {
                if ($file === null) {
                    $until = $meta['checked'] + $maxAge + 1;
                    $next = $next === 0 ? $until : min($next, $until);
                }
                if ($paths === []) {
                    $entries[$f['action']][] = [$ranges, $rule];
                } else {
                    $at[] = ['action' => (string) $f['action'], 'table' => \CjwNetwork\RequestShield\IpTable::build([[$ranges, $rule]]), 'paths' => $paths];
                }
            }
            if ($f['action'] === 'signal') {
                $weights[$rule] = max(1, min(99, is_int($f['weight'] ?? null) ? $f['weight'] : 1));
            }
            $feeds[] = [
                'name' => $name, 'title' => is_string($f['title'] ?? null) ? $f['title'] : $name, 'action' => (string) $f['action'], 'weight' => $weights[$rule] ?? 1,
                'paths' => $paths, 'rule' => $rule, 'terms' => is_string($f['terms'] ?? null) ? $f['terms'] : '',
                'urls' => array_values(array_filter((array) ($f['urls'] ?? []), 'is_string')), 'format' => is_string($f['format'] ?? null) ? $f['format'] : 'plain',
                'every' => is_int($f['every'] ?? null) ? $f['every'] : 3600, 'wideOk' => (bool) ($f['wideOk'] ?? false),
                'count' => count($ranges), 'fetched' => $meta['checked'], 'state' => $state, 'file' => $file,
            ];
        }
        $tables = [];
        foreach ($entries as $action => $list) {
            $tables[(string) $action] = \CjwNetwork\RequestShield\IpTable::build($list);
        }
        return [$feeds, $tables, $at, $weights, $maxAge, $next];
    }

    /**
     * The live view's memory: on or off, and how long an entry stays (at most
     * a day); and where a ban is kept (memory, or also a file).
     *
     * @param array<mixed> $c
     * @return array{0: bool, 1: int, 2: string}
     */
    private static function live(array $c): array
    {
        $l = $c['live'] ?? [];
        $l = is_array($l) ? $l : ['enabled' => $l];
        $on = $l['enabled'] ?? false;
        $keep = $l['keep'] ?? 3600;
        if (!is_bool($on) || !is_int($keep) || $keep < 60 || $keep > 86400) {
            throw self::wrong('live', "['enabled' => true|false, 'keep' => seconds from 60 to 86400]");
        }
        $banKeep = $c['banKeep'] ?? 'memory';
        if (!in_array($banKeep, ['memory', 'file'], true)) {
            throw self::wrong('banKeep', 'memory or file');
        }
        return [$on, $keep, $banKeep];
    }

    /**
     * The site blocks (from a rule file): website name => block, this block,
     * and which name picks one.
     *
     * @param array<mixed> $c
     * @return array{0: array<string, string>, 1: ?string, 2: string}
     */
    private static function sites(array $c): array
    {
        $map = [];
        foreach ((array) ($c['sites'] ?? []) as $name => $id) {
            if (!is_string($id)) {
                throw self::wrong('sites', 'website name => site block');
            }
            $map[(string) $name] = $id;
        }
        $site = $c['site'] ?? null;
        $from = $c['siteFrom'] ?? 'server-name';
        if (!in_array($from, ['server-name', 'host'], true)) {
            throw self::wrong('siteFrom', 'server-name or host');
        }
        return [$map, is_string($site) ? $site : null, $from];
    }

    /**
     * The site block a request belongs to, or null (the base): its name --
     * the web server's (SERVER_NAME) or, with site-from host, the Host header
     * (from a trusted proxy: X-Forwarded-Host) -- in lower case, without its
     * port and a trailing dot; looked up as itself, as *.<the rest>, then
     * "default". Two isset(), no expression.
     *
     * @param array<mixed> $server $_SERVER
     */
    public function siteFor(array $server): ?string
    {
        return $this->sites === [] ? null : self::pick($this->sites, $this->siteFrom, $this->trustedProxies, $server);
    }

    /**
     * siteFor() on the plain values -- for loadFor(), which picks the website
     * before it makes any settings.
     *
     * @param array<string, string> $sites
     * @param list<string> $trusted
     * @param array<mixed> $server
     */
    private static function pick(array $sites, string $from, array $trusted, array $server): ?string
    {
        $name = $server['SERVER_NAME'] ?? '';
        if ($from === 'host') {
            $name = $server['HTTP_HOST'] ?? $name;
            $forwarded = $server['HTTP_X_FORWARDED_HOST'] ?? null;
            $peer = $server['REMOTE_ADDR'] ?? '';
            if (is_string($forwarded) && is_string($peer) && $peer !== '' && $trusted !== [] && IpAddress::inRanges($peer, $trusted)) {
                $name = trim(explode(',', $forwarded)[0]);
            }
        }
        $name = is_string($name) ? strtolower($name) : '';
        // Without its port and a trailing dot -- string functions, no expression.
        $colon = strrpos($name, ':');
        if ($colon !== false && ctype_digit(substr($name, $colon + 1))) {
            $name = substr($name, 0, $colon);
        }
        $name = rtrim($name, '.');
        if ($name !== '' && isset($sites[$name])) {
            return $sites[$name];
        }
        $dot = strpos($name, '.');
        if ($dot !== false && isset($sites['*' . substr($name, $dot)])) {
            return $sites['*' . substr($name, $dot)];
        }
        return $sites['default'] ?? null;
    }

    /** @param array<mixed> $c */
    /**
     * dashboard-access: who may open the dashboard's pages, by a token's hash --
     * '*' (everything) or an opaque principal (customer-a): what a principal
     * may see is the pages' business (the statistics map it to a group's
     * websites), the core only knows the id. Ended lines are left out.
     * Plus dashboard-session, the login's lifetime.
     *
     * @param array<mixed> $c
     * @return array{0: list<array{who: string, hash: string, until: ?int, rule: string}>, 1: int}
     */
    private static function dashboardAccess(array $c): array
    {
        $out = [];
        foreach ((array) ($c['dashboardAccess'] ?? []) as $i => $a) {
            if (!is_array($a) || !is_string($a['who'] ?? null) || !is_string($a['hash'] ?? null) || preg_match('/^[0-9a-f]{64}$/', $a['hash']) !== 1) {
                throw self::wrong("dashboardAccess[$i]", "['who' => '*' or a principal, 'hash' => the token's SHA-256 in hex]");
            }
            $who = $a['who'] === '*' ? '*' : self::principal($a['who']);
            if ($who === '') {
                throw self::wrong("dashboardAccess[$i]", "* or a principal of letters and digits -- not \"{$a['who']}\"");
            }
            $until = is_int($a['until'] ?? null) ? $a['until'] : null;
            if ($until !== null && $until <= time()) {
                continue;                               // ended: left out
            }
            $out[] = ['who' => $who, 'hash' => $a['hash'], 'until' => $until, 'rule' => is_string($a['rule'] ?? null) ? $a['rule'] : "dashboardAccess[$i]"];
        }
        $session = $c['dashboardSession'] ?? 28800;
        if (!is_int($session) || $session < 60 || $session > 2592000) {
            throw self::wrong('dashboardSession', 'seconds from 60 to 2592000 (30 days)');
        }
        return [$out, $session];
    }

    /** A principal's id, as the dashboard and its links name it: "Customer A" -> customer-a. */
    public static function principal(string $name): string
    {
        return trim((string) preg_replace('/[^a-z0-9]+/', '-', strtolower($name)), '-');
    }

    /**
     * A learning run (0016), as Learn::read() found it when the rules were compiled.
     *
     * @param array<mixed> $c
     * @return array{until: int, token: string, from: list<string>}|null
     */
    private static function learn(array $c): ?array
    {
        $l = $c['learn'] ?? null;
        if ($l === null) {
            return null;
        }
        if (!is_array($l) || !is_int($l['until'] ?? null) || !is_string($l['token'] ?? null) || preg_match('/^[0-9a-f]{64}$/', $l['token']) !== 1
            || !is_array($l['from'] ?? null) || array_filter($l['from'], static fn ($a): bool => !is_string($a)) !== []) {
            throw self::wrong('learn', "until (a time), token (a SHA-256 in hex), from (addresses) -- what request-shield learn writes");
        }
        /** @var list<string> $from */
        $from = array_values($l['from']);
        return ['until' => $l['until'], 'token' => $l['token'], 'from' => $from];
    }

    /**
     * @param array<mixed> $c
     * @return array<int|string, array<string, string>> status (a number keeps its key as one) => language => HTML
     */
    private static function errorPages(array $c): array
    {
        $pages = $c['errorPages'] ?? [];
        if (!is_array($pages)) {
            throw self::wrong('errorPages', 'status => language => HTML (set error-page in a rule file)');
        }
        $out = [];
        foreach ($pages as $status => $byLang) {
            if (!in_array((string) $status, ErrorPage::STATUSES, true) || !is_array($byLang)) {
                throw self::wrong("errorPages.$status", 'a status the shield refuses with (' . implode(', ', ErrorPage::STATUSES) . ') => language => HTML');
            }
            foreach ($byLang as $lang => $html) {
                if (!is_string($html) || strlen($html) > ErrorPage::MAX || ($lang !== '' && preg_match('/^[a-z]{2,3}(-[a-z0-9]{2,8})?$/', (string) $lang) !== 1)) {
                    throw self::wrong("errorPages.$status.$lang", 'HTML of at most 64 KB, by a language code ("" for all)');
                }
                $out[(string) $status][(string) $lang] = $html;
            }
        }
        return $out;
    }

    /** @param array<mixed> $c the docs' folder: an http(s) address or a path on the site; "off" (or "") for no links */
    private static function docsUrl(array $c): string
    {
        $u = $c['docsUrl'] ?? Help::DOCS;
        if ($u === 'off' || $u === '') {
            return '';
        }
        if (!is_string($u) || preg_match('#^(https?://[^\s"<>]+|/(?!/)[^\s"<>]*)$#i', $u) !== 1) {
            throw self::wrong('docsUrl', 'an address such as https://docs.example.org/request-shield, a path such as /docs, or off');
        }
        return rtrim($u, '/');
    }

    /** @param array<mixed> $c */
    private static function dashboardPath(array $c): string
    {
        $p = $c['dashboardPath'] ?? '/rs';
        // Names of letters, digits and . _ ~ -, but no "." or ".." of their own.
        if (!is_string($p) || !preg_match('#^(/[A-Za-z0-9._~-]+)+$#', $p) || preg_match('#/\.+(/|$)#', $p)) {
            throw self::wrong('dashboardPath', 'a path such as /rs or /admin/rs');
        }
        return $p;
    }

    /**
     * @param array<mixed> $c
     * @return array<string, string>
     */
    private static function crawlerPolicy(array $c): array
    {
        $out = [];
        foreach (self::map($c, 'crawlerPolicy') as $key => $policy) {
            if (!is_string($policy)) {
                throw self::wrong("crawlerPolicy.$key", implode(', ', Rules\RuleFile::POLICIES));
            }
            $out[(string) $key] = $policy;
        }
        return $out;
    }

    /**
     * Every crawler's User-Agent pattern in one expression: a request that
     * names none costs one match. (*MARK:n) says which one matched.
     *
     * @param array<string, array{ua: string}> $crawlers
     * @return array{0: string, 1: list<string>}
     */
    public static function crawlerIndex(array $crawlers): array
    {
        $parts = [];
        $ids = [];
        foreach ($crawlers as $id => $x) {
            // '#…#i' or '/…/i': the expression between the delimiters.
            $d = $x['ua'][0];
            $end = strrpos($x['ua'], $d);
            $inner = substr($x['ua'], 1, (int) $end - 1);
            // Into '#…#': a "#" of another delimiter's expression needs its backslash.
            $inner = $d === '#' ? $inner : str_replace('#', '\#', str_replace('\\' . $d, $d, $inner));
            $parts[] = '(?:' . $inner . ')(*MARK:' . count($ids) . ')';
            $ids[] = $id;
        }
        $index = $parts === [] ? '' : '#' . implode('|', $parts) . '#i';
        if ($index !== '' && @preg_match($index, '') === false) {
            throw self::wrong('crawlers', 'User-Agent patterns that go into one expression (no back references)');
        }
        return [$index, $ids];
    }

    /**
     * @param array<mixed> $list
     * @return list<array{paths: list<string>|null, exact: array<string, string>, globs: array<string, string>}>
     */
    private static function queryParams(array $list): array
    {
        $out = [];
        $type = static function ($t, string $where): string {
            if (!is_string($t) || !(in_array($t, ['int', 'number', 'word', 'id', 'list', 'text', 'any'], true)
                || (strncmp($t, '#', 1) === 0 && @preg_match($t, '') !== false))) {
                throw self::wrong($where, 'int, number, word, id, list, text, any or a regex');
            }
            return $t;
        };
        foreach ($list as $i => $r) {
            if (!is_array($r)) {
                throw self::wrong("queryParams.$i", "an array of 'paths', 'exact' and 'globs'");
            }
            $exact = [];
            foreach (self::map($r, 'exact', "queryParams.$i.exact") as $name => $t) {
                $exact[(string) $name] = $type($t, "queryParams.$i.exact.$name");
            }
            $globs = [];
            foreach (self::map($r, 'globs', "queryParams.$i.globs") as $glob => $t) {
                if (@preg_match((string) $glob, '') === false) {
                    throw self::wrong("queryParams.$i.globs", 'regular expressions as keys');
                }
                $globs[(string) $glob] = $type($t, "queryParams.$i.globs");
            }
            $out[] = ['paths' => self::stringsOrNull($r, 'paths', "queryParams.$i.paths"), 'exact' => $exact, 'globs' => $globs];
        }
        return $out;
    }

    /**
     * For each target, the texts every one of its patterns starts with --
     * "${" for "\$\{(jndi|...)" -- when there are such: the request is then
     * normalised and matched only if its raw value holds one of them, or a
     * "%" (an encoding). Normalising can decode, lower-case and merge white
     * space, none of which makes such a text appear. A target where any
     * pattern can start otherwise gets none, and is always matched.
     *
     * @param list<array{target: string, patterns: list<string>}> $rules
     * @return array<string, list<string>>
     */
    public static function hints(array $rules): array
    {
        $by = [];
        $none = [];
        foreach ($rules as $r) {
            foreach ($r['patterns'] as $p) {
                if (!preg_match('/^#(.*)#i?$/s', $p, $m)) {
                    $none[$r['target']] = true;
                    continue;
                }
                foreach (self::alternatives($m[1]) as $alt) {
                    $lit = self::leadingLiteral($alt);
                    if (strlen($lit) < 2) {
                        $none[$r['target']] = true;
                        continue 2;
                    }
                    $by[$r['target']][strtolower($lit)] = true;
                }
            }
        }
        $out = [];
        foreach ($by as $target => $lits) {
            if (isset($none[$target])) {
                continue;
            }
            // A text that holds a shorter one is found with it: only the shorter.
            $keep = [];
            foreach (array_keys($lits) as $l) {
                foreach (array_keys($lits) as $other) {
                    if ($other !== $l && strpos((string) $l, (string) $other) !== false) {
                        continue 2;
                    }
                }
                $keep[] = (string) $l;
            }
            $out[$target] = $keep;
        }
        return $out;
    }

    /** @return list<string> an expression's top-level alternatives */
    private static function alternatives(string $re): array
    {
        $out = [];
        $depth = 0;
        $class = false;
        $start = 0;
        for ($i = 0, $n = strlen($re); $i < $n; $i++) {
            $c = $re[$i];
            if ($c === '\\') {
                $i++;
            } elseif ($class) {
                $class = $c !== ']';
            } elseif ($c === '[') {
                $class = true;
            } elseif ($c === '(') {
                $depth++;
            } elseif ($c === ')') {
                $depth--;
            } elseif ($c === '|' && $depth === 0) {
                $out[] = substr($re, $start, $i - $start);
                $start = $i + 1;
            }
        }
        $out[] = substr($re, $start);
        return $out;
    }

    /** The plain text an alternative has to start with ("\$\{" -> "${"); '' if none. */
    private static function leadingLiteral(string $alt): string
    {
        $lit = '';
        for ($i = 0, $n = strlen($alt); $i < $n; $i++) {
            $c = $alt[$i];
            if ($c === '\\') {
                $next = $alt[$i + 1] ?? '';
                if ($next === '' || ctype_alnum($next)) {
                    break;                  // \s, \d, \b, \1 ...: not a plain character
                }
                $lit .= $next;
                $i++;
                $last = $i;
                continue;
            }
            if (strpos('.[](){}?*+|^$', $c) !== false) {
                break;
            }
            $lit .= $c;
        }
        // A quantifier that allows none takes the last character back.
        $after = $alt[$i] ?? '';
        if ($lit !== '' && ($after === '?' || $after === '*' || $after === '{')) {
            $lit = substr($lit, 0, -1);
        }
        return $lit;
    }

    /**
     * Several expressions as one: "#a#", "#b#i" -> "#(?:a)|(?i:b)#". Only
     * where that means the same -- delimiters "#" or "/", no flags but "i",
     * no back references or named groups (they would point elsewhere);
     * otherwise '' and the patterns are matched one by one, as before.
     *
     * @param list<string> $patterns
     */
    public static function combine(array $patterns): string
    {
        if (count($patterns) < 2) {
            return '';
        }
        $parts = [];
        foreach ($patterns as $p) {
            if (!preg_match('~^([#/])(.*)\1(i?)$~s', $p, $m) || preg_match('/\\\\[1-9]|\\\\g\{?-?\d|\(\?P?[<\'=]|\(\?\|/', $m[2])) {
                return '';
            }
            $body = $m[1] === '/' ? str_replace(['\\/', '#'], ['/', '\\#'], $m[2]) : $m[2];
            $parts[] = ($m[3] === 'i' ? '(?i:' : '(?:') . $body . ')';
        }
        $all = '#' . implode('|', $parts) . '#';
        return @preg_match($all, '') === false ? '' : $all;
    }

    /**
     * The attack rules, and per target one expression of all its patterns --
     * a clean request then costs one match per target.
     *
     * @param array<mixed> $list
     * @return array{0: list<array{target: string, patterns: list<string>}>, 1: array<string, string>}
     */
    private static function contentRules(array $list): array
    {
        $rules = [];
        $bodies = [];
        foreach ($list as $i => $r) {
            if (!is_array($r)) {
                throw self::wrong("contentRules.$i", "an array of 'target' and 'patterns'");
            }
            $target = strtolower(self::string($r, 'target', "contentRules.$i.target"));
            if (!in_array($target, ['query', 'headers', 'anywhere'], true) && !preg_match('/^header:[a-z0-9-]+$/', $target)) {
                throw self::wrong("contentRules.$i.target", 'query, headers, anywhere or header:<name>');
            }
            $patterns = self::strings($r, 'patterns', "contentRules.$i.patterns");
            foreach ($patterns as $p) {
                if (!preg_match('/^#(.*)#i?$/s', $p, $m) || @preg_match($p, '') === false) {
                    throw self::wrong("contentRules.$i.patterns", 'regular expressions in #...# (flag i at most)');
                }
                // All of a target's patterns become one expression: a back
                // reference would point at another pattern's group, and a name
                // could be taken twice; a call or a condition by number ((?1), (?R),
                // \g<1>, (?(1)…)) would reach another pattern's group too. A look
                // around ((?<!…), (?=…)) or a relative call ((?-1)) is fine.
                if (preg_match('/\\\\[1-9]|\\\\g\{?-?\d|\\\\g[<\']\+?\d|\\\\k[<{\']|\(\?(P?<(?![=!])|\'|P[=>]|[R0-9]|\+\d|\((\d|R))/', $m[1])) {
                    throw self::wrong("contentRules.$i.patterns", 'expressions without back references, named groups or groups called by number');
                }
                $bodies[$target][] = '(?:' . $m[1] . ')';
            }
            $rules[] = ['target' => $target, 'patterns' => $patterns];
        }
        $index = [];
        foreach ($bodies as $target => $b) {
            $index[$target] = '#' . implode('|', $b) . '#i';
            if (@preg_match($index[$target], '') === false) {
                throw self::wrong('contentRules', 'patterns that also work together (' . $target . ')');
            }
        }
        return [$rules, $index];
    }

    /**
     * @param array<mixed> $o
     * @return array<string, array<string, string>>
     */
    private static function origins(array $o): array
    {
        $out = [];
        foreach ($o as $setting => $list) {
            if (!is_array($list)) {
                throw self::wrong("origins.$setting", 'an array');
            }
            foreach ($list as $what => $where) {
                if (!is_string($where)) {
                    throw self::wrong("origins.$setting", 'an array of strings');
                }
                $out[(string) $setting][(string) $what] = $where;
            }
        }
        return $out;
    }

    /**
     * Where the rule behind a pattern or budget was written ("site.rules:12",
     * "default @scanners.backups"); null for settings from a PHP array.
     */
    public function origin(string $setting, string $what): ?string
    {
        return $this->origins[$setting][$what] ?? null;
    }

    /**
     * The rule's name for the log and the pages: where the setting was written
     * (its ID or file:line), else $fallback -- printable characters only.
     */
    public function ruleName(string $setting, string $what, string $fallback): string
    {
        $origin = $this->origin($setting, $what) ?? $fallback;
        return preg_replace('/[^\x21-\x7e ]/', '?', $origin) ?? $fallback;
    }

    // ── Compiled: checked once, then loaded from OPcache ──────────────────

    /** Deny entries kept as they were written, for the pages; the rest only in the table. */
    public const DENY_SHOWN = 100;

    /** Bumped when the export's shape changes, so old compiled files are rebuilt. */
    /** The capabilities a Plugin may have: hook name => its interface (recorded by compiledExt()). */
    private const HOOKS = ['ruleCounts' => RuleCounts::class, 'sink' => Sink::class, 'pages' => Pages::class, 'ruleProvider' => RuleProvider::class, 'handler' => Handler::class, 'methodHandler' => MethodHandler::class, 'contextHandler' => ContextHandler::class, 'purger' => Purger::class];

    private const FORMAT = 67;       // 3: rule files, several sources, origins; 4: restricted, methodPaths, log; 5: blockExceptions; 6: challenge.language; 7: appChallenge; 8: challenge.home; 9: contentRules; 10: blockedIndex; 11: contentHints; 12: widget; 13: earnBack, apiPaths; 14: dnsLookups; 15: queryParams; 16: queryIndex; 17: mode, uncachedWeight, monitor, challenge.alwaysMaxAge; 18: crawlers; 19: stats, crawlerLog; 20: statsParts, statsFlush; 21: statsMonths; 22: challenge.logo; 23: dashboardPath; 24: statsDepth; 25: origins.queryParams; 26: plugins; 27: sites, site, siteFrom; 28: budget.site; 29: deny, lists, bans; 30: denyTable, denyCount; 31: liveEnabled, liveKeep, banKeep; 32: feeds, feedTables, feedsAt, feedWeights, feedsMaxAge; 33: statsHosts; 34: statsSkip, statsGroups; 36: statsPath; 37: statsAccess, statsSession; 38: budget.paths; 39: postOrigin; 40: backend, statsParts.forms; 41: ext, hooks, routes; 42: stats in ext.stats; 43: routes compiled, stats path in ext.stats; 44: dashboardAccess, dashboardSession (stats-group in ext.stats); 45: hooks recorded; 46: the sink hook; 47: the pages hook; 48: the ruleProvider hook; 49: the handler hook; 50: pluginFiles; 51: routeBases; 52: docsUrl; 53: errorPages; 54: the WAF's pages are a plugin (routes with ext waf); 55: challenge.alwaysMethods; 56: learn; 57: ext.stats.slow (0046); 58: fileMode, dirMode; 59: the methodHandler hook, the cache's purge settings; 60: the contextHandler hook, the cache's role settings; 61: the cache's user hash lookup; 62: the cache's memory and disk cap; 63: the purger hook; 64: cacheableIgnore, cacheableUnknown (0048); 65: ext.cache.page; 66: store-dir, lists-dir relative to the rule file; 67: queryDrop

    public const MODES = ['off', 'monitor', 'enforce', 'strict'];

    /**
     * The settings of a file, checked only when it changed. A ".rules" file
     * is a rule file (Rules\RuleFile), anything else a PHP file returning
     * the settings array; $sources are further rule files or globs read
     * before it (an adapter's extensions), each with its includes.
     *
     * The checked values are kept as a PHP file in $cacheDir, which OPcache
     * serves from memory. Whether the sources changed:
     *   - one file: its mtime and size, on every call (one stat());
     *   - several, with APCu: all of them, at most every "recheck" seconds
     *     (default 10) -- in between not a single stat();
     *   - several, without APCu: the main file on every call; the others
     *     when it changes (bin/request-shield reload touches it).
     * "set recheck 0" checks every source on every call.
     *
     * With site blocks (rules per website, 0024) the base is checked and, for
     * a website's block, $site loads its settings: the same sources, so no
     * check of its own -- one more include from OPcache.
     *
     * @param list<string> $sources
     * @param ?string $site a site block (siteFor() names it); null: the base
     * @param bool $failSafe never throw (the request path, see loadFor()): a file that does not compile
     *   leaves the last good compiled settings in force, or, without any, the shield switched off
     * @throws \InvalidArgumentException for a setting of the wrong type (Rules\RuleFileException: with file and line)
     * @throws \RuntimeException when the file cannot be read
     */
    public static function load(string $file, ?string $cacheDir = null, array $sources = [], ?string $site = null, bool $failSafe = false): self
    {
        $cacheDir ??= self::cacheDirFor($file);
        $key = hash(PHP_VERSION_ID >= 80100 ? 'xxh128' : 'md5', $file . "\0" . implode("\0", $sources));
        if ($site !== null) {
            return self::loadSite($file, $cacheDir, $sources, $site, $key, $failSafe);
        }
        $compiled = $cacheDir . '/settings-' . $key . '.php';
        $e = self::compiled($compiled, $file);
        if ($e !== null) {
            /** @var array{seen: array<string, array{0: int, 1: int}>, env: array<string, string|null>, recheck: int, settings: array<string, mixed>} $e */
            if (($e['env'] === [] || self::sameEnv($e['env'])) && self::inForce($e['settings']) && self::fresh($e['seen'], $e['recheck'], $key)) {
                self::$checked[$key] = $e['seen'];
                return self::imported($e['settings'], $compiled) ?? self::tryBuild($file, $cacheDir, $sources, $key, null, $failSafe);
            }
            if ($failSafe && self::stillBroken($cacheDir, $key)) {
                return self::imported($e['settings'], $compiled) ?? self::off($cacheDir, $file);     // as they were when they last failed: the last good ones
            }
            $lock = self::lock($cacheDir, $key);
            if ($lock === null) {
                return self::imported($e['settings'], $compiled) ?? self::tryBuild($file, $cacheDir, $sources, $key, null, $failSafe);     // another request is building them: the last ones meanwhile
            }
            try {
                return self::tryBuild($file, $cacheDir, $sources, $key, $e['settings'], $failSafe);
            } finally {
                self::unlock($lock);
            }
        }
        if ($failSafe && self::stillBroken($cacheDir, $key)) {
            return self::off($cacheDir, $file);
        }
        return self::tryBuild($file, $cacheDir, $sources, $key, null, $failSafe);
    }

    /**
     * Where the compiled settings go unless protectFile() names a directory:
     * .request-shield/ next to the settings file -- the owner's directory,
     * outside the document root as the file is; never the system's temp dir,
     * shared with other customers on a shared host. No realpath(): a stat.
     */
    public static function cacheDirFor(string $file): string
    {
        return dirname($file) . '/.request-shield';
    }

    /**
     * The compiled settings in a file: the array when it is this file's and
     * of this format, else null. A file that cannot even be parsed (cut short
     * by a full disk) is deleted, so the next request compiles anew. No
     * is_file() first: a stat costs more than everything else here, and an
     * include of a missing file just returns false.
     *
     * @return array<mixed>|null
     */
    private static function compiled(string $path, string $file): ?array
    {
        try {
            $e = @include $path;
        } catch (\Throwable $t) {
            @unlink($path);
            return null;
        }
        // Written by write() below, so trusted beyond its format, its file -- and its end: "whole"
        // comes last, so a file cut short (a full disk) that still parses lacks it. The constructor
        // would take a short array (its last arguments have defaults), and with PHP 8.1-8.3's JIT
        // not even a TypeError for a missing one stops it.
        return is_array($e) && ($e['format'] ?? 0) === self::FORMAT && ($e['file'] ?? '') === $file && ($e['whole'] ?? false) === true ? $e : null;
    }

    /**
     * import(), or null when the compiled array does not fit the constructor
     * (a file cut short inside the array): it is deleted and built anew.
     *
     * @param array<string, mixed> $settings
     */
    private static function imported(array $settings, string $path): ?self
    {
        try {
            return self::import($settings);
        } catch (\TypeError $t) {
            @unlink($path);
            return null;
        }
    }

    /**
     * build() -- and when the rule files cannot be compiled (a mistake in
     * them, a file that cannot be read), the site stays up (ADR 0007): the
     * last good compiled settings stay in force, or, without any, the shield
     * runs switched off. Noted in the error log once a minute; a marker keeps
     * the next requests from compiling again until a source changes.
     *
     * @param list<string> $sources
     * @param array<string, mixed>|null $last the last good compiled settings (export()), if any
     * @param bool $failSafe on the request path (loadFor()): never throw; a tool's load(): do
     */
    private static function tryBuild(string $file, string $cacheDir, array $sources, string $key, ?array $last, bool $failSafe): self
    {
        if (!$failSafe) {
            return self::build($file, $cacheDir, $sources, $key);     // a tool (check, the tests): a mistake is an error
        }
        try {
            $s = self::build($file, $cacheDir, $sources, $key);
        } catch (\InvalidArgumentException|\RuntimeException $e) {
            self::markBroken($cacheDir, $key, $file);
            Failure::note('settings', 'the rules cannot be compiled -- ' . ($last !== null ? 'the last good ones stay in force' : 'the shield runs switched off until they are fixed')
                . ': ' . $e->getMessage(), $cacheDir);
            return ($last !== null ? self::imported($last, $cacheDir . '/settings-' . $key . '.php') : null) ?? self::from(['mode' => 'off']);
        }
        @unlink($cacheDir . '/settings-' . $key . '.failed');
        return $s;
    }

    /** The shield switched off because the rules never compiled: said again, once a minute. */
    private static function off(string $cacheDir, string $file): self
    {
        Failure::note('settings', "the rules in $file still cannot be compiled -- the shield runs switched off until they are fixed (request-shield check $file says why)", $cacheDir);
        return self::from(['mode' => 'off']);
    }

    /**
     * Remembers that the sources, as they are now, do not compile: their
     * mtime and size, so the next requests see at one stat per file whether
     * anything changed.
     */
    private static function markBroken(string $cacheDir, string $key, string $file): void
    {
        // The main file: it is what changes on a fix (an included file that
        // changes alone is seen on the main file's next change, or by reload).
        clearstatcache();
        $seen = [$file => [(int) @filemtime($file), (int) @filesize($file)]];
        self::write($cacheDir . '/settings-' . $key . '.failed', "<?php\n// cjw-network/request-shield: these rules did not compile; checked again when they change.\nreturn " . var_export(['seen' => $seen], true) . ";\n");
    }

    /** Whether the sources are still exactly as they were when they last failed to compile. */
    private static function stillBroken(string $cacheDir, string $key): bool
    {
        $m = @include $cacheDir . '/settings-' . $key . '.failed';
        if (!is_array($m) || !is_array($m['seen'] ?? null) || $m['seen'] === []) {
            return false;
        }
        clearstatcache();
        foreach ($m['seen'] as $path => $stat) {
            if (!is_array($stat) || (int) @filemtime($path) !== ($stat[0] ?? null) || (int) @filesize($path) !== ($stat[1] ?? null)) {
                return false;
            }
        }
        return true;
    }

    /**
     * The settings for this request: load(), and with site blocks the
     * website's (siteFor()) -- picked from the compiled base before any
     * settings are made, so a website's request builds only its own.
     *
     * @param array<mixed> $server $_SERVER
     * @param list<string> $sources
     */
    public static function loadFor(string $file, array $server, ?string $cacheDir = null, array $sources = []): self
    {
        $cacheDir ??= self::cacheDirFor($file);
        $key = hash(PHP_VERSION_ID >= 80100 ? 'xxh128' : 'md5', $file . "\0" . implode("\0", $sources));
        $compiled = $cacheDir . '/settings-' . $key . '.php';
        $e = self::compiled($compiled, $file);
        if ($e !== null) {
            /** @var array{seen: array<string, array{0: int, 1: int}>, env: array<string, string|null>, recheck: int, settings: array{sites: array<string, string>, siteFrom: string, trustedProxies: list<string>}} $e */
            if (($e['env'] === [] || self::sameEnv($e['env'])) && self::inForce($e['settings']) && self::fresh($e['seen'], $e['recheck'], $key)) {
                self::$checked[$key] = $e['seen'];
                $raw = $e['settings'];
                $site = $raw['sites'] === [] ? null : self::pick($raw['sites'], $raw['siteFrom'], $raw['trustedProxies'], $server);
                if ($site !== null) {
                    return self::loadSite($file, $cacheDir, $sources, $site, $key, true);
                }
                return self::imported($raw, $compiled) ?? self::tryBuild($file, $cacheDir, $sources, $key, null, true);
            }
            if (self::stillBroken($cacheDir, $key)) {
                /** @var array<string, mixed> $raw */
                $raw = $e['settings'];
                return self::imported($raw, $compiled) ?? self::off($cacheDir, $file);     // as they were when they last failed: the last good ones
            }
            $lock = self::lock($cacheDir, $key);
            if ($lock === null) {
                // Another request is building them: the last ones meanwhile, the website's too.
                $raw = $e['settings'];
                $site = $raw['sites'] === [] ? null : self::pick($raw['sites'], $raw['siteFrom'], $raw['trustedProxies'], $server);
                $one = $site === null ? null : self::compiled($cacheDir . '/settings-' . $key . '-' . hash('crc32b', $site) . '.php', $file);    // whole, or not at all
                if ($one !== null && ($one['site'] ?? null) === $site) {
                    /** @var array{settings: array<string, mixed>} $one */
                    return self::import($one['settings']);
                }
                /** @var array<string, mixed> $raw */
                return self::import($raw);
            }
            try {
                /** @var array<string, mixed> $last */
                $last = $e['settings'];
                $base = self::tryBuild($file, $cacheDir, $sources, $key, $last, true);
            } finally {
                self::unlock($lock);
            }
            $site = $base->siteFor($server);
            return $site === null ? $base : self::loadSite($file, $cacheDir, $sources, $site, $key, true);
        }
        if (self::stillBroken($cacheDir, $key)) {
            return self::off($cacheDir, $file);
        }
        $base = self::tryBuild($file, $cacheDir, $sources, $key, null, true);
        $site = $base->siteFor($server);
        return $site === null ? $base : self::loadSite($file, $cacheDir, $sources, $site, $key, true);
    }

    /** @var array<string, array<string, array{0: int, 1: int}>> base key => the sources its last check found unchanged, this request */
    private static array $checked = [];

    /**
     * A website's settings (its site block on the base): checked with the
     * base -- the base just found the same sources unchanged, so the site's
     * compiled file is taken as it is (one include from OPcache, no stat).
     *
     * @param list<string> $sources
     */
    private static function loadSite(string $file, string $cacheDir, array $sources, string $site, string $key, bool $failSafe): self
    {
        if (!isset(self::$checked[$key])) {
            self::load($file, $cacheDir, $sources, null, $failSafe);         // the base, checked: its sources are the site's
        }
        $compiled = $cacheDir . '/settings-' . $key . '-' . hash('crc32b', $site) . '.php';
        $e = self::compiled($compiled, $file);
        if (self::isSite($e, $file, $site, $key)) {
            /** @var array{settings: array<string, mixed>} $e */
            $s = self::imported($e['settings'], $compiled);
            if ($s !== null) {
                return $s;
            }
        }
        // Missing, or from other sources: every website built again with the base.
        $base = self::tryBuild($file, $cacheDir, $sources, $key, null, $failSafe);
        $e = self::compiled($compiled, $file);
        if (self::isSite($e, $file, $site, $key)) {
            /** @var array{settings: array<string, mixed>} $e */
            return self::import($e['settings']);
        }
        return $base;                       // a site block that is gone: the base
    }

    /** Whether an included file is the compiled settings of this site, from the sources the base just found unchanged. */
    private static function isSite(mixed $e, string $file, string $site, string $key): bool
    {
        return is_array($e) && ($e['format'] ?? 0) === self::FORMAT && ($e['file'] ?? '') === $file && ($e['site'] ?? null) === $site
            && ($e['seen'] ?? null) === (self::$checked[$key] ?? false);
    }

    /**
     * The right to build these settings: a handle, true when there is no lock
     * file to be had (built anyway, as before), or null while another request
     * holds it -- with a big list a build takes seconds, and every request
     * under load building at once would take the server down with it.
     *
     * @return resource|true|null
     */
    private static function lock(string $cacheDir, string $key)
    {
        if (!is_dir($cacheDir)) {
            @mkdir($cacheDir, 0700, true);
        }
        $h = @fopen($cacheDir . '/settings-' . $key . '.lock', 'c');
        if ($h === false) {
            return true;
        }
        if (!flock($h, LOCK_EX | LOCK_NB)) {
            fclose($h);
            return null;
        }
        return $h;
    }

    /** @param resource|true $lock */
    private static function unlock($lock): void
    {
        if (is_resource($lock)) {
            flock($lock, LOCK_UN);
            fclose($lock);
        }
    }

    /**
     * Reads and checks the settings, writes them compiled -- and, for a rule
     * file with site blocks, each website's settings beside them (all checked
     * now: a mistake in any block is an error here, not at that website's
     * first visitor). Every source any of them read is in "seen".
     *
     * @param list<string> $sources
     */
    private static function build(string $file, string $cacheDir, array $sources, string $key): self
    {
        try {
            return self::compile($file, $cacheDir, $sources, $key);
        } finally {
            Rules\RuleFile::forgetLists();         // read once per build, kept by no worker
        }
    }

    /** @param list<string> $sources */
    private static function compile(string $file, string $cacheDir, array $sources, string $key): self
    {
        $sites = [];
        if (substr($file, -6) === '.rules') {
            $files = $sources;
            $files[] = $file;
            $read = Rules\RuleFile::read($files);
            // The main file first: without APCu it is the one checked.
            $seen = [$file => $read['seen'][$file] ?? [0, 0]] + $read['seen'];
            $recheck = $read['recheck'];
            $config = $read['config'];
            $env = $read['env'];
            foreach ((array) ($config['sites'] ?? []) as $id) {
                if (!is_string($id) || isset($sites[$id])) {
                    continue;
                }
                $one = Rules\RuleFile::read($files, $id);
                $seen += $one['seen'];
                $env += $one['env'];
                $sites[$id] = self::from($one['config']);
            }
        } else {
            clearstatcache();
            $stat = Rules\RuleFile::stat($file);
            if ($stat === null) {
                throw new \RuntimeException("request-shield: cannot read the settings file $file");
            }
            // OPcache judges a file by its mtime, and a file rewritten within
            // the same second keeps it -- the old settings would be compiled
            // under the new size and stay for good.
            if (function_exists('opcache_invalidate')) {
                @opcache_invalidate($file, true);
            }
            $config = require $file;
            if (!is_array($config)) {
                throw new \RuntimeException("request-shield: $file must return an array");
            }
            if (!is_string($config['storeDir'] ?? null)) {
                $config['storeDir'] = dirname($file) . '/.request-shield/store';     // as a rule file's default: next to it
            }
            $seen = [$file => $stat];
            $recheck = 0;
            $env = [];
            if ($sources !== []) {
                throw new \RuntimeException('request-shield: further sources need a .rules main file');
            }
        }
        $settings = self::from($config);
        foreach ($sites as $id => $one) {
            self::write($cacheDir . '/settings-' . $key . '-' . hash('crc32b', $id) . '.php', "<?php\n// Compiled by cjw-network/request-shield from $file, site $id; rebuilt when it changes.\nreturn "
                . var_export(['format' => self::FORMAT, 'file' => $file, 'site' => $id, 'seen' => $seen, 'settings' => $one->export(), 'whole' => true], true) . ";\n");
        }
        self::write($cacheDir . '/settings-' . $key . '.php', "<?php\n// Compiled by cjw-network/request-shield from $file; rebuilt when it changes.\nreturn "
            . var_export(['format' => self::FORMAT, 'file' => $file, 'seen' => $seen, 'env' => $env, 'recheck' => $recheck, 'settings' => $settings->export(), 'whole' => true], true) . ";\n");
        if ($recheck > 0 && Capability::apcu()) {
            apcu_store('rshield:fresh:' . $key, true, $recheck);
        }
        self::$checked[$key] = $seen;
        return $settings;
    }

    /**
     * Whether compiled settings still hold: no list entry (deny … until,
     * exempt … until) has ended since -- one comparison.
     *
     * @param array<mixed> $settings what export() wrote
     */
    private static function inForce(array $settings): bool
    {
        $until = $settings['listsUntil'] ?? 0;
        return !is_int($until) || $until === 0 || time() < $until;
    }

    /** @param array<string, string|null> $env the environment variables a rule file used, with their values then */
    private static function sameEnv(array $env): bool
    {
        foreach ($env as $name => $value) {
            $now = getenv($name);
            if ((is_string($now) ? $now : null) !== $value) {
                return false;
            }
        }
        return true;
    }

    /**
     * Whether the sources are unchanged. Kept small and free of other
     * classes: it runs on every request.
     *
     * @param array<string, array{0: int, 1: int}> $seen path => [mtime, size], the main file first
     */
    private static function fresh(array $seen, int $recheck, string $key): bool
    {
        $apcu = $recheck > 0 && Capability::apcu();
        if ($apcu && apcu_fetch('rshield:fresh:' . $key) === true) {
            return true;
        }
        // PHP keeps the last stat() for the rest of the process: in a
        // long-running server (and a second load() in one request) the old
        // mtime and size would be compared, and a change never seen.
        clearstatcache();
        foreach ($seen as $path => $stat) {
            if (@filemtime($path) !== $stat[0] || @filesize($path) !== $stat[1]) {
                return false;
            }
            if ($recheck > 0 && !$apcu) {
                break;          // without APCu: only the main file
            }
        }
        if ($apcu) {
            apcu_store('rshield:fresh:' . $key, true, $recheck);
        }
        return true;
    }

    /** @return array<string, mixed> */
    public function export(): array
    {
        /** @var array<string, mixed> $e */
        $e = get_object_vars($this);
        $e['budgets'] = array_map(static fn (Budget $b): array => $b->export(), $this->budgets);
        $e['challenge'] = $this->challenge->export();
        $e['monitor'] = $this->monitor === null ? null : $this->monitor->export();
        return $e;
    }

    /** @param array<string, mixed> $e what export() returned (trusted: no checks) */
    public static function import(array $e): self
    {
        $budgets = [];
        foreach ((array) $e['budgets'] as $name => $b) {
            /** @var array<string, mixed> $b */
            $budgets[(string) $name] = Budget::import($b);
        }
        $e['budgets'] = $budgets;
        /** @var array<string, mixed> $challenge */
        $challenge = $e['challenge'];
        $e['challenge'] = ChallengeSettings::import($challenge);
        /** @var array<string, mixed>|null $monitor */
        $monitor = $e['monitor'];
        $e['monitor'] = $monitor === null ? null : self::import($monitor);
        // Positional, in declaration order (what export() returns): unpacking
        // string keys into named arguments needs PHP 8.1.
        /** @phpstan-ignore argument.type */
        return new self(...array_values($e));
    }

    private static function write(string $file, string $php): void
    {
        $dir = dirname($file);
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        $tmp = $file . '.' . bin2hex(random_bytes(4));
        if (@file_put_contents($tmp, $php) === false) {
            return;             // not cacheable here: checked again next time
        }
        @chmod($tmp, 0600);
        if (!@rename($tmp, $file)) {
            @unlink($tmp);
        } elseif (function_exists('opcache_invalidate')) {
            @opcache_invalidate($file, true);
        }
    }

    // ── Typed reading, shared with Budget and ChallengeSettings ────────────

    /**
     * @param array<mixed> $a
     * @return array<mixed>
     */
    public static function map(array $a, string $key, ?string $name = null): array
    {
        $v = $a[$key] ?? [];
        if (!is_array($v)) {
            throw self::wrong($name ?? $key, 'an array');
        }
        return $v;
    }

    /**
     * @param array<mixed> $a
     * @return list<string>
     */
    public static function strings(array $a, string $key, ?string $name = null): array
    {
        $v = $a[$key] ?? [];
        if (!is_array($v)) {
            throw self::wrong($name ?? $key, 'a list of strings');
        }
        $out = [];
        foreach ($v as $item) {
            if (!is_string($item)) {
                throw self::wrong($name ?? $key, 'a list of strings');
            }
            $out[] = $item;
        }
        return $out;
    }

    /**
     * @param array<mixed> $a
     * @return list<string>|null
     */
    public static function stringsOrNull(array $a, string $key, ?string $name = null): ?array
    {
        return ($a[$key] ?? null) === null ? null : self::strings($a, $key, $name);
    }

    /** @param array<mixed> $a */
    public static function int(array $a, string $key, ?string $name = null, int $default = 0): int
    {
        $v = $a[$key] ?? $default;
        if (is_int($v)) {
            return $v;
        }
        if (is_string($v) && preg_match('/^-?\d+$/', $v)) {
            return (int) $v;
        }
        throw self::wrong($name ?? $key, 'an integer');
    }

    /** @param array<mixed> $a */
    public static function intOrNull(array $a, string $key, ?string $name = null): ?int
    {
        return ($a[$key] ?? null) === null ? null : self::int($a, $key, $name);
    }

    /** @param array<mixed> $a */
    public static function bool(array $a, string $key, ?string $name = null, bool $default = false): bool
    {
        $v = $a[$key] ?? $default;
        if (!is_bool($v)) {
            throw self::wrong($name ?? $key, 'true or false');
        }
        return $v;
    }

    /** @param array<mixed> $a */
    public static function string(array $a, string $key, ?string $name = null, string $default = ''): string
    {
        $v = $a[$key] ?? $default;
        if (!is_string($v)) {
            throw self::wrong($name ?? $key, 'a string');
        }
        return $v;
    }

    public static function wrong(string $key, string $what): \InvalidArgumentException
    {
        return new \InvalidArgumentException("request-shield: '$key' must be $what");
    }
}
